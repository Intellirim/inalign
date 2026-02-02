"""
Generic webhook notification channel with HMAC-SHA256 signing.

Delivers JSON alert payloads to user-configured HTTPS endpoints
with request signing and exponential backoff retry.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from typing import Any

import httpx

from app.notifications import BaseNotifier

logger = logging.getLogger("agentshield.notifications.webhook")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
_MAX_ATTEMPTS: int = 3
_BASE_DELAY_SECONDS: float = 1.0
_REQUEST_TIMEOUT: float = 15.0


class WebhookNotifier(BaseNotifier):
    """Send alert notifications to a generic webhook endpoint.

    Payloads are signed using HMAC-SHA256 and the signature is placed
    in the ``X-Signature`` header for verification by the receiver.
    Failed deliveries are retried with exponential backoff up to
    :data:`_MAX_ATTEMPTS` times.
    """

    async def send(
        self,
        url: str,
        secret: str,
        alert_data: dict[str, Any],
    ) -> bool:
        """Deliver an alert to a webhook endpoint.

        Parameters
        ----------
        url:
            The HTTPS endpoint URL.
        secret:
            HMAC-SHA256 shared secret for payload signing.
        alert_data:
            Alert dictionary to deliver as JSON.

        Returns
        -------
        bool
            ``True`` if delivery succeeded within the retry budget.
        """
        payload_bytes: bytes = json.dumps(alert_data, sort_keys=True).encode("utf-8")
        signature: str = self._compute_signature(payload_bytes, secret)

        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "X-Signature": signature,
            "User-Agent": "AgentShield-Webhook/1.0",
        }

        last_exception: Exception | None = None

        for attempt in range(1, _MAX_ATTEMPTS + 1):
            try:
                async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
                    response = await client.post(
                        url,
                        content=payload_bytes,
                        headers=headers,
                    )
                    response.raise_for_status()

                logger.info(
                    "Webhook delivered: url=%s alert=%s attempt=%d",
                    url,
                    alert_data.get("alert_id", "N/A"),
                    attempt,
                )
                return True

            except (httpx.HTTPStatusError, httpx.RequestError) as exc:
                last_exception = exc
                if attempt < _MAX_ATTEMPTS:
                    delay = _BASE_DELAY_SECONDS * (2 ** (attempt - 1))
                    logger.warning(
                        "Webhook delivery attempt %d/%d failed for %s: %s. "
                        "Retrying in %.1fs...",
                        attempt,
                        _MAX_ATTEMPTS,
                        url,
                        exc,
                        delay,
                    )
                    # Use asyncio.sleep for async backoff
                    import asyncio

                    await asyncio.sleep(delay)
                else:
                    logger.error(
                        "Webhook delivery failed after %d attempts for %s: %s",
                        _MAX_ATTEMPTS,
                        url,
                        exc,
                        exc_info=True,
                    )

            except Exception as exc:
                last_exception = exc
                logger.error(
                    "Unexpected webhook error for %s: %s",
                    url,
                    exc,
                    exc_info=True,
                )
                break

        return False

    @staticmethod
    def _compute_signature(payload: bytes, secret: str) -> str:
        """Compute HMAC-SHA256 signature for a payload.

        Parameters
        ----------
        payload:
            The raw bytes to sign.
        secret:
            The shared secret key.

        Returns
        -------
        str
            Hex-encoded HMAC-SHA256 digest.
        """
        return hmac.new(
            secret.encode("utf-8"),
            payload,
            hashlib.sha256,
        ).hexdigest()
