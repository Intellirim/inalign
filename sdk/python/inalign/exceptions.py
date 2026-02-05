"""Exception classes for InALign SDK."""

from __future__ import annotations

from typing import Any, Optional


class InALignError(Exception):
    """Base exception for all InALign SDK errors.

    Attributes:
        message: Human-readable error description.
        status_code: HTTP status code, if applicable.
        response_body: Raw response body, if available.
    """

    def __init__(
        self,
        message: str = "An error occurred with the InALign API.",
        status_code: Optional[int] = None,
        response_body: Optional[dict[str, Any]] = None,
    ) -> None:
        self.message = message
        self.status_code = status_code
        self.response_body = response_body
        super().__init__(self.message)

    @classmethod
    def from_response(cls, response: Any) -> "InALignError":
        """Create a typed exception from an HTTP response.

        Maps HTTP status codes to specific exception subclasses:
            - 401: AuthenticationError
            - 403: AuthenticationError
            - 404: NotFoundError
            - 422: ValidationError
            - 429: RateLimitError
            - 500+: ServerError

        Args:
            response: An httpx.Response object.

        Returns:
            An appropriate InALignError subclass instance.
        """
        status_code = response.status_code
        try:
            body = response.json()
        except Exception:
            body = {"detail": response.text}

        message = body.get("detail", body.get("message", f"HTTP {status_code} error"))

        error_map: dict[int, type[InALignError]] = {
            401: AuthenticationError,
            403: AuthenticationError,
            404: NotFoundError,
            422: ValidationError,
            429: RateLimitError,
        }

        error_cls = error_map.get(status_code)
        if error_cls is not None:
            return error_cls(message=message, status_code=status_code, response_body=body)

        if status_code >= 500:
            return ServerError(message=message, status_code=status_code, response_body=body)

        return cls(message=message, status_code=status_code, response_body=body)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(message={self.message!r}, status_code={self.status_code})"


class AuthenticationError(InALignError):
    """Raised when authentication fails (401/403).

    This typically means the API key is invalid, expired, or missing.
    """

    def __init__(
        self,
        message: str = "Authentication failed. Check your API key.",
        status_code: Optional[int] = 401,
        response_body: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, status_code, response_body)


class RateLimitError(InALignError):
    """Raised when the API rate limit is exceeded (429).

    The client should implement backoff and retry logic.
    """

    def __init__(
        self,
        message: str = "Rate limit exceeded. Please slow down requests.",
        status_code: Optional[int] = 429,
        response_body: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, status_code, response_body)


class NotFoundError(InALignError):
    """Raised when the requested resource is not found (404)."""

    def __init__(
        self,
        message: str = "The requested resource was not found.",
        status_code: Optional[int] = 404,
        response_body: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, status_code, response_body)


class ValidationError(InALignError):
    """Raised when the request fails validation (422).

    Check the request parameters and try again.
    """

    def __init__(
        self,
        message: str = "Request validation failed. Check your parameters.",
        status_code: Optional[int] = 422,
        response_body: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, status_code, response_body)


class ServerError(InALignError):
    """Raised when the server encounters an internal error (500+).

    This is typically a transient error that may resolve on retry.
    """

    def __init__(
        self,
        message: str = "An internal server error occurred.",
        status_code: Optional[int] = 500,
        response_body: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, status_code, response_body)
