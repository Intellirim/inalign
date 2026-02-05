"""
In-A-Lign Shield - Cloudflare-style Protection Layer.

Provides:
- Real-time threat detection
- Rate limiting
- Anomaly detection
- Attack logging & analytics
- Automatic threat response

Designed to scale from small projects to enterprise.
"""

import hashlib
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger("inalign.shield")


class ThreatLevel(Enum):
    """Threat severity levels."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(Enum):
    """Actions to take on threats."""

    ALLOW = "allow"
    LOG = "log"
    CHALLENGE = "challenge"
    BLOCK = "block"
    BAN = "ban"


@dataclass
class ThreatEvent:
    """A detected threat event."""

    timestamp: datetime
    user_id: str
    ip_address: Optional[str]
    threat_type: str
    threat_level: ThreatLevel
    action_taken: Action
    details: dict
    blocked: bool

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "ip_address": self.ip_address,
            "threat_type": self.threat_type,
            "threat_level": self.threat_level.value,
            "action_taken": self.action_taken.value,
            "details": self.details,
            "blocked": self.blocked,
        }


@dataclass
class UserProfile:
    """Track user behavior for anomaly detection."""

    user_id: str
    first_seen: datetime = field(default_factory=datetime.now)
    request_count: int = 0
    threat_count: int = 0
    last_request: Optional[datetime] = None
    is_banned: bool = False
    ban_until: Optional[datetime] = None
    trust_score: float = 1.0  # 0.0 to 1.0

    def update_trust(self, is_threat: bool) -> None:
        """Update trust score based on behavior."""
        if is_threat:
            self.trust_score = max(0.0, self.trust_score - 0.1)
            self.threat_count += 1
        else:
            self.trust_score = min(1.0, self.trust_score + 0.01)

        self.request_count += 1
        self.last_request = datetime.now()


class RateLimiter:
    """
    Rate limiting with sliding window.
    """

    def __init__(
        self,
        requests_per_minute: int = 60,
        requests_per_hour: int = 1000,
    ):
        self.rpm_limit = requests_per_minute
        self.rph_limit = requests_per_hour
        self._minute_windows: dict[str, list[float]] = defaultdict(list)
        self._hour_windows: dict[str, list[float]] = defaultdict(list)

    def check(self, user_id: str) -> tuple[bool, Optional[str]]:
        """
        Check if request is within rate limits.

        Returns:
            Tuple of (allowed, reason_if_blocked)
        """
        now = time.time()

        # Clean old entries
        self._minute_windows[user_id] = [
            t for t in self._minute_windows[user_id] if now - t < 60
        ]
        self._hour_windows[user_id] = [
            t for t in self._hour_windows[user_id] if now - t < 3600
        ]

        # Check limits
        if len(self._minute_windows[user_id]) >= self.rpm_limit:
            return False, f"Rate limit exceeded: {self.rpm_limit} requests/minute"

        if len(self._hour_windows[user_id]) >= self.rph_limit:
            return False, f"Rate limit exceeded: {self.rph_limit} requests/hour"

        # Record request
        self._minute_windows[user_id].append(now)
        self._hour_windows[user_id].append(now)

        return True, None


class AnomalyDetector:
    """
    Detects anomalous behavior patterns.
    """

    def __init__(self):
        self._user_patterns: dict[str, list[dict]] = defaultdict(list)

    def analyze(self, user_id: str, request: dict) -> dict:
        """
        Analyze request for anomalies.

        Returns:
            Dict with anomaly score and details
        """
        anomalies = []
        score = 0.0

        # Check request length anomaly
        text_length = len(request.get("text", ""))
        if text_length > 10000:
            anomalies.append("unusually_long_request")
            score += 0.3
        elif text_length > 5000:
            anomalies.append("long_request")
            score += 0.1

        # Check for rapid requests (burst)
        history = self._user_patterns[user_id]
        if len(history) >= 5:
            recent = history[-5:]
            time_span = (datetime.now() - recent[0].get("time", datetime.now())).total_seconds()
            if time_span < 10:  # 5 requests in 10 seconds
                anomalies.append("burst_requests")
                score += 0.2

        # Check for pattern changes (simplified)
        # In production, would use ML for this

        # Record this request
        self._user_patterns[user_id].append({
            "time": datetime.now(),
            "length": text_length,
        })

        # Keep only last 100 requests per user
        if len(self._user_patterns[user_id]) > 100:
            self._user_patterns[user_id] = self._user_patterns[user_id][-100:]

        return {
            "score": min(1.0, score),
            "anomalies": anomalies,
            "is_anomalous": score >= 0.5,
        }


class Shield:
    """
    Main protection layer - like Cloudflare for AI.

    Provides multi-layer protection:
    1. Rate limiting
    2. Injection detection
    3. Anomaly detection
    4. User reputation tracking
    5. Automatic threat response

    Usage:
        shield = Shield()

        # Check every request
        result = shield.check(
            text="user input",
            user_id="user123",
            ip_address="1.2.3.4"
        )

        if result["blocked"]:
            return error_response(result["reason"])

        # Process request normally
        response = process_request(text)

        # Optionally report outcome
        shield.report_outcome(user_id, success=True)
    """

    def __init__(
        self,
        injection_detector: Optional[Any] = None,
        protection_level: str = "standard",  # "relaxed", "standard", "strict"
        rate_limit_rpm: int = 60,
        rate_limit_rph: int = 1000,
        auto_ban_threshold: int = 10,
        ban_duration_hours: int = 24,
    ):
        self.protection_level = protection_level
        self.auto_ban_threshold = auto_ban_threshold
        self.ban_duration_hours = ban_duration_hours

        # Components
        self.rate_limiter = RateLimiter(rate_limit_rpm, rate_limit_rph)
        self.anomaly_detector = AnomalyDetector()
        self._injection_detector = injection_detector

        # User tracking
        self._users: dict[str, UserProfile] = {}

        # Event logging
        self._events: list[ThreatEvent] = []
        self._events_by_user: dict[str, list[ThreatEvent]] = defaultdict(list)
        self._events_by_type: dict[str, int] = defaultdict(int)

        # Stats
        self._total_requests = 0
        self._blocked_requests = 0

    def _get_or_create_user(self, user_id: str) -> UserProfile:
        """Get or create user profile."""
        if user_id not in self._users:
            self._users[user_id] = UserProfile(user_id=user_id)
        return self._users[user_id]

    def _get_action_for_threat(self, threat_level: ThreatLevel, user: UserProfile) -> Action:
        """Determine action based on threat level and user history."""
        # Check if user is banned
        if user.is_banned:
            if user.ban_until and datetime.now() < user.ban_until:
                return Action.BAN
            else:
                user.is_banned = False
                user.ban_until = None

        # Action matrix based on protection level and threat
        action_matrix = {
            "relaxed": {
                ThreatLevel.LOW: Action.LOG,
                ThreatLevel.MEDIUM: Action.LOG,
                ThreatLevel.HIGH: Action.CHALLENGE,
                ThreatLevel.CRITICAL: Action.BLOCK,
            },
            "standard": {
                ThreatLevel.LOW: Action.LOG,
                ThreatLevel.MEDIUM: Action.CHALLENGE,
                ThreatLevel.HIGH: Action.BLOCK,
                ThreatLevel.CRITICAL: Action.BLOCK,
            },
            "strict": {
                ThreatLevel.LOW: Action.CHALLENGE,
                ThreatLevel.MEDIUM: Action.BLOCK,
                ThreatLevel.HIGH: Action.BLOCK,
                ThreatLevel.CRITICAL: Action.BAN,
            },
        }

        action = action_matrix.get(
            self.protection_level, action_matrix["standard"]
        ).get(threat_level, Action.LOG)

        # Escalate for repeat offenders
        if user.trust_score < 0.3:
            if action == Action.LOG:
                action = Action.CHALLENGE
            elif action == Action.CHALLENGE:
                action = Action.BLOCK

        # Auto-ban for excessive threats
        if user.threat_count >= self.auto_ban_threshold:
            action = Action.BAN
            user.is_banned = True
            user.ban_until = datetime.now() + timedelta(hours=self.ban_duration_hours)

        return action

    def check(
        self,
        text: str,
        user_id: str,
        ip_address: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> dict:
        """
        Check a request through all protection layers.

        Args:
            text: The text to check
            user_id: User identifier
            ip_address: Optional IP address
            metadata: Optional additional metadata

        Returns:
            Dict with check results
        """
        self._total_requests += 1
        user = self._get_or_create_user(user_id)

        result = {
            "allowed": True,
            "blocked": False,
            "reason": None,
            "action": Action.ALLOW.value,
            "threat_level": ThreatLevel.NONE.value,
            "details": {},
        }

        # Layer 1: Check if user is banned
        if user.is_banned:
            if user.ban_until and datetime.now() < user.ban_until:
                result["allowed"] = False
                result["blocked"] = True
                result["reason"] = "User is temporarily banned"
                result["action"] = Action.BAN.value
                self._blocked_requests += 1
                return result
            else:
                user.is_banned = False

        # Layer 2: Rate limiting
        rate_ok, rate_reason = self.rate_limiter.check(user_id)
        if not rate_ok:
            result["allowed"] = False
            result["blocked"] = True
            result["reason"] = rate_reason
            result["action"] = Action.BLOCK.value
            result["threat_level"] = ThreatLevel.MEDIUM.value
            self._blocked_requests += 1
            self._log_event(user_id, ip_address, "rate_limit", ThreatLevel.MEDIUM, Action.BLOCK, {}, True)
            return result

        # Layer 3: Injection detection
        threats = []
        threat_level = ThreatLevel.NONE

        if self._injection_detector:
            detection_result = self._injection_detector.scan(text)
            if detection_result.get("threats"):
                threats = detection_result["threats"]
                # Determine highest threat level
                max_confidence = max(t.get("confidence", 0) for t in threats)
                if max_confidence >= 0.9:
                    threat_level = ThreatLevel.CRITICAL
                elif max_confidence >= 0.7:
                    threat_level = ThreatLevel.HIGH
                elif max_confidence >= 0.5:
                    threat_level = ThreatLevel.MEDIUM
                else:
                    threat_level = ThreatLevel.LOW

        # Layer 4: Anomaly detection
        anomaly_result = self.anomaly_detector.analyze(user_id, {"text": text})
        if anomaly_result["is_anomalous"]:
            if threat_level.value == "none":
                threat_level = ThreatLevel.LOW
            result["details"]["anomalies"] = anomaly_result["anomalies"]

        # Determine action
        if threat_level != ThreatLevel.NONE:
            action = self._get_action_for_threat(threat_level, user)
            result["action"] = action.value
            result["threat_level"] = threat_level.value
            result["details"]["threats"] = [
                {"type": t.get("subtype"), "confidence": t.get("confidence")}
                for t in threats
            ]

            if action in [Action.BLOCK, Action.BAN]:
                result["allowed"] = False
                result["blocked"] = True
                result["reason"] = f"Blocked: {threats[0].get('description') if threats else 'Security policy'}"
                self._blocked_requests += 1

            # Log event
            self._log_event(
                user_id, ip_address,
                threats[0].get("subtype", "unknown") if threats else "anomaly",
                threat_level, action,
                {"threats": len(threats), "anomalies": anomaly_result.get("anomalies", [])},
                result["blocked"]
            )

        # Update user profile
        user.update_trust(threat_level != ThreatLevel.NONE)

        return result

    def _log_event(
        self,
        user_id: str,
        ip_address: Optional[str],
        threat_type: str,
        threat_level: ThreatLevel,
        action: Action,
        details: dict,
        blocked: bool,
    ) -> None:
        """Log a threat event."""
        event = ThreatEvent(
            timestamp=datetime.now(),
            user_id=user_id,
            ip_address=ip_address,
            threat_type=threat_type,
            threat_level=threat_level,
            action_taken=action,
            details=details,
            blocked=blocked,
        )

        self._events.append(event)
        self._events_by_user[user_id].append(event)
        self._events_by_type[threat_type] += 1

        # Keep only last 10000 events in memory
        if len(self._events) > 10000:
            self._events = self._events[-10000:]

        logger.info(
            "Threat detected: user=%s type=%s level=%s action=%s blocked=%s",
            user_id, threat_type, threat_level.value, action.value, blocked
        )

    def report_outcome(self, user_id: str, success: bool, feedback: Optional[str] = None) -> None:
        """
        Report the outcome of a request (for learning).

        Args:
            user_id: User identifier
            success: Whether the request was legitimate
            feedback: Optional feedback
        """
        user = self._get_or_create_user(user_id)

        if success:
            # Slightly increase trust for successful interactions
            user.trust_score = min(1.0, user.trust_score + 0.005)

    def get_stats(self) -> dict:
        """Get protection statistics."""
        return {
            "total_requests": self._total_requests,
            "blocked_requests": self._blocked_requests,
            "block_rate": f"{(self._blocked_requests / max(self._total_requests, 1)) * 100:.2f}%",
            "active_users": len(self._users),
            "banned_users": sum(1 for u in self._users.values() if u.is_banned),
            "events_by_type": dict(self._events_by_type),
            "recent_events": [e.to_dict() for e in self._events[-10:]],
        }

    def get_user_stats(self, user_id: str) -> Optional[dict]:
        """Get statistics for a specific user."""
        if user_id not in self._users:
            return None

        user = self._users[user_id]
        events = self._events_by_user.get(user_id, [])

        return {
            "user_id": user_id,
            "first_seen": user.first_seen.isoformat(),
            "request_count": user.request_count,
            "threat_count": user.threat_count,
            "trust_score": round(user.trust_score, 3),
            "is_banned": user.is_banned,
            "ban_until": user.ban_until.isoformat() if user.ban_until else None,
            "recent_events": [e.to_dict() for e in events[-10:]],
        }

    def unban_user(self, user_id: str) -> bool:
        """Manually unban a user."""
        if user_id in self._users:
            self._users[user_id].is_banned = False
            self._users[user_id].ban_until = None
            return True
        return False

    def set_protection_level(self, level: str) -> None:
        """Change protection level."""
        if level in ["relaxed", "standard", "strict"]:
            self.protection_level = level
            logger.info("Protection level changed to: %s", level)
