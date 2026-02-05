"""
In-A-Lign Platform - Unified AI Security & Efficiency Solution.

The central platform that combines:
- Environment scanning & analysis
- Security protection (injection detection, threat blocking)
- Efficiency optimization (routing, caching, cost tracking)
- Enterprise-grade protection (rate limiting, anomaly detection, user tracking)

Usage:
    from app.platform import InALign

    # Initialize once
    platform = InALign(api_key="your_api_key")

    # Or scan project and auto-configure
    platform = InALign.from_project("/path/to/project")

    # Use for every AI request
    result = platform.process(
        text="user input",
        user_id="user123",
        ip_address="1.2.3.4"
    )

    if result["blocked"]:
        return {"error": result["reason"]}

    # Make your LLM call with optimized settings
    response = your_llm_call(
        model=result["recommended_model"],
        messages=[...]
    )

    # Record the response for analytics
    platform.record(
        text="user input",
        response=response,
        model=result["recommended_model"],
        tokens={"input": 100, "output": 200}
    )
"""

import logging
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

# Load environment variables FIRST
from dotenv import load_dotenv
load_dotenv()

# Import all components
from app.detectors.injection.detector import InjectionDetector
from app.efficiency.engine import EfficiencyEngine
from app.protection.shield import Shield, ThreatLevel, Action
from app.scanner.environment_scanner import EnvironmentScanner, ScanResult

logger = logging.getLogger("inalign.platform")


@dataclass
class PlatformConfig:
    """Platform configuration."""

    # Security settings
    protection_level: str = "standard"  # relaxed, standard, strict
    enable_injection_detection: bool = True
    enable_anomaly_detection: bool = True

    # Efficiency settings
    enable_smart_routing: bool = True
    enable_caching: bool = True
    cache_ttl_hours: int = 24

    # Rate limiting
    rate_limit_rpm: int = 60
    rate_limit_rph: int = 1000

    # Auto-ban settings
    auto_ban_threshold: int = 10
    ban_duration_hours: int = 24

    # Model routing
    routing_config: Optional[dict] = None


class InALign:
    """
    In-A-Lign Platform - Your AI Security & Efficiency Solution.

    One integration to:
    - Protect your AI from attacks
    - Optimize your costs
    - Monitor everything

    Like Cloudflare, but for AI.
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        api_key: Optional[str] = None,
        config: Optional[PlatformConfig] = None,
        project_path: Optional[str] = None,
    ):
        """
        Initialize the In-A-Lign platform.

        Args:
            api_key: Your In-A-Lign API key (for cloud features)
            config: Platform configuration
            project_path: Optional project path for auto-configuration
        """
        self.api_key = api_key
        self.config = config or PlatformConfig()

        # Initialize components
        self._init_components()

        # Auto-configure from project if provided
        if project_path:
            self.configure_from_project(project_path)

        logger.info("In-A-Lign Platform v%s initialized", self.VERSION)

    def _init_components(self) -> None:
        """Initialize all platform components."""
        # Security: Injection detector
        if self.config.enable_injection_detection:
            self.detector = InjectionDetector()
        else:
            self.detector = None

        # Efficiency: Smart routing & caching
        self.efficiency = EfficiencyEngine(
            enable_caching=self.config.enable_caching,
            enable_routing=self.config.enable_smart_routing,
            routing_config=self.config.routing_config,
            cache_ttl_hours=self.config.cache_ttl_hours,
        )

        # Protection: Shield (Cloudflare-style)
        self.shield = Shield(
            injection_detector=self.detector,
            protection_level=self.config.protection_level,
            rate_limit_rpm=self.config.rate_limit_rpm,
            rate_limit_rph=self.config.rate_limit_rph,
            auto_ban_threshold=self.config.auto_ban_threshold,
            ban_duration_hours=self.config.ban_duration_hours,
        )

        # Scanner
        self.scanner = None  # Initialized on demand

        # Neo4j Attack Logger - Store all attacks as graph data
        self._init_neo4j()

    def _init_neo4j(self) -> None:
        """Initialize Neo4j connection for attack logging."""
        self.neo4j_driver = None
        try:
            uri = os.getenv("NEO4J_URI")
            user = os.getenv("NEO4J_USER")
            password = os.getenv("NEO4J_PASSWORD")

            if uri and user and password:
                from neo4j import GraphDatabase
                self.neo4j_driver = GraphDatabase.driver(uri, auth=(user, password))
                logger.info("Neo4j connected - Attack data will be stored as graph")
            else:
                logger.warning("Neo4j credentials not found - Attack logging disabled")
        except Exception as e:
            logger.warning(f"Neo4j connection failed: {e}")
            self.neo4j_driver = None

    def _log_attack_to_graph(
        self,
        text: str,
        user_id: str,
        threat_level: str,
        threats: list,
        blocked: bool,
        ip_address: Optional[str] = None,
    ) -> None:
        """
        Log detected attack to Neo4j graph database.

        Creates nodes and relationships:
        - AttackSample: The attack text
        - Attacker: The user who made the attack
        - AttackType: The type of attack
        - Relationships: ATTEMPTED_BY, HAS_TYPE
        """
        if not self.neo4j_driver:
            return

        try:
            with self.neo4j_driver.session() as session:
                # Create attack sample and relationships
                query = """
                MERGE (attack:AttackSample {text: $text})
                SET attack.detected_at = datetime(),
                    attack.threat_level = $threat_level,
                    attack.blocked = $blocked,
                    attack.confidence = $confidence

                MERGE (user:Attacker {user_id: $user_id})
                SET user.last_attack = datetime(),
                    user.attack_count = COALESCE(user.attack_count, 0) + 1

                MERGE (attack)-[:ATTEMPTED_BY]->(user)

                WITH attack
                UNWIND $attack_types AS attack_type
                MERGE (t:AttackType {name: attack_type})
                MERGE (attack)-[:HAS_TYPE]->(t)

                RETURN id(attack) as attack_id
                """

                # Extract attack types from threats
                attack_types = list(set(
                    t.get("subtype", t.get("pattern_id", "unknown"))
                    for t in threats
                ))

                # Get max confidence
                confidence = max((t.get("confidence", 0) for t in threats), default=0)

                session.run(query, {
                    "text": text[:1000],  # Limit text length
                    "threat_level": threat_level,
                    "blocked": blocked,
                    "confidence": confidence,
                    "user_id": user_id,
                    "attack_types": attack_types,
                })

                logger.debug(f"Attack logged to Neo4j: {threat_level} from {user_id}")

        except Exception as e:
            logger.error(f"Failed to log attack to Neo4j: {e}")

    @classmethod
    def from_project(cls, project_path: str, api_key: Optional[str] = None) -> "InALign":
        """
        Create platform instance with auto-configuration from project scan.

        Args:
            project_path: Path to the project to scan
            api_key: Optional API key

        Returns:
            Configured InALign instance
        """
        instance = cls(api_key=api_key)
        instance.configure_from_project(project_path)
        return instance

    def configure_from_project(self, project_path: str) -> dict:
        """
        Scan a project and auto-configure the platform.

        Args:
            project_path: Path to scan

        Returns:
            Dict with scan results and applied configuration
        """
        self.scanner = EnvironmentScanner(project_path)
        scan_result = self.scanner.scan()
        recommendations = self.scanner.get_recommendations()

        # Apply security recommendations
        security_rec = recommendations.get("security", {})
        if security_rec.get("injection_protection") == "strict":
            self.shield.set_protection_level("strict")
        elif security_rec.get("injection_protection") == "relaxed":
            self.shield.set_protection_level("relaxed")

        # Apply efficiency recommendations
        efficiency_rec = recommendations.get("efficiency", {})
        if efficiency_rec.get("model_routing"):
            # Update router config
            routing = efficiency_rec["model_routing"]
            if "simple_queries" in routing:
                self.efficiency.router.routing = {
                    "simple": routing.get("simple_queries", "gpt-3.5-turbo"),
                    "medium": routing.get("complex_queries", "gpt-4"),
                    "complex": routing.get("complex_queries", "gpt-4"),
                }

        logger.info(
            "Auto-configured from project: type=%s, providers=%s, frameworks=%s",
            scan_result.project_type,
            scan_result.llm_providers,
            scan_result.frameworks,
        )

        return {
            "scan_result": scan_result.to_dict(),
            "recommendations": recommendations,
            "applied_config": {
                "protection_level": self.shield.protection_level,
                "routing": self.efficiency.router.routing,
            },
        }

    def process(
        self,
        text: str,
        user_id: str,
        ip_address: Optional[str] = None,
        system_prompt: Optional[str] = None,
        force_model: Optional[str] = None,
        skip_cache: bool = False,
        metadata: Optional[dict] = None,
    ) -> dict:
        """
        Process an AI request through all layers.

        This is the main entry point - call this for every user request.

        Args:
            text: User input text
            user_id: Unique user identifier
            ip_address: Optional IP address for additional security
            system_prompt: System prompt (for cache key)
            force_model: Force a specific model (bypass routing)
            skip_cache: Skip cache lookup
            metadata: Additional metadata

        Returns:
            Dict with:
            - blocked: Whether request was blocked
            - reason: Reason if blocked
            - cached: Whether response was cached
            - response: Cached response if available
            - recommended_model: Best model to use
            - threat_level: Detected threat level
            - details: Additional details
        """
        result = {
            "blocked": False,
            "reason": None,
            "cached": False,
            "response": None,
            "recommended_model": None,
            "threat_level": "none",
            "action": "allow",
            "details": {},
        }

        # Step 1: Security check through Shield
        shield_result = self.shield.check(
            text=text,
            user_id=user_id,
            ip_address=ip_address,
            metadata=metadata,
        )

        if shield_result["blocked"]:
            result["blocked"] = True
            result["reason"] = shield_result["reason"]
            result["threat_level"] = shield_result["threat_level"]
            result["action"] = shield_result["action"]
            result["details"] = shield_result.get("details", {})

            # Log attack to Neo4j graph
            self._log_attack_to_graph(
                text=text,
                user_id=user_id,
                threat_level=shield_result["threat_level"],
                threats=shield_result.get("details", {}).get("threats", []),
                blocked=True,
                ip_address=ip_address,
            )
            return result

        # Also log non-blocked but detected threats
        if shield_result["threat_level"] != "none":
            self._log_attack_to_graph(
                text=text,
                user_id=user_id,
                threat_level=shield_result["threat_level"],
                threats=shield_result.get("details", {}).get("threats", []),
                blocked=False,
                ip_address=ip_address,
            )

        result["threat_level"] = shield_result["threat_level"]
        result["action"] = shield_result["action"]

        # Step 2: Efficiency optimization
        efficiency_result = self.efficiency.optimize_request(
            query=text,
            system_prompt=system_prompt,
            force_model=force_model,
            skip_cache=skip_cache,
        )

        if efficiency_result["cached"]:
            result["cached"] = True
            result["response"] = efficiency_result["response"]
            result["recommended_model"] = efficiency_result["model"]
        else:
            result["recommended_model"] = efficiency_result["model"]
            result["details"]["routing_analysis"] = efficiency_result.get("analysis")

        return result

    def record(
        self,
        text: str,
        response: str,
        model: str,
        tokens: dict,
        user_id: Optional[str] = None,
        system_prompt: Optional[str] = None,
        cache_response: bool = True,
    ) -> dict:
        """
        Record a completed request for analytics and caching.

        Call this after getting the LLM response.

        Args:
            text: Original user input
            response: LLM response
            model: Model that was used
            tokens: Dict with input/output token counts
            user_id: User ID (for feedback)
            system_prompt: System prompt used
            cache_response: Whether to cache this response

        Returns:
            Dict with cost information
        """
        input_tokens = tokens.get("input", 0)
        output_tokens = tokens.get("output", 0)

        cost_result = self.efficiency.record_response(
            query=text,
            response=response,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            system_prompt=system_prompt,
            cache_response=cache_response,
        )

        # Report successful outcome to shield
        if user_id:
            self.shield.report_outcome(user_id, success=True)

        return cost_result

    def get_stats(self) -> dict:
        """
        Get comprehensive platform statistics.

        Returns:
            Dict with all stats
        """
        return {
            "version": self.VERSION,
            "protection": self.shield.get_stats(),
            "efficiency": self.efficiency.get_stats(),
        }

    def get_user_stats(self, user_id: str) -> Optional[dict]:
        """Get statistics for a specific user."""
        return self.shield.get_user_stats(user_id)

    # =========================================================================
    # Convenience methods
    # =========================================================================

    def scan(self, text: str) -> dict:
        """
        Just scan text for threats (without full processing).

        Args:
            text: Text to scan

        Returns:
            Scan results with keys:
            - threats: List of detected threats
            - is_safe: Whether the text is considered safe
            - risk_score: Overall risk score (0.0-1.0)
            - risk_level: Risk level (negligible/low/medium/high/critical)
        """
        if self.detector:
            result = self.detector.scan(text)
            # Add is_safe based on threats
            result["is_safe"] = len(result.get("threats", [])) == 0
            return result
        return {"threats": [], "is_safe": True, "risk_score": 0.0, "risk_level": "negligible"}

    def set_protection_level(self, level: str) -> None:
        """Change protection level (relaxed/standard/strict)."""
        self.shield.set_protection_level(level)

    def unban_user(self, user_id: str) -> bool:
        """Manually unban a user."""
        return self.shield.unban_user(user_id)

    def clear_cache(self) -> None:
        """Clear the response cache."""
        self.efficiency.cache.clear()


# ============================================================================
# Global instance for simple usage
# ============================================================================

_default_platform: Optional[InALign] = None


def init(api_key: Optional[str] = None, **kwargs) -> InALign:
    """Initialize the global platform instance."""
    global _default_platform
    _default_platform = InALign(api_key=api_key, **kwargs)
    return _default_platform


def get_platform() -> InALign:
    """Get the global platform instance."""
    global _default_platform
    if _default_platform is None:
        _default_platform = InALign()
    return _default_platform


def process(text: str, user_id: str, **kwargs) -> dict:
    """Process a request using the global instance."""
    return get_platform().process(text, user_id, **kwargs)


def record(text: str, response: str, model: str, tokens: dict, **kwargs) -> dict:
    """Record a response using the global instance."""
    return get_platform().record(text, response, model, tokens, **kwargs)


def stats() -> dict:
    """Get stats from the global instance."""
    return get_platform().get_stats()
