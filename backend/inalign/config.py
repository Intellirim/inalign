"""
In-A-Lign Configuration.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class InALignConfig:
    """Global configuration for In-A-Lign."""

    # API settings (for cloud features)
    api_key: Optional[str] = None
    api_base_url: str = "https://api.in-a-lign.com/v1"

    # Detection thresholds
    block_threshold: float = 0.5
    warn_threshold: float = 0.3

    # Features
    use_ml_classifier: bool = True
    use_rule_detection: bool = True
    use_graphrag: bool = False

    # Neo4j (for GraphRAG)
    neo4j_uri: Optional[str] = None
    neo4j_user: Optional[str] = None
    neo4j_password: Optional[str] = None

    # Caching
    enable_cache: bool = True
    cache_ttl_seconds: int = 3600

    # Logging
    log_level: str = "INFO"
    log_threats: bool = True

    @classmethod
    def from_env(cls) -> "InALignConfig":
        """Load configuration from environment variables."""
        import os

        return cls(
            api_key=os.getenv("INALIGN_API_KEY"),
            api_base_url=os.getenv("INALIGN_API_URL", "https://api.in-a-lign.com/v1"),
            block_threshold=float(os.getenv("INALIGN_BLOCK_THRESHOLD", "0.5")),
            use_ml_classifier=os.getenv("INALIGN_USE_ML", "true").lower() == "true",
            use_graphrag=os.getenv("INALIGN_USE_GRAPHRAG", "false").lower() == "true",
            neo4j_uri=os.getenv("NEO4J_URI"),
            neo4j_user=os.getenv("NEO4J_USER"),
            neo4j_password=os.getenv("NEO4J_PASSWORD"),
        )
