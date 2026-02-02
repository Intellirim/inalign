"""
Application configuration using pydantic-settings.

All configuration is loaded from environment variables with sensible defaults
for local development. Production deployments MUST set SECRET_KEY and all
database credentials explicitly.
"""

from __future__ import annotations

import logging
import logging.config
import sys
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import Field, PostgresDsn, RedisDsn, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d | %(message)s"


class Environment(str, Enum):
    """Supported runtime environments."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TESTING = "testing"


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
class Settings(BaseSettings):
    """
    Central application settings.

    Values are read from environment variables (case-insensitive) and from a
    ``.env`` file located at the repository root when present.
    """

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -- API -----------------------------------------------------------------
    api_host: str = Field(default="0.0.0.0", description="Bind address")
    api_port: int = Field(default=8000, ge=1, le=65535, description="Bind port")
    api_env: Environment = Field(
        default=Environment.DEVELOPMENT,
        description="Runtime environment",
    )
    secret_key: str = Field(
        default="CHANGE-ME-IN-PRODUCTION",
        min_length=16,
        description="Secret key used for JWT signing and token hashing",
    )
    allowed_origins: list[str] = Field(
        default=["http://localhost:3000"],
        description="CORS allowed origins (comma-separated in env)",
    )
    api_v1_prefix: str = Field(default="/api/v1", description="API v1 route prefix")
    debug: bool = Field(default=False, description="Enable debug mode")

    # -- PostgreSQL ----------------------------------------------------------
    postgres_host: str = Field(default="localhost")
    postgres_port: int = Field(default=5432, ge=1, le=65535)
    postgres_db: str = Field(default="agentshield")
    postgres_user: str = Field(default="agentshield")
    postgres_password: str = Field(default="agentshield")
    postgres_pool_size: int = Field(default=20, ge=1)
    postgres_max_overflow: int = Field(default=10, ge=0)
    postgres_echo: bool = Field(default=False)

    # -- Neo4j ---------------------------------------------------------------
    neo4j_uri: str = Field(default="bolt://localhost:7687")
    neo4j_user: str = Field(default="neo4j")
    neo4j_password: str = Field(default="neo4j")
    neo4j_database: str = Field(default="neo4j")
    neo4j_max_connection_pool_size: int = Field(default=50, ge=1)

    # -- Redis ---------------------------------------------------------------
    redis_url: RedisDsn = Field(default="redis://localhost:6379/0")  # type: ignore[assignment]
    redis_pool_max_connections: int = Field(default=20, ge=1)

    # -- LLM keys ------------------------------------------------------------
    openai_api_key: str | None = Field(default=None, description="OpenAI API key")
    anthropic_api_key: str | None = Field(default=None, description="Anthropic API key")

    # -- Notification channels -----------------------------------------------
    slack_webhook_url: str | None = Field(default=None)
    telegram_bot_token: str | None = Field(default=None)
    telegram_chat_id: str | None = Field(default=None)
    sendgrid_api_key: str | None = Field(default=None)
    notification_from_email: str | None = Field(default=None)
    notification_to_emails: list[str] = Field(default_factory=list)

    # -- Rate limiting -------------------------------------------------------
    rate_limit_per_minute: int = Field(default=100, ge=1)
    rate_limit_burst: int = Field(default=20, ge=1)

    # -- JWT -----------------------------------------------------------------
    jwt_algorithm: str = Field(default="HS256")
    jwt_access_token_expire_minutes: int = Field(default=30, ge=1)

    # -- Logging -------------------------------------------------------------
    log_level: str = Field(default="INFO")
    log_json: bool = Field(default=False, description="Emit structured JSON logs")

    # -- Validators ----------------------------------------------------------
    @field_validator("allowed_origins", mode="before")
    @classmethod
    def _parse_origins(cls, v: Any) -> list[str]:
        """Accept a comma-separated string or list for allowed_origins."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @field_validator("notification_to_emails", mode="before")
    @classmethod
    def _parse_to_emails(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            return [e.strip() for e in v.split(",") if e.strip()]
        return v

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalise_log_level(cls, v: Any) -> str:
        if isinstance(v, str):
            v = v.upper()
            if v not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
                raise ValueError(f"Invalid log level: {v}")
        return v

    @model_validator(mode="after")
    def _warn_default_secret(self) -> "Settings":
        if (
            self.api_env == Environment.PRODUCTION
            and self.secret_key == "CHANGE-ME-IN-PRODUCTION"
        ):
            raise ValueError(
                "SECRET_KEY must be changed from the default in production."
            )
        return self

    # -- Derived properties --------------------------------------------------
    @property
    def async_database_url(self) -> str:
        """SQLAlchemy async connection string for PostgreSQL."""
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def sync_database_url(self) -> str:
        """Synchronous connection string (used by Alembic)."""
        return (
            f"postgresql+psycopg2://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def is_production(self) -> bool:
        return self.api_env == Environment.PRODUCTION

    @property
    def is_testing(self) -> bool:
        return self.api_env == Environment.TESTING


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
_settings: Settings | None = None


def get_settings() -> Settings:
    """Return the cached application settings singleton."""
    global _settings  # noqa: PLW0603
    if _settings is None:
        _settings = Settings()
    return _settings


# ---------------------------------------------------------------------------
# Logging bootstrap
# ---------------------------------------------------------------------------
def configure_logging(settings: Settings | None = None) -> None:
    """
    Configure the root logger according to application settings.

    Call once at application startup (e.g., in the lifespan handler).
    """
    if settings is None:
        settings = get_settings()

    handlers: dict[str, dict[str, Any]] = {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "default",
            "stream": "ext://sys.stdout",
        },
    }

    formatters: dict[str, dict[str, Any]] = {
        "default": {
            "format": LOG_FORMAT,
            "datefmt": "%Y-%m-%dT%H:%M:%S%z",
        },
    }

    if settings.log_json:
        try:
            import json_log_formatter  # noqa: F401  # optional dependency

            formatters["default"] = {
                "()": "json_log_formatter.JSONFormatter",
            }
        except ImportError:
            pass  # fall back to plain text

    config: dict[str, Any] = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": formatters,
        "handlers": handlers,
        "loggers": {
            "agentshield": {
                "level": settings.log_level,
                "handlers": ["console"],
                "propagate": False,
            },
            "uvicorn": {
                "level": settings.log_level,
                "handlers": ["console"],
                "propagate": False,
            },
            "sqlalchemy.engine": {
                "level": "WARNING",
                "handlers": ["console"],
                "propagate": False,
            },
        },
        "root": {
            "level": settings.log_level,
            "handlers": ["console"],
        },
    }

    logging.config.dictConfig(config)

    # Silence overly chatty libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("neo4j").setLevel(logging.WARNING)
