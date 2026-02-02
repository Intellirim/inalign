"""
API key generation CLI script.

Creates a new API key for a given user (identified by email), stores
the hashed key in the database, and prints the raw key exactly once.

Usage::

    python -m scripts.generate_api_key --email admin@agentshield.io
    python -m scripts.generate_api_key --email admin@agentshield.io --name "Production Key"
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

# Ensure the backend package root is on sys.path
_backend_root = Path(__file__).resolve().parent.parent
if str(_backend_root) not in sys.path:
    sys.path.insert(0, str(_backend_root))

from app.config import configure_logging, get_settings

logger = logging.getLogger("agentshield.scripts.generate_api_key")


async def generate_key(email: str, key_name: str) -> None:
    """Generate an API key for the user with *email*.

    Parameters
    ----------
    email:
        The user's email address (must already exist in the database).
    key_name:
        A human-readable label for the key.
    """
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    from app.core.security import generate_api_key, get_api_key_prefix, hash_api_key
    from app.models.api_key import APIKey
    from app.models.user import User

    settings = get_settings()
    engine = create_async_engine(settings.async_database_url, echo=False)
    async_session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with async_session_factory() as session:
        # Find the user
        result = await session.execute(
            select(User).where(User.email == email)
        )
        user = result.scalar_one_or_none()

        if user is None:
            print(f"\nError: No user found with email '{email}'.")
            print("Create the user first with: python -m scripts.init_db")
            await engine.dispose()
            sys.exit(1)

        # Generate key
        raw_key: str = generate_api_key()
        key_hash: str = hash_api_key(raw_key)
        key_prefix: str = get_api_key_prefix(raw_key)

        api_key = APIKey(
            user_id=user.id,
            key_hash=key_hash,
            key_prefix=key_prefix,
            name=key_name,
            permissions={
                "scan:read": True,
                "scan:write": True,
                "logs:read": True,
                "logs:write": True,
                "sessions:read": True,
                "reports:read": True,
                "reports:write": True,
            },
            is_active=True,
        )

        session.add(api_key)
        await session.commit()

        logger.info(
            "API key created: user=%s name=%s prefix=%s",
            email,
            key_name,
            key_prefix,
        )

        # Print the raw key (shown once, never again)
        print("\n" + "=" * 60)
        print("  API KEY GENERATED SUCCESSFULLY")
        print("=" * 60)
        print(f"  User    : {email}")
        print(f"  Name    : {key_name}")
        print(f"  Prefix  : {key_prefix}")
        print(f"  Key ID  : {api_key.id}")
        print()
        print(f"  API Key : {raw_key}")
        print()
        print("  WARNING: This key will NOT be shown again.")
        print("  Store it in a secure location immediately.")
        print("=" * 60 + "\n")

    await engine.dispose()


def main() -> None:
    """Parse CLI arguments and generate the API key."""
    parser = argparse.ArgumentParser(
        description="Generate a new API key for an AgentShield user."
    )
    parser.add_argument(
        "--email",
        required=True,
        help="Email address of the user to generate a key for.",
    )
    parser.add_argument(
        "--name",
        default="Default API Key",
        help="Human-readable name for the API key (default: 'Default API Key').",
    )
    args = parser.parse_args()

    settings = get_settings()
    configure_logging(settings)

    asyncio.run(generate_key(args.email, args.name))


if __name__ == "__main__":
    main()
