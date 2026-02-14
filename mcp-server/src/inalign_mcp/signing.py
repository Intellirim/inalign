"""
Ed25519 Digital Signing for InALign Provenance Records

Provides non-repudiation: proves which machine created a provenance record.
Keys are generated automatically on first use and stored at ~/.inalign/.

Key files:
- ~/.inalign/signing_key     (private, Ed25519, PEM)
- ~/.inalign/signing_key.pub (public, Ed25519, PEM)

The cryptography library is optional. If not installed, signing is silently
skipped and all records remain unsigned (hash chain still works).
"""

import logging
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger("inalign-mcp")

INALIGN_DIR = Path.home() / ".inalign"
PRIVATE_KEY_PATH = INALIGN_DIR / "signing_key"
PUBLIC_KEY_PATH = INALIGN_DIR / "signing_key.pub"

# Lazy-loaded globals
_private_key = None
_public_key = None
_signing_available = None


def _check_available() -> bool:
    """Check if cryptography library is installed."""
    global _signing_available
    if _signing_available is not None:
        return _signing_available
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: F401
        _signing_available = True
    except ImportError:
        _signing_available = False
        logger.debug("[SIGNING] cryptography library not installed — signing disabled")
    return _signing_available


def generate_keypair(force: bool = False) -> bool:
    """
    Generate a new Ed25519 keypair at ~/.inalign/.

    Args:
        force: If True, overwrite existing keys.

    Returns:
        True if keys were generated, False otherwise.
    """
    if not _check_available():
        return False

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    if not force and PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists():
        logger.debug("[SIGNING] Keys already exist")
        return True

    INALIGN_DIR.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()

    # Save private key (no encryption — protected by filesystem permissions)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    PRIVATE_KEY_PATH.write_bytes(private_pem)

    # Save public key
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    PUBLIC_KEY_PATH.write_bytes(public_pem)

    # Try to restrict permissions (best-effort on Windows)
    try:
        PRIVATE_KEY_PATH.chmod(0o600)
    except (OSError, NotImplementedError):
        pass

    logger.info("[SIGNING] Ed25519 keypair generated")
    return True


def _load_private_key():
    """Load private key from disk (lazy, cached)."""
    global _private_key
    if _private_key is not None:
        return _private_key

    if not _check_available():
        return None

    if not PRIVATE_KEY_PATH.exists():
        # Auto-generate on first use
        if not generate_keypair():
            return None

    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    try:
        pem_data = PRIVATE_KEY_PATH.read_bytes()
        _private_key = load_pem_private_key(pem_data, password=None)
        return _private_key
    except Exception as e:
        logger.warning(f"[SIGNING] Failed to load private key: {e}")
        return None


def _load_public_key():
    """Load public key from disk (lazy, cached)."""
    global _public_key
    if _public_key is not None:
        return _public_key

    if not _check_available():
        return None

    if not PUBLIC_KEY_PATH.exists():
        return None

    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    try:
        pem_data = PUBLIC_KEY_PATH.read_bytes()
        _public_key = load_pem_public_key(pem_data)
        return _public_key
    except Exception as e:
        logger.warning(f"[SIGNING] Failed to load public key: {e}")
        return None


def sign_record(record_hash: str) -> Optional[str]:
    """
    Sign a record hash with the local Ed25519 private key.

    Args:
        record_hash: The SHA-256 hash string to sign.

    Returns:
        Hex-encoded signature string, or None if signing is unavailable.
    """
    private_key = _load_private_key()
    if private_key is None:
        return None

    try:
        signature_bytes = private_key.sign(record_hash.encode("utf-8"))
        return signature_bytes.hex()
    except Exception as e:
        logger.warning(f"[SIGNING] Failed to sign: {e}")
        return None


def verify_signature(record_hash: str, signature_hex: str, public_key_pem: bytes = None) -> bool:
    """
    Verify an Ed25519 signature on a record hash.

    Args:
        record_hash: The SHA-256 hash string that was signed.
        signature_hex: Hex-encoded signature to verify.
        public_key_pem: Optional PEM bytes of the public key.
                        If not provided, uses the local public key.

    Returns:
        True if signature is valid, False otherwise.
    """
    if not _check_available():
        return False

    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    try:
        if public_key_pem:
            pub_key = load_pem_public_key(public_key_pem)
        else:
            pub_key = _load_public_key()
            if pub_key is None:
                return False

        signature_bytes = bytes.fromhex(signature_hex)
        pub_key.verify(signature_bytes, record_hash.encode("utf-8"))
        return True
    except Exception:
        return False


def get_public_key_pem() -> Optional[str]:
    """
    Get the public key as a PEM string (for sharing/verification).

    Returns:
        PEM-encoded public key string, or None.
    """
    if not PUBLIC_KEY_PATH.exists():
        if not generate_keypair():
            return None

    try:
        return PUBLIC_KEY_PATH.read_text()
    except Exception:
        return None


def get_signer_id() -> Optional[str]:
    """
    Get a short identifier for the current signer (fingerprint of public key).

    Returns:
        First 16 hex chars of SHA-256(public_key_pem), or None.
    """
    import hashlib

    pem = get_public_key_pem()
    if not pem:
        return None

    return hashlib.sha256(pem.encode()).hexdigest()[:16]


def is_signing_available() -> bool:
    """Check if signing is available (cryptography lib installed)."""
    return _check_available()


def reset_cache():
    """Reset cached keys (for testing)."""
    global _private_key, _public_key
    _private_key = None
    _public_key = None
