"""
Polygon Blockchain Anchoring for InALign

SQLite-first, local-only blockchain anchoring:
- Computes Merkle root from session hash chains in provenance.db
- Anchors to Polygon (mainnet or Amoy testnet) via web3.py
- Stores anchor proofs locally in SQLite
- Simple config: just set POLYGON_PRIVATE_KEY in ~/.inalign.env

Cost: ~$0.001-0.01 per anchor on Polygon mainnet.
"""

import os
import json
import hashlib
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any
from dataclasses import dataclass, asdict

logger = logging.getLogger("inalign-polygon")

INALIGN_DIR = Path.home() / ".inalign"
DB_PATH = INALIGN_DIR / "provenance.db"

# Network configurations
NETWORK_CONFIGS = {
    "mainnet": {
        "chain_id": 137,
        "chain_name": "Polygon Mainnet",
        "rpc_urls": [
            "https://polygon-rpc.com",
            "https://rpc-mainnet.matic.network",
            "https://matic-mainnet.chainstacklabs.com",
        ],
        "explorer": "https://polygonscan.com",
        "currency": "POL",
    },
    "amoy": {
        "chain_id": 80002,
        "chain_name": "Polygon Amoy Testnet",
        "rpc_urls": [
            "https://rpc-amoy.polygon.technology",
            "https://polygon-amoy-bor-rpc.publicnode.com",
        ],
        "explorer": "https://amoy.polygonscan.com",
        "currency": "POL",
    },
}


def get_network() -> str:
    return os.getenv("POLYGON_NETWORK", "amoy").lower()


def get_config() -> dict:
    network = get_network()
    return NETWORK_CONFIGS.get(network, NETWORK_CONFIGS["amoy"])


@dataclass
class AnchorResult:
    """Result of blockchain anchoring."""
    success: bool
    session_id: str
    merkle_root: str
    record_count: int = 0
    transaction_hash: Optional[str] = None
    block_number: Optional[int] = None
    block_timestamp: Optional[str] = None
    gas_used: Optional[int] = None
    cost_matic: Optional[float] = None
    cost_usd: Optional[float] = None
    explorer_url: Optional[str] = None
    network: Optional[str] = None
    wallet_address: Optional[str] = None
    error: Optional[str] = None
    mock: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


# ============================================================
# SQLite Storage
# ============================================================

def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _ensure_anchor_table():
    """Create blockchain_anchors table if not exists."""
    conn = _get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS blockchain_anchors (
            id TEXT PRIMARY KEY,
            session_id TEXT,
            merkle_root TEXT NOT NULL,
            record_count INTEGER DEFAULT 0,
            transaction_hash TEXT,
            block_number INTEGER,
            block_timestamp TEXT,
            chain TEXT DEFAULT 'polygon',
            network TEXT DEFAULT 'amoy',
            gas_used INTEGER,
            cost_matic REAL,
            cost_usd REAL,
            explorer_url TEXT,
            mock INTEGER DEFAULT 0,
            wallet_address TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_anchors_session
        ON blockchain_anchors(session_id)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_anchors_merkle
        ON blockchain_anchors(merkle_root)
    """)
    conn.commit()
    conn.close()


# Auto-init on import
try:
    _ensure_anchor_table()
except Exception:
    pass


# ============================================================
# Merkle Root Computation (from SQLite records)
# ============================================================

def compute_merkle_root(record_hashes: list[str]) -> str:
    """Compute merkle root from a list of hashes."""
    if not record_hashes:
        return hashlib.sha256(b"empty").hexdigest()

    hashes = list(record_hashes)
    while len(hashes) > 1:
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        new_level = []
        for i in range(0, len(hashes), 2):
            combined = hashes[i] + hashes[i + 1]
            new_level.append(hashlib.sha256(combined.encode()).hexdigest())
        hashes = new_level

    return hashes[0]


def get_session_merkle_root(session_id: str) -> tuple[str, int]:
    """Get merkle root for a session from SQLite records."""
    try:
        conn = _get_db()
        rows = conn.execute("""
            SELECT record_hash FROM records
            WHERE session_id = ?
            ORDER BY sequence_number ASC
        """, (session_id,)).fetchall()
        conn.close()

        hashes = [r["record_hash"] for r in rows if r["record_hash"]]
        if not hashes:
            return "", 0

        return compute_merkle_root(hashes), len(hashes)
    except Exception as e:
        logger.error(f"Failed to get merkle root: {e}")
        return "", 0


def get_batch_merkle_root(session_ids: list[str] = None) -> tuple[str, int, list[dict]]:
    """Get combined merkle root for multiple sessions (or all)."""
    try:
        conn = _get_db()
        if session_ids:
            placeholders = ",".join("?" * len(session_ids))
            rows = conn.execute(f"""
                SELECT session_id, record_hash FROM records
                WHERE session_id IN ({placeholders})
                ORDER BY session_id, sequence_number ASC
            """, session_ids).fetchall()
        else:
            rows = conn.execute("""
                SELECT session_id, record_hash FROM records
                ORDER BY session_id, sequence_number ASC
            """).fetchall()
        conn.close()

        if not rows:
            return "", 0, []

        # Group by session
        sessions = {}
        for r in rows:
            sid = r["session_id"]
            if sid not in sessions:
                sessions[sid] = []
            sessions[sid].append(r["record_hash"])

        # Compute per-session roots
        session_roots = []
        for sid, hashes in sessions.items():
            root = compute_merkle_root(hashes)
            session_roots.append({"session_id": sid, "merkle_root": root,
                                  "record_count": len(hashes)})

        # Combine all session roots into batch root
        all_roots = [s["merkle_root"] for s in session_roots]
        batch_root = compute_merkle_root(all_roots)
        total_records = sum(s["record_count"] for s in session_roots)

        return batch_root, total_records, session_roots

    except Exception as e:
        logger.error(f"Failed to compute batch merkle root: {e}")
        return "", 0, []


# ============================================================
# RPC & Wallet Helpers
# ============================================================

def get_rpc_url() -> str:
    custom = os.getenv("POLYGON_RPC_URL")
    if custom:
        return custom
    return get_config()["rpc_urls"][0]


def get_wallet_key() -> Optional[str]:
    return os.getenv("POLYGON_PRIVATE_KEY")


def get_wallet_address() -> Optional[str]:
    """Get wallet address from private key or env."""
    addr = os.getenv("POLYGON_WALLET_ADDRESS")
    if addr:
        return addr
    pk = get_wallet_key()
    if pk:
        try:
            from web3 import Web3
            w3 = Web3()
            account = w3.eth.account.from_key(pk)
            return account.address
        except Exception:
            pass
    return None


def get_balance() -> dict:
    """Get wallet balance on current network."""
    pk = get_wallet_key()
    addr = get_wallet_address()
    if not addr:
        return {"error": "No wallet configured", "balance": 0}

    try:
        from web3 import Web3
        w3 = Web3(Web3.HTTPProvider(get_rpc_url()))
        if not w3.is_connected():
            return {"error": "Cannot connect to RPC", "balance": 0}

        balance_wei = w3.eth.get_balance(addr)
        balance_matic = float(w3.from_wei(balance_wei, 'ether'))
        return {
            "address": addr,
            "balance_matic": balance_matic,
            "balance_usd": balance_matic * 0.40,
            "network": get_network(),
            "rpc": get_rpc_url(),
            "can_anchor": pk is not None,
        }
    except ImportError:
        return {"error": "web3 not installed (pip install web3)", "balance": 0}
    except Exception as e:
        return {"error": str(e), "balance": 0}


# ============================================================
# Anchoring
# ============================================================

def anchor_session(session_id: str) -> AnchorResult:
    """Anchor a single session's hash chain to Polygon."""
    merkle_root, record_count = get_session_merkle_root(session_id)
    if not merkle_root:
        return AnchorResult(success=False, session_id=session_id,
                            merkle_root="", error="No records found")

    return _do_anchor(merkle_root, session_id, record_count)


def anchor_batch(session_ids: list[str] = None) -> AnchorResult:
    """Anchor multiple sessions as a single Merkle root."""
    batch_root, total_records, session_roots = get_batch_merkle_root(session_ids)
    if not batch_root:
        return AnchorResult(success=False, session_id="batch",
                            merkle_root="", error="No records found")

    sid_label = f"batch-{len(session_roots)}-sessions"
    return _do_anchor(batch_root, sid_label, total_records)


def _do_anchor(merkle_root: str, session_id: str, record_count: int) -> AnchorResult:
    """Core anchoring logic — tries real, falls back to mock."""
    private_key = get_wallet_key()
    network = get_network()

    if private_key:
        try:
            result = _anchor_real(merkle_root, session_id, record_count,
                                  get_rpc_url(), private_key)
            _store_anchor_proof(result)
            return result
        except ImportError:
            logger.warning("web3 not installed, using mock")
        except Exception as e:
            logger.error(f"Real anchor failed: {e}")
            return AnchorResult(success=False, session_id=session_id,
                                merkle_root=merkle_root, error=str(e),
                                network=network)

    result = _anchor_mock(merkle_root, session_id, record_count)
    _store_anchor_proof(result)
    return result


def _anchor_real(
    merkle_root: str, session_id: str, record_count: int,
    rpc_url: str, private_key: str,
) -> AnchorResult:
    """Real blockchain anchoring using web3."""
    from web3 import Web3

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        raise Exception(f"Cannot connect to RPC: {rpc_url}")

    account = w3.eth.account.from_key(private_key)
    address = account.address
    network = get_network()
    config = get_config()

    balance = w3.eth.get_balance(address)
    balance_matic = w3.from_wei(balance, 'ether')
    if balance_matic < 0.001:
        raise Exception(f"Insufficient balance: {balance_matic:.6f} POL")

    # Encode merkle root as transaction data
    data = bytes.fromhex(merkle_root)

    nonce = w3.eth.get_transaction_count(address)
    gas_price = w3.eth.gas_price

    tx = {
        'nonce': nonce,
        'to': address,  # self-send (data-only tx)
        'value': 0,
        'gas': 21000 + len(data) * 16,
        'gasPrice': gas_price,
        'data': data,
        'chainId': config["chain_id"],
    }

    signed = w3.eth.account.sign_transaction(tx, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    tx_hash_hex = tx_hash.hex()

    logger.info(f"[ANCHOR] TX sent: {tx_hash_hex}")

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    gas_used = receipt.gasUsed
    cost_wei = gas_used * gas_price
    cost_matic = float(w3.from_wei(cost_wei, 'ether'))

    return AnchorResult(
        success=True,
        session_id=session_id,
        merkle_root=merkle_root,
        record_count=record_count,
        transaction_hash=tx_hash_hex,
        block_number=receipt.blockNumber,
        block_timestamp=datetime.now(timezone.utc).isoformat(),
        gas_used=gas_used,
        cost_matic=cost_matic,
        cost_usd=cost_matic * 0.40,
        explorer_url=f"{config['explorer']}/tx/{tx_hash_hex}",
        network=network,
        wallet_address=address,
    )


def _anchor_mock(
    merkle_root: str, session_id: str, record_count: int,
) -> AnchorResult:
    """Mock anchor for testing (no wallet needed)."""
    mock_tx = f"0x{uuid.uuid4().hex}{uuid.uuid4().hex[:24]}"
    config = get_config()
    network = get_network()

    return AnchorResult(
        success=True,
        session_id=session_id,
        merkle_root=merkle_root,
        record_count=record_count,
        transaction_hash=mock_tx,
        block_number=99999999,
        block_timestamp=datetime.now(timezone.utc).isoformat(),
        gas_used=21500,
        cost_matic=0.0,
        cost_usd=0.0,
        explorer_url=f"{config['explorer']}/tx/{mock_tx}",
        network=network,
        wallet_address=get_wallet_address() or "not_configured",
        mock=True,
    )


# ============================================================
# SQLite Proof Storage
# ============================================================

def _store_anchor_proof(result: AnchorResult):
    """Store anchor proof in SQLite."""
    try:
        _ensure_anchor_table()
        conn = _get_db()
        anchor_id = f"anchor-{uuid.uuid4().hex[:12]}"
        conn.execute("""
            INSERT INTO blockchain_anchors
            (id, session_id, merkle_root, record_count, transaction_hash,
             block_number, block_timestamp, chain, network, gas_used,
             cost_matic, cost_usd, explorer_url, mock, wallet_address, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (anchor_id, result.session_id, result.merkle_root, result.record_count,
              result.transaction_hash, result.block_number, result.block_timestamp,
              "polygon", result.network, result.gas_used, result.cost_matic,
              result.cost_usd, result.explorer_url, 1 if result.mock else 0,
              result.wallet_address,
              datetime.now(timezone.utc).isoformat()))
        conn.commit()
        conn.close()
        logger.info(f"[ANCHOR] Stored proof: {anchor_id}")
    except Exception as e:
        logger.error(f"Failed to store anchor proof: {e}")


def get_anchor_history(session_id: str = None, limit: int = 20) -> list[dict]:
    """Get anchor history from SQLite."""
    try:
        _ensure_anchor_table()
        conn = _get_db()
        if session_id:
            rows = conn.execute("""
                SELECT * FROM blockchain_anchors
                WHERE session_id = ?
                ORDER BY created_at DESC LIMIT ?
            """, (session_id, limit)).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM blockchain_anchors
                ORDER BY created_at DESC LIMIT ?
            """, (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def get_latest_anchor(session_id: str = None) -> Optional[dict]:
    """Get most recent anchor proof."""
    history = get_anchor_history(session_id, limit=1)
    return history[0] if history else None


# ============================================================
# Verification
# ============================================================

def verify_anchor(tx_hash: str) -> dict:
    """Verify anchor transaction on Polygon."""
    try:
        from web3 import Web3
        w3 = Web3(Web3.HTTPProvider(get_rpc_url()))
        if not w3.is_connected():
            return {"verified": False, "error": "Cannot connect to RPC"}

        tx = w3.eth.get_transaction(tx_hash)
        if not tx:
            return {"verified": False, "error": "Transaction not found"}

        receipt = w3.eth.get_transaction_receipt(tx_hash)
        merkle_root_from_chain = tx.input.hex() if tx.input else None

        return {
            "verified": True,
            "block_number": receipt.blockNumber,
            "status": "confirmed" if receipt.status == 1 else "failed",
            "merkle_root": merkle_root_from_chain,
            "confirmations": w3.eth.block_number - receipt.blockNumber,
            "network": get_network(),
            "explorer_url": f"{get_config()['explorer']}/tx/{tx_hash}",
        }
    except ImportError:
        return {"verified": False, "error": "web3 not installed (pip install web3)"}
    except Exception as e:
        return {"verified": False, "error": str(e)}


def verify_session_integrity(session_id: str) -> dict:
    """Full integrity check: recompute merkle root and compare with anchored."""
    merkle_root, record_count = get_session_merkle_root(session_id)
    if not merkle_root:
        return {"integrity": "unknown", "error": "No records found"}

    latest = get_latest_anchor(session_id)
    if not latest:
        return {
            "integrity": "unanchored",
            "current_merkle_root": merkle_root,
            "record_count": record_count,
            "message": "Session has not been anchored to blockchain yet",
        }

    anchored_root = latest["merkle_root"]
    match = merkle_root == anchored_root

    result = {
        "integrity": "valid" if match else "TAMPERED",
        "current_merkle_root": merkle_root,
        "anchored_merkle_root": anchored_root,
        "match": match,
        "record_count": record_count,
        "anchor_tx": latest.get("transaction_hash"),
        "anchor_time": latest.get("created_at"),
        "network": latest.get("network"),
    }

    if not match:
        result["warning"] = ("Records have been modified since anchoring! "
                             "The current merkle root does not match the "
                             "blockchain-anchored root.")

    return result


# ============================================================
# Setup helper
# ============================================================

def setup_instructions() -> str:
    return """
# Polygon Wallet Setup for InALign

## Quick Start (3 steps)

### 1. Get a Wallet
- Install Metamask or use any EVM wallet
- Note your wallet address (0x...)

### 2. Get POL Tokens
- Testnet (free): https://faucet.polygon.technology (Amoy)
- Mainnet: Buy POL on any exchange, ~$1 enough for 100+ anchors

### 3. Configure InALign
Add to ~/.inalign.env:
```
POLYGON_PRIVATE_KEY=your_private_key_here
POLYGON_NETWORK=amoy          # or mainnet
POLYGON_RPC_URL=               # optional, uses public RPC
```

## Cost
- Amoy testnet: FREE
- Mainnet: ~$0.001-0.01 per anchor

## Security
- Use a dedicated wallet for anchoring only
- Keep minimal POL balance (~$1-5)
- Private key never leaves your machine (local-first)
"""
