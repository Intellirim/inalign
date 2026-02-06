"""
Polygon Blockchain Anchoring for InALign

Simple, cost-effective blockchain anchoring:
- ~$0.01-0.05 per transaction on mainnet
- Free on Amoy testnet
- Batches multiple sessions
- Legally valid timestamps

Set POLYGON_NETWORK=amoy for testnet, POLYGON_NETWORK=mainnet for production.
"""

import os
import json
import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional, Any
from dataclasses import dataclass, asdict

logger = logging.getLogger("inalign-polygon")

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
    """Get current network from environment."""
    return os.getenv("POLYGON_NETWORK", "amoy").lower()


def get_config() -> dict:
    """Get configuration for current network."""
    network = get_network()
    return NETWORK_CONFIGS.get(network, NETWORK_CONFIGS["amoy"])


# For backwards compatibility
POLYGON_CONFIG = get_config()


@dataclass
class AnchorResult:
    """Result of blockchain anchoring."""
    success: bool
    session_id: str
    merkle_root: str
    transaction_hash: Optional[str] = None
    block_number: Optional[int] = None
    block_timestamp: Optional[str] = None
    gas_used: Optional[int] = None
    cost_matic: Optional[float] = None
    cost_usd: Optional[float] = None
    explorer_url: Optional[str] = None
    error: Optional[str] = None
    mock: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def get_rpc_url() -> str:
    """Get Polygon RPC URL from env or use public."""
    custom = os.getenv("POLYGON_RPC_URL")
    if custom:
        return custom
    config = get_config()
    return config["rpc_urls"][0]


def get_wallet_key() -> Optional[str]:
    """Get wallet private key from environment."""
    return os.getenv("POLYGON_PRIVATE_KEY")


def compute_merkle_root(record_hashes: list[str]) -> str:
    """Compute merkle root from record hashes."""
    if not record_hashes:
        return hashlib.sha256(b"empty").hexdigest()

    hashes = list(record_hashes)

    while len(hashes) > 1:
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])

        new_level = []
        for i in range(0, len(hashes), 2):
            combined = hashes[i] + hashes[i + 1]
            new_hash = hashlib.sha256(combined.encode()).hexdigest()
            new_level.append(new_hash)
        hashes = new_level

    return hashes[0]


def get_session_merkle_root(client_id: str) -> tuple[str, int]:
    """Get merkle root for all records of a client_id."""
    try:
        from .graph_store import get_graph_store
        store = get_graph_store()
        if not store:
            return "", 0

        with store.session() as session:
            result = session.run("""
                MATCH (r:ProvenanceRecord)
                WHERE r.client_id = $client_id
                RETURN r.record_hash as hash
                ORDER BY r.sequence_number ASC
            """, client_id=client_id)

            hashes = [row["hash"] for row in result if row["hash"]]

            if not hashes:
                return "", 0

            return compute_merkle_root(hashes), len(hashes)

    except Exception as e:
        logger.error(f"Failed to get merkle root: {e}")
        return "", 0


def anchor_to_polygon(
    client_id: str,
    session_id: str = None,
) -> AnchorResult:
    """
    Anchor client's provenance chain to Polygon mainnet.

    Returns AnchorResult with transaction details.
    """
    # Get merkle root
    merkle_root, record_count = get_session_merkle_root(client_id)

    if not merkle_root:
        return AnchorResult(
            success=False,
            session_id=session_id or client_id,
            merkle_root="",
            error="No records found to anchor"
        )

    private_key = get_wallet_key()
    rpc_url = get_rpc_url()

    # Try real anchoring if wallet configured
    if private_key:
        try:
            return _anchor_real(
                merkle_root=merkle_root,
                client_id=client_id,
                session_id=session_id,
                record_count=record_count,
                rpc_url=rpc_url,
                private_key=private_key,
            )
        except ImportError:
            logger.warning("web3 not installed, using mock anchor")
        except Exception as e:
            logger.error(f"Real anchor failed: {e}")
            return AnchorResult(
                success=False,
                session_id=session_id or client_id,
                merkle_root=merkle_root,
                error=str(e)
            )

    # Mock anchor for testing (no wallet configured)
    return _anchor_mock(merkle_root, client_id, session_id, record_count)


def _anchor_real(
    merkle_root: str,
    client_id: str,
    session_id: str,
    record_count: int,
    rpc_url: str,
    private_key: str,
) -> AnchorResult:
    """Real blockchain anchoring using web3."""
    from web3 import Web3

    w3 = Web3(Web3.HTTPProvider(rpc_url))

    if not w3.is_connected():
        raise Exception(f"Cannot connect to RPC: {rpc_url}")

    account = w3.eth.account.from_key(private_key)
    address = account.address

    # Check balance
    balance = w3.eth.get_balance(address)
    balance_matic = w3.from_wei(balance, 'ether')

    if balance_matic < 0.01:
        raise Exception(f"Insufficient MATIC balance: {balance_matic:.4f}")

    # Prepare data (merkle root as hex)
    data = bytes.fromhex(merkle_root)

    # Build transaction (simple data transaction to self)
    nonce = w3.eth.get_transaction_count(address)
    gas_price = w3.eth.gas_price

    tx = {
        'nonce': nonce,
        'to': address,  # Send to self (just storing data)
        'value': 0,
        'gas': 21000 + len(data) * 16,  # Base gas + data cost
        'gasPrice': gas_price,
        'data': data,
        'chainId': get_config()["chain_id"],
    }

    # Sign and send
    signed = w3.eth.account.sign_transaction(tx, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    tx_hash_hex = tx_hash.hex()

    logger.info(f"Transaction sent: {tx_hash_hex}")

    # Wait for receipt
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

    # Calculate cost
    gas_used = receipt.gasUsed
    cost_wei = gas_used * gas_price
    cost_matic = float(w3.from_wei(cost_wei, 'ether'))

    # Estimate USD (rough: 1 MATIC ~ $0.80)
    cost_usd = cost_matic * 0.80

    result = AnchorResult(
        success=True,
        session_id=session_id or client_id,
        merkle_root=merkle_root,
        transaction_hash=tx_hash_hex,
        block_number=receipt.blockNumber,
        block_timestamp=datetime.now(timezone.utc).isoformat(),
        gas_used=gas_used,
        cost_matic=cost_matic,
        cost_usd=cost_usd,
        explorer_url=f"{get_config()['explorer']}/tx/{tx_hash_hex}",
    )

    # Store anchor proof in Neo4j
    _store_anchor_proof(result, client_id, record_count)

    return result


def _anchor_mock(
    merkle_root: str,
    client_id: str,
    session_id: str,
    record_count: int,
) -> AnchorResult:
    """Mock anchor for testing without wallet."""
    import uuid

    mock_tx = f"0x{uuid.uuid4().hex}{uuid.uuid4().hex[:24]}"

    result = AnchorResult(
        success=True,
        session_id=session_id or client_id,
        merkle_root=merkle_root,
        transaction_hash=mock_tx,
        block_number=99999999,
        block_timestamp=datetime.now(timezone.utc).isoformat(),
        gas_used=21500,
        cost_matic=0.0001,
        cost_usd=0.0001,
        explorer_url=f"{POLYGON_CONFIG['explorer']}/tx/{mock_tx}",
        mock=True,
    )

    # Store mock proof too (for testing)
    _store_anchor_proof(result, client_id, record_count)

    logger.warning(f"Mock anchor created (no wallet configured): {mock_tx}")
    return result


def _store_anchor_proof(result: AnchorResult, client_id: str, record_count: int):
    """Store anchor proof in Neo4j."""
    try:
        from .graph_store import get_graph_store
        store = get_graph_store()
        if not store:
            return

        with store.session() as session:
            session.run("""
                MERGE (a:BlockchainAnchor {merkle_root: $merkle_root})
                ON CREATE SET
                    a.client_id = $client_id,
                    a.session_id = $session_id,
                    a.transaction_hash = $tx_hash,
                    a.block_number = $block_number,
                    a.block_timestamp = $block_timestamp,
                    a.chain = 'polygon',
                    a.explorer_url = $explorer_url,
                    a.record_count = $record_count,
                    a.cost_matic = $cost_matic,
                    a.mock = $mock,
                    a.created_at = datetime()
                WITH a
                MATCH (r:ProvenanceRecord {client_id: $client_id})
                MERGE (r)-[:ANCHORED_BY]->(a)
            """,
                merkle_root=result.merkle_root,
                client_id=client_id,
                session_id=result.session_id,
                tx_hash=result.transaction_hash,
                block_number=result.block_number,
                block_timestamp=result.block_timestamp,
                explorer_url=result.explorer_url,
                record_count=record_count,
                cost_matic=result.cost_matic,
                mock=result.mock,
            )

            logger.info(f"Stored anchor proof for {client_id}: {result.transaction_hash}")

    except Exception as e:
        logger.error(f"Failed to store anchor proof: {e}")


def get_anchor_status(client_id: str) -> Optional[dict]:
    """Get latest anchor status for a client."""
    try:
        from .graph_store import get_graph_store
        store = get_graph_store()
        if not store:
            return None

        with store.session() as session:
            result = session.run("""
                MATCH (a:BlockchainAnchor {client_id: $client_id})
                RETURN a.merkle_root as merkle_root,
                       a.transaction_hash as tx_hash,
                       a.block_number as block_number,
                       a.block_timestamp as timestamp,
                       a.explorer_url as explorer_url,
                       a.record_count as record_count,
                       a.cost_matic as cost,
                       a.mock as mock,
                       a.created_at as created_at
                ORDER BY a.created_at DESC
                LIMIT 1
            """, client_id=client_id)

            row = result.single()
            if row:
                return dict(row)
            return None

    except Exception as e:
        logger.error(f"Failed to get anchor status: {e}")
        return None


def verify_anchor(tx_hash: str) -> dict:
    """Verify anchor transaction on Polygon."""
    rpc_url = get_rpc_url()

    try:
        from web3 import Web3
        w3 = Web3(Web3.HTTPProvider(rpc_url))

        if not w3.is_connected():
            return {"verified": False, "error": "Cannot connect to RPC"}

        # Get transaction
        tx = w3.eth.get_transaction(tx_hash)
        if not tx:
            return {"verified": False, "error": "Transaction not found"}

        # Get receipt
        receipt = w3.eth.get_transaction_receipt(tx_hash)

        return {
            "verified": True,
            "block_number": receipt.blockNumber,
            "status": "confirmed" if receipt.status == 1 else "failed",
            "data_hex": tx.input.hex() if tx.input else None,
            "confirmations": w3.eth.block_number - receipt.blockNumber,
        }

    except ImportError:
        return {"verified": False, "error": "web3 not installed"}
    except Exception as e:
        return {"verified": False, "error": str(e)}


# Wallet setup helper
def setup_instructions() -> str:
    """Return wallet setup instructions."""
    return """
# Polygon Wallet Setup for InALign

## 1. Create/Use Metamask Wallet
- Install Metamask browser extension
- Create new wallet or use existing
- Switch network to Polygon Mainnet

## 2. Get MATIC Tokens
- Buy MATIC on exchange (Binance, Coinbase, etc.)
- Transfer to your Polygon wallet
- ~$5 worth is enough for ~100+ anchors

## 3. Export Private Key
- Metamask > Account Details > Export Private Key
- KEEP THIS SECURE!

## 4. Configure InALign
Set environment variables:

```bash
export POLYGON_PRIVATE_KEY="your_private_key_here"
export POLYGON_RPC_URL="https://polygon-rpc.com"  # Optional
```

Or add to .env file:
```
POLYGON_PRIVATE_KEY=your_private_key_here
```

## Cost Estimate
- Per anchor: ~$0.01-0.05
- Batch 100 sessions: ~$0.01-0.05 (same cost!)
- Monthly (1000 sessions): ~$0.10-0.50

## Security
- Use a dedicated wallet for anchoring
- Only keep small amount of MATIC
- Never share private key
"""
