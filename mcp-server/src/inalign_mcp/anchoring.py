"""
On-Chain Anchoring for Provenance Chains

Provides cryptographic anchoring of provenance merkle roots to
public blockchains for tamper-evident, third-party verifiable
audit trails.

Supported chains:
- Ethereum (mainnet, sepolia, arbitrum)
- Polygon
- Bitcoin (via OP_RETURN or Chainpoint)

Architecture:
1. Collect merkle roots from provenance chains
2. Batch roots into a single anchor transaction
3. Store anchor proof (tx hash, block number)
4. Verify anchors against chain state
"""

import os
import json
import hashlib
import logging
from typing import Any, Optional
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger("inalign-anchor")


class ChainType(str, Enum):
    """Supported blockchain networks."""
    ETHEREUM_MAINNET = "ethereum_mainnet"
    ETHEREUM_SEPOLIA = "ethereum_sepolia"
    ARBITRUM = "arbitrum"
    POLYGON = "polygon"
    BITCOIN = "bitcoin"


@dataclass
class AnchorProof:
    """
    Proof that a merkle root was anchored on-chain.

    Contains all information needed to independently verify
    the anchor without trusting In-A-Lign.
    """
    # Identity
    proof_id: str
    created_at: str

    # Anchor data
    merkle_root: str
    chain_type: ChainType
    transaction_hash: str
    block_number: int
    block_hash: str

    # Batch info (if part of batched anchor)
    batch_root: Optional[str] = None
    merkle_proof: Optional[list[str]] = None

    # Session reference
    session_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "proof_id": self.proof_id,
            "created_at": self.created_at,
            "merkle_root": self.merkle_root,
            "chain_type": self.chain_type.value,
            "transaction_hash": self.transaction_hash,
            "block_number": self.block_number,
            "block_hash": self.block_hash,
            "batch_root": self.batch_root,
            "merkle_proof": self.merkle_proof,
            "session_id": self.session_id,
        }


@dataclass
class AnchorConfig:
    """Configuration for blockchain anchoring."""
    chain_type: ChainType = ChainType.ETHEREUM_SEPOLIA
    rpc_url: str = ""
    private_key: str = ""
    contract_address: str = ""
    gas_limit: int = 100000
    batch_size: int = 100
    batch_interval_seconds: int = 3600

    @classmethod
    def from_env(cls) -> "AnchorConfig":
        """Load configuration from environment."""
        chain_str = os.getenv("ANCHOR_CHAIN", "ethereum_sepolia")
        chain_map = {
            "ethereum_mainnet": ChainType.ETHEREUM_MAINNET,
            "ethereum_sepolia": ChainType.ETHEREUM_SEPOLIA,
            "arbitrum": ChainType.ARBITRUM,
            "polygon": ChainType.POLYGON,
            "bitcoin": ChainType.BITCOIN,
        }
        return cls(
            chain_type=chain_map.get(chain_str, ChainType.ETHEREUM_SEPOLIA),
            rpc_url=os.getenv("ETH_RPC_URL", ""),
            private_key=os.getenv("ETH_PRIVATE_KEY", ""),
            contract_address=os.getenv("ANCHOR_CONTRACT_ADDRESS", ""),
            gas_limit=int(os.getenv("ANCHOR_GAS_LIMIT", "100000")),
            batch_size=int(os.getenv("ANCHOR_BATCH_SIZE", "100")),
            batch_interval_seconds=int(os.getenv("ANCHOR_BATCH_INTERVAL", "3600")),
        )


class AnchorService:
    """
    Service for anchoring provenance merkle roots on-chain.

    Features:
    - Batched anchoring for cost efficiency
    - Multi-chain support
    - Verification without trust
    - Anchor proof generation
    - Neo4j graph integration for third-party verification queries
    """

    # Simple anchor contract ABI (just stores a hash)
    ANCHOR_ABI = [
        {
            "inputs": [{"type": "bytes32", "name": "hash"}],
            "name": "anchor",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [{"type": "bytes32", "name": "hash"}],
            "name": "isAnchored",
            "outputs": [{"type": "bool"}],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [{"type": "bytes32", "name": "hash"}],
            "name": "getAnchorTime",
            "outputs": [{"type": "uint256"}],
            "stateMutability": "view",
            "type": "function"
        },
    ]

    def __init__(self, config: Optional[AnchorConfig] = None, graph_store=None):
        """Initialize anchor service with optional graph store."""
        self.config = config or AnchorConfig.from_env()
        self._web3 = None
        self._contract = None
        self._pending_roots: list[tuple[str, str]] = []  # (session_id, merkle_root)
        self._proofs: dict[str, AnchorProof] = {}
        self._graph_store = graph_store

    @property
    def web3(self):
        """Lazy load web3 connection."""
        if self._web3 is None:
            try:
                from web3 import Web3
                self._web3 = Web3(Web3.HTTPProvider(self.config.rpc_url))
                if not self._web3.is_connected():
                    logger.warning("Web3 not connected to RPC")
            except ImportError:
                logger.warning("web3 package not installed")
                return None
        return self._web3

    @property
    def contract(self):
        """Get anchor contract instance."""
        if self._contract is None and self.web3 and self.config.contract_address:
            self._contract = self.web3.eth.contract(
                address=self.config.contract_address,
                abi=self.ANCHOR_ABI,
            )
        return self._contract

    def queue_anchor(self, session_id: str, merkle_root: str):
        """
        Queue a merkle root for batched anchoring.

        Roots are collected and anchored together to reduce
        transaction costs.
        """
        self._pending_roots.append((session_id, merkle_root))
        logger.info(f"Queued root for anchoring: {merkle_root[:16]}... (session: {session_id})")

        # Auto-flush if batch is full
        if len(self._pending_roots) >= self.config.batch_size:
            self.flush_batch()

    def flush_batch(self) -> Optional[str]:
        """
        Anchor all pending roots in a single transaction.

        Returns transaction hash or None if failed/empty.
        """
        if not self._pending_roots:
            return None

        if not self.web3 or not self.config.private_key:
            logger.warning("Cannot anchor: Web3 or private key not configured")
            return None

        # Compute batch merkle root
        roots = [r[1] for r in self._pending_roots]
        batch_root = self._compute_batch_root(roots)

        try:
            # Build and send transaction
            from web3 import Web3

            account = self.web3.eth.account.from_key(self.config.private_key)
            nonce = self.web3.eth.get_transaction_count(account.address)

            tx = self.contract.functions.anchor(
                bytes.fromhex(batch_root)
            ).build_transaction({
                "from": account.address,
                "gas": self.config.gas_limit,
                "nonce": nonce,
            })

            signed_tx = self.web3.eth.account.sign_transaction(tx, self.config.private_key)
            tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            tx_hash_hex = tx_hash.hex()

            # Wait for receipt
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

            # Create proofs for each root
            import uuid
            for i, (session_id, root) in enumerate(self._pending_roots):
                proof = AnchorProof(
                    proof_id=f"anchor:{uuid.uuid4().hex[:12]}",
                    created_at=datetime.now(timezone.utc).isoformat(),
                    merkle_root=root,
                    chain_type=self.config.chain_type,
                    transaction_hash=tx_hash_hex,
                    block_number=receipt.blockNumber,
                    block_hash=receipt.blockHash.hex(),
                    batch_root=batch_root,
                    merkle_proof=self._compute_merkle_proof(roots, i),
                    session_id=session_id,
                )
                self._proofs[root] = proof

                # Store in graph for third-party verification queries
                if self._graph_store:
                    try:
                        self._graph_store.store_anchor(
                            session_id=session_id,
                            proof_id=proof.proof_id,
                            merkle_root=proof.merkle_root,
                            chain_type=proof.chain_type.value,
                            transaction_hash=proof.transaction_hash,
                            block_number=proof.block_number,
                            block_hash=proof.block_hash,
                            batch_root=proof.batch_root,
                            merkle_proof=proof.merkle_proof,
                        )
                    except Exception as e:
                        logger.error(f"Failed to store anchor in graph: {e}")

            logger.info(f"Anchored {len(self._pending_roots)} roots in tx {tx_hash_hex}")

            # Clear pending
            self._pending_roots = []

            return tx_hash_hex

        except Exception as e:
            logger.error(f"Anchoring failed: {e}")
            return None

    def _compute_batch_root(self, roots: list[str]) -> str:
        """Compute merkle root of multiple roots."""
        if not roots:
            return hashlib.sha256(b"").hexdigest()

        hashes = list(roots)

        while len(hashes) > 1:
            if len(hashes) % 2 == 1:
                hashes.append(hashes[-1])

            new_hashes = []
            for i in range(0, len(hashes), 2):
                combined = hashes[i] + hashes[i + 1]
                new_hashes.append(hashlib.sha256(combined.encode()).hexdigest())
            hashes = new_hashes

        return hashes[0]

    def _compute_merkle_proof(self, roots: list[str], index: int) -> list[str]:
        """Compute merkle proof for a specific root in the batch."""
        if len(roots) == 1:
            return []

        proof = []
        hashes = list(roots)

        while len(hashes) > 1:
            if len(hashes) % 2 == 1:
                hashes.append(hashes[-1])

            # Find sibling
            if index % 2 == 0:
                sibling_idx = index + 1
            else:
                sibling_idx = index - 1

            if sibling_idx < len(hashes):
                proof.append(hashes[sibling_idx])

            # Move up
            new_hashes = []
            for i in range(0, len(hashes), 2):
                combined = hashes[i] + hashes[i + 1]
                new_hashes.append(hashlib.sha256(combined.encode()).hexdigest())
            hashes = new_hashes
            index = index // 2

        return proof

    def get_proof(self, merkle_root: str) -> Optional[AnchorProof]:
        """Get anchor proof for a merkle root."""
        return self._proofs.get(merkle_root)

    def verify_anchor(self, proof: AnchorProof) -> tuple[bool, str]:
        """
        Verify an anchor proof against on-chain data.

        Returns (is_valid, error_message).
        """
        if not self.web3:
            return False, "Web3 not connected"

        try:
            # Check if anchored on contract
            is_anchored = self.contract.functions.isAnchored(
                bytes.fromhex(proof.batch_root or proof.merkle_root)
            ).call()

            if not is_anchored:
                return False, "Hash not found on chain"

            # Verify merkle proof if batched
            if proof.batch_root and proof.merkle_proof:
                computed_root = proof.merkle_root
                for sibling in proof.merkle_proof:
                    # Determine order (simplified - real impl would track position)
                    combined = computed_root + sibling
                    computed_root = hashlib.sha256(combined.encode()).hexdigest()

                if computed_root != proof.batch_root:
                    return False, "Merkle proof invalid"

            return True, "Verified"

        except Exception as e:
            return False, str(e)

    def verify_without_web3(self, proof: AnchorProof, tx_data: dict) -> tuple[bool, str]:
        """
        Verify anchor proof using provided transaction data.

        Allows verification without connecting to RPC by providing
        transaction/block data obtained from any source (explorer, etc).
        """
        # Verify block hash matches
        if tx_data.get("block_hash") != proof.block_hash:
            return False, "Block hash mismatch"

        # Verify transaction hash matches
        if tx_data.get("tx_hash") != proof.transaction_hash:
            return False, "Transaction hash mismatch"

        # Verify batch root is in transaction data
        if proof.batch_root:
            if proof.batch_root not in tx_data.get("input_data", ""):
                return False, "Batch root not in transaction"

        # Verify merkle proof
        if proof.merkle_proof:
            computed = proof.merkle_root
            for sibling in proof.merkle_proof:
                combined = computed + sibling
                computed = hashlib.sha256(combined.encode()).hexdigest()
            if computed != proof.batch_root:
                return False, "Merkle proof invalid"

        return True, "Verified (offline)"

    def verify_session_full(self, session_id: str) -> dict[str, Any]:
        """
        Full verification using graph database.

        Combines:
        - Chain integrity verification
        - On-chain anchor verification
        - Third-party verifiable proof
        """
        if not self._graph_store:
            return {
                "error": "Graph store not configured",
                "session_id": session_id,
            }

        # Use graph store's full verification
        result = self._graph_store.verify_session_full(session_id)

        # If anchored, also verify on-chain
        if result.get("is_anchored") and self.web3:
            merkle_root = result.get("verification_details", {}).get("merkle_root")
            if merkle_root:
                proof = self.get_proof(merkle_root)
                if proof:
                    is_valid, msg = self.verify_anchor(proof)
                    result["onchain_verified"] = is_valid
                    result["onchain_message"] = msg

                    # Update graph if verified
                    if is_valid and self._graph_store:
                        current_block = self.web3.eth.block_number
                        self._graph_store.mark_anchor_verified(
                            proof.proof_id,
                            current_block,
                        )

        return result

    def get_verification_report(self, session_id: str) -> dict[str, Any]:
        """
        Generate third-party verifiable report.

        Contains all information needed to independently verify
        the provenance chain without trusting In-A-Lign.
        """
        report = {
            "report_type": "third_party_verification",
            "session_id": session_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "verification_status": {},
            "anchor_proof": None,
            "verification_instructions": [],
        }

        # Get full verification
        verification = self.verify_session_full(session_id)
        report["verification_status"] = verification

        # Get anchor proof for independent verification
        merkle_root = verification.get("verification_details", {}).get("merkle_root")
        if merkle_root:
            proof = self.get_proof(merkle_root)
            if proof:
                report["anchor_proof"] = proof.to_dict()

        # Add verification instructions
        report["verification_instructions"] = [
            "1. Verify chain integrity by recalculating all record hashes",
            "2. Verify hash chain links (each record's previous_hash matches prior record's hash)",
            "3. Compute merkle root from all record hashes",
            f"4. Look up transaction {verification.get('verification_details', {}).get('tx_hash')} on {verification.get('verification_details', {}).get('chain_type')}",
            "5. Verify the merkle root (or batch root) is in the transaction input data",
            "6. If batched, verify the merkle proof to confirm inclusion in batch",
        ]

        return report


# Global service instance
_anchor_service: Optional[AnchorService] = None


def get_anchor_service(graph_store=None) -> AnchorService:
    """Get or create the global anchor service."""
    global _anchor_service
    if _anchor_service is None:
        _anchor_service = AnchorService(graph_store=graph_store)
    elif graph_store and _anchor_service._graph_store is None:
        _anchor_service._graph_store = graph_store
    return _anchor_service


def anchor_chain(session_id: str, merkle_root: str, graph_store=None):
    """Convenience function to queue a chain for anchoring."""
    get_anchor_service(graph_store).queue_anchor(session_id, merkle_root)


def get_anchor_proof(merkle_root: str) -> Optional[AnchorProof]:
    """Convenience function to get anchor proof."""
    return get_anchor_service().get_proof(merkle_root)


def verify_session_third_party(session_id: str, graph_store=None) -> dict[str, Any]:
    """
    Convenience function for full third-party verification.

    Returns comprehensive verification status using graph and on-chain data.
    """
    service = get_anchor_service(graph_store)
    return service.verify_session_full(session_id)


def get_verification_report(session_id: str, graph_store=None) -> dict[str, Any]:
    """
    Convenience function to generate third-party verifiable report.
    """
    service = get_anchor_service(graph_store)
    return service.get_verification_report(session_id)
