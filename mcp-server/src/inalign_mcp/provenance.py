"""
Agent Provenance Layer

Cryptographically verifiable record of AI agent actions and decisions.
Based on W3C PROV data model with hash chaining for tamper-evidence.

Key Concepts (W3C PROV):
- Entity: Data that was used or generated
- Activity: An action that occurred (tool call, decision, etc.)
- Agent: The AI agent or user that performed the activity

Each record is:
1. Hashed (SHA-256)
2. Chained (includes previous record's hash)
3. Timestamped (ISO 8601)
4. Optionally signed
"""

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional
from enum import Enum
import uuid


class ActivityType(str, Enum):
    """Types of agent activities that can be recorded."""
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    LLM_REQUEST = "llm_request"
    LLM_RESPONSE = "llm_response"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    DECISION = "decision"
    USER_INPUT = "user_input"
    SECURITY_CHECK = "security_check"
    ERROR = "error"


@dataclass
class Entity:
    """W3C PROV Entity - Data that was used or generated."""
    id: str
    type: str  # "prompt", "response", "file", "tool_input", "tool_output"
    value_hash: str  # SHA-256 of the actual value (not stored, just hash)
    attributes: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_value(cls, value: Any, entity_type: str, **attrs) -> "Entity":
        """Create entity from a value, hashing it."""
        value_str = json.dumps(value, sort_keys=True, default=str)
        value_hash = hashlib.sha256(value_str.encode()).hexdigest()
        return cls(
            id=f"entity:{uuid.uuid4().hex[:12]}",
            type=entity_type,
            value_hash=value_hash,
            attributes=attrs,
        )


@dataclass
class Agent:
    """W3C PROV Agent - Who/what performed the activity."""
    id: str
    type: str  # "ai_agent", "user", "system"
    name: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProvenanceRecord:
    """
    A single provenance record in the chain.

    Contains:
    - Activity metadata (what happened)
    - Used entities (inputs)
    - Generated entities (outputs)
    - Agent attribution (who did it)
    - Chain link (previous record hash)
    - Cryptographic hash (tamper-evidence)
    """
    # Identity
    id: str
    timestamp: str  # ISO 8601

    # Activity (W3C PROV)
    activity_type: ActivityType
    activity_name: str
    activity_attributes: dict[str, Any] = field(default_factory=dict)

    # Entities
    used_entities: list[Entity] = field(default_factory=list)
    generated_entities: list[Entity] = field(default_factory=list)

    # Agent
    agent: Optional[Agent] = None

    # Chain
    previous_hash: str = ""  # Hash of previous record (empty for genesis)
    sequence_number: int = 0

    # Session context
    session_id: str = ""
    client_id: str = ""  # Links session to customer account

    # Computed hash (set after creation)
    record_hash: str = ""

    # Optional signature
    signature: Optional[str] = None
    signer_id: Optional[str] = None

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of this record's content."""
        # Create canonical representation (excluding hash and signature)
        content = {
            "id": self.id,
            "timestamp": self.timestamp,
            "activity_type": self.activity_type.value,
            "activity_name": self.activity_name,
            "activity_attributes": self.activity_attributes,
            "used_entities": [asdict(e) for e in self.used_entities],
            "generated_entities": [asdict(e) for e in self.generated_entities],
            "agent": asdict(self.agent) if self.agent else None,
            "previous_hash": self.previous_hash,
            "sequence_number": self.sequence_number,
            "session_id": self.session_id,
        }
        canonical = json.dumps(content, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "activity_type": self.activity_type.value,
            "activity_name": self.activity_name,
            "activity_attributes": self.activity_attributes,
            "used_entities": [asdict(e) for e in self.used_entities],
            "generated_entities": [asdict(e) for e in self.generated_entities],
            "agent": asdict(self.agent) if self.agent else None,
            "previous_hash": self.previous_hash,
            "sequence_number": self.sequence_number,
            "session_id": self.session_id,
            "record_hash": self.record_hash,
            "signature": self.signature,
            "signer_id": self.signer_id,
        }


class ProvenanceChain:
    """
    Manages a chain of provenance records for a session.

    Provides:
    - Append-only record creation
    - Hash chain verification
    - Export to various formats
    """

    def __init__(self, session_id: str, agent: Agent, client_id: str = ""):
        self.session_id = session_id
        self.agent = agent
        self.client_id = client_id  # Links to customer account
        self.records: list[ProvenanceRecord] = []
        self._sequence = 0

    @property
    def latest_hash(self) -> str:
        """Get hash of the latest record, or empty string if chain is empty."""
        if not self.records:
            return ""
        return self.records[-1].record_hash

    def record_activity(
        self,
        activity_type: ActivityType,
        activity_name: str,
        used: list[tuple[Any, str]] = None,  # (value, type) pairs
        generated: list[tuple[Any, str]] = None,
        attributes: dict[str, Any] = None,
    ) -> ProvenanceRecord:
        """
        Record a new activity in the chain.

        Args:
            activity_type: Type of activity
            activity_name: Name/description of the activity
            used: List of (value, entity_type) tuples for inputs
            generated: List of (value, entity_type) tuples for outputs
            attributes: Additional activity attributes

        Returns:
            The created provenance record
        """
        # Create entities
        used_entities = []
        if used:
            for value, entity_type in used:
                used_entities.append(Entity.from_value(value, entity_type))

        generated_entities = []
        if generated:
            for value, entity_type in generated:
                generated_entities.append(Entity.from_value(value, entity_type))

        # Create record
        record = ProvenanceRecord(
            id=f"prov:{uuid.uuid4().hex[:16]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            activity_type=activity_type,
            activity_name=activity_name,
            activity_attributes=attributes or {},
            used_entities=used_entities,
            generated_entities=generated_entities,
            agent=self.agent,
            previous_hash=self.latest_hash,
            sequence_number=self._sequence,
            session_id=self.session_id,
            client_id=self.client_id,
        )

        # Compute and set hash
        record.record_hash = record.compute_hash()

        # Add to chain
        self.records.append(record)
        self._sequence += 1

        return record

    def verify_chain(self) -> tuple[bool, Optional[str]]:
        """
        Verify the integrity of the entire chain.

        Returns:
            (is_valid, error_message)
        """
        if not self.records:
            return True, None

        # Check genesis record
        if self.records[0].previous_hash != "":
            return False, "Genesis record has non-empty previous_hash"

        # Verify each record
        for i, record in enumerate(self.records):
            # Verify hash
            computed = record.compute_hash()
            if computed != record.record_hash:
                return False, f"Hash mismatch at record {i}: {record.id}"

            # Verify chain link
            if i > 0:
                expected_prev = self.records[i - 1].record_hash
                if record.previous_hash != expected_prev:
                    return False, f"Chain broken at record {i}: {record.id}"

            # Verify sequence
            if record.sequence_number != i:
                return False, f"Sequence mismatch at record {i}: {record.id}"

        return True, None

    def export_json(self) -> str:
        """Export chain as JSON."""
        return json.dumps({
            "session_id": self.session_id,
            "agent": asdict(self.agent),
            "record_count": len(self.records),
            "chain_hash": self.latest_hash,
            "records": [r.to_dict() for r in self.records],
        }, indent=2)

    def export_prov_jsonld(self) -> dict:
        """Export as W3C PROV JSON-LD format."""
        # Simplified PROV-O compatible output
        prov = {
            "@context": {
                "prov": "http://www.w3.org/ns/prov#",
                "inalign": "https://in-a-lign.com/prov#",
            },
            "@graph": [],
        }

        for record in self.records:
            # Activity node
            activity = {
                "@id": record.id,
                "@type": "prov:Activity",
                "prov:startedAtTime": record.timestamp,
                "inalign:activityType": record.activity_type.value,
                "inalign:activityName": record.activity_name,
                "inalign:recordHash": record.record_hash,
                "inalign:previousHash": record.previous_hash,
            }

            # Add used entities
            if record.used_entities:
                activity["prov:used"] = [
                    {"@id": e.id, "inalign:valueHash": e.value_hash}
                    for e in record.used_entities
                ]

            # Add generated entities
            if record.generated_entities:
                activity["prov:generated"] = [
                    {"@id": e.id, "inalign:valueHash": e.value_hash}
                    for e in record.generated_entities
                ]

            # Add agent attribution
            if record.agent:
                activity["prov:wasAssociatedWith"] = {
                    "@id": record.agent.id,
                    "@type": "prov:Agent",
                    "prov:label": record.agent.name,
                }

            prov["@graph"].append(activity)

        return prov

    def get_merkle_root(self) -> str:
        """
        Compute Merkle root of all record hashes.
        Useful for on-chain anchoring.
        """
        if not self.records:
            return hashlib.sha256(b"").hexdigest()

        hashes = [r.record_hash for r in self.records]

        while len(hashes) > 1:
            if len(hashes) % 2 == 1:
                hashes.append(hashes[-1])  # Duplicate last if odd

            new_hashes = []
            for i in range(0, len(hashes), 2):
                combined = hashes[i] + hashes[i + 1]
                new_hashes.append(hashlib.sha256(combined.encode()).hexdigest())
            hashes = new_hashes

        return hashes[0]


# Global session chains storage
_session_chains: dict[str, ProvenanceChain] = {}


def get_or_create_chain(session_id: str, agent_name: str = "claude", client_id: str = "") -> ProvenanceChain:
    """Get or create a provenance chain for a session."""
    if session_id not in _session_chains:
        agent = Agent(
            id=f"agent:{agent_name}:{session_id[:8]}",
            type="ai_agent",
            name=agent_name,
        )
        _session_chains[session_id] = ProvenanceChain(session_id, agent, client_id)
    elif client_id and not _session_chains[session_id].client_id:
        # Update client_id if it was missing
        _session_chains[session_id].client_id = client_id
    return _session_chains[session_id]


def record_tool_call(
    session_id: str,
    tool_name: str,
    arguments: dict[str, Any],
    result: Any = None,
    agent_name: str = "claude",
) -> ProvenanceRecord:
    """Convenience function to record a tool call."""
    chain = get_or_create_chain(session_id, agent_name)

    used = [(arguments, "tool_input")]
    generated = [(result, "tool_output")] if result is not None else []

    return chain.record_activity(
        activity_type=ActivityType.TOOL_CALL,
        activity_name=tool_name,
        used=used,
        generated=generated,
        attributes={"tool_name": tool_name, "arguments": arguments},
    )


def record_decision(
    session_id: str,
    decision: str,
    reasoning: str = "",
    inputs: list[Any] = None,
    agent_name: str = "claude",
) -> ProvenanceRecord:
    """Convenience function to record a decision."""
    chain = get_or_create_chain(session_id, agent_name)

    used = [(inp, "decision_input") for inp in (inputs or [])]
    generated = [(decision, "decision")]

    return chain.record_activity(
        activity_type=ActivityType.DECISION,
        activity_name="decision",
        used=used,
        generated=generated,
        attributes={"decision": decision, "reasoning": reasoning},
    )


def get_chain_summary(session_id: str) -> dict[str, Any]:
    """Get summary of a session's provenance chain."""
    if session_id not in _session_chains:
        return {"exists": False}

    chain = _session_chains[session_id]
    is_valid, error = chain.verify_chain()

    return {
        "exists": True,
        "session_id": session_id,
        "record_count": len(chain.records),
        "chain_valid": is_valid,
        "validation_error": error,
        "latest_hash": chain.latest_hash,
        "merkle_root": chain.get_merkle_root(),
    }
