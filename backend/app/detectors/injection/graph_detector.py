"""
Graph RAG-enhanced injection detector.

Uses the Neo4j attack knowledge graph to augment regex-based detection:
- Searches for similar known attacks by keyword overlap
- Boosts risk score based on graph evidence
- Detects attacks that evade regex but are similar to known-malicious inputs

IMPORTANT: This detector is intentionally conservative to avoid false
positives. It only fires when there is strong multi-keyword overlap
with known attacks, not on single common keywords like "ignore" or "admin".
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional

from neo4j import AsyncSession

from app.services.attack_knowledge_service import AttackKnowledgeService

logger = logging.getLogger("agentshield.graph_detector")

# Keywords that are too common in benign text to be useful alone.
# The graph detector requires MULTIPLE co-occurring attack keywords
# to avoid flagging "The admin panel needs a password reset" as an attack.
_BENIGN_OVERLAP_WORDS = {
    "system", "admin", "password", "ignore", "execute", "reveal",
    "debug", "override", "bypass", "pretend", "mode", "enable",
    "disable", "show", "display", "export", "command", "extract",
    "activate", "deactivate",
}

# High-intent keyword combinations that strongly signal attacks
# (any 2+ of these co-occurring is suspicious)
_HIGH_INTENT_COMBOS = [
    {"ignore", "previous", "instructions"},
    {"ignore", "instructions", "prompt"},
    {"system", "prompt", "reveal"},
    {"system", "prompt", "show"},
    {"admin", "privilege", "execute"},
    {"bypass", "safety", "filter"},
    {"jailbreak", "unrestricted"},
    {"decode", "execute", "follow"},
    {"disable", "safety", "security"},
    {"override", "instructions", "ignore"},
]


class GraphDetector:
    """
    Graph-based injection detector that queries the attack knowledge graph.

    This detector complements the rule-based detector by leveraging
    historical attack data stored in Neo4j. It is intentionally conservative:
    - Requires high keyword overlap (>= 60%) with known attacks
    - Requires multiple shared keywords (>= 3)
    - Assigns moderate confidence (never > 0.75 from graph alone)
    - Is meant to catch evasion attacks, not replace regex patterns
    """

    def __init__(self, neo4j_session: AsyncSession):
        self._knowledge = AttackKnowledgeService(neo4j_session)

    async def detect(self, text: str) -> list[dict[str, Any]]:
        """
        Search the attack knowledge graph for similar known-malicious inputs.

        Returns a list of threat dicts for significant matches.
        Conservative thresholds prevent false positives on benign text.
        """
        threats: list[dict[str, Any]] = []

        # Quick check: does the text contain high-intent keyword combos?
        text_lower = text.lower()
        text_words = set(re.findall(r"[a-zA-Z]+", text_lower))

        has_intent_combo = False
        for combo in _HIGH_INTENT_COMBOS:
            if len(combo & text_words) >= 2:
                has_intent_combo = True
                break

        # Skip graph query entirely if no suspicious keyword combo found
        if not has_intent_combo:
            return threats

        try:
            similar = await self._knowledge.find_similar_attacks(
                text=text,
                min_overlap=0.5,  # Require 50%+ keyword overlap (was 0.3)
                limit=5,
            )

            if not similar:
                return threats

            for match in similar:
                similarity = match.get("similarity", 0)
                risk_score = match.get("risk_score", 0)
                shared = match.get("shared_keywords", 0)
                category = match.get("category", "unknown")

                # Require HIGH similarity, HIGH risk, AND multiple shared keywords
                if similarity >= 0.6 and risk_score >= 0.7 and shared >= 3:
                    # Cap confidence lower than regex-based detection
                    confidence = min(0.75, similarity * risk_score * 0.9)
                    severity = "medium"

                    threats.append({
                        "type": "injection",
                        "subtype": f"graph_rag_{category}",
                        "pattern_id": f"GRAPH-{match.get('sample_id', 'unknown')[:12]}",
                        "matched_text": f"Similar to known {category} attack ({shared} shared keywords)",
                        "position": (0, min(len(text), 50)),
                        "confidence": round(confidence, 4),
                        "severity": severity,
                        "description": (
                            f"Graph RAG: Input is {similarity:.0%} similar to a known "
                            f"{category} attack (risk={risk_score:.2f}, "
                            f"shared {shared} keywords)."
                        ),
                    })
                    break  # Only report the best match, not all

        except Exception as exc:
            logger.warning("GraphDetector query failed: %s", exc)

        if threats:
            logger.info(
                "GraphDetector found %d threat(s) for text of length %d.",
                len(threats), len(text),
            )

        return threats
