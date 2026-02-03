"""
Attack Knowledge Service — Graph RAG layer for adaptive threat detection.

Manages the attack knowledge graph in Neo4j:
- Stores every scan result (detected or missed) as an AttackSample node
- Extracts and links keywords and techniques
- Provides similarity search for real-time detection boosting
- Tracks detection rates per technique for continuous learning
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from typing import Any, Optional

from neo4j import AsyncSession

from app.graph import attack_queries as aq

logger = logging.getLogger("agentshield.attack_knowledge")

# ---------------------------------------------------------------------------
# Attack keyword extraction
# ---------------------------------------------------------------------------

# Core attack-related keywords to index in the graph
_ATTACK_KEYWORDS = {
    # instruction override
    "ignore", "disregard", "forget", "override", "bypass", "skip",
    "overlook", "dismiss", "neglect", "omit",
    # system extraction
    "system", "prompt", "instructions", "configuration", "hidden",
    "reveal", "show", "display", "expose", "output",
    # role manipulation
    "pretend", "act", "roleplay", "simulate", "persona",
    "dan", "jailbreak", "unrestricted", "evil",
    # privilege escalation
    "admin", "root", "sudo", "privilege", "elevated", "authorization",
    "execute", "command", "shell",
    # data extraction
    "password", "credential", "api_key", "secret", "database",
    "export", "dump", "extract",
    # encoding/evasion
    "base64", "decode", "hex", "rot13", "reverse", "backwards",
    "encode", "encrypted",
    # context manipulation
    "developer", "maintenance", "debug", "mode", "enable", "disable",
    "activate", "deactivate",
    # Korean keywords
    "무시", "시스템", "프롬프트", "관리자", "비밀번호", "권한",
    "활성화", "비활성화", "디버그", "개발자", "보안", "긴급",
}

# Technique classification based on mutation/attack type
_TECHNIQUE_DESCRIPTIONS = {
    "synonym_mutation": "Replace attack keywords with synonyms to evade exact-match regex",
    "homoglyph": "Replace ASCII chars with visually similar Unicode characters",
    "zero_width": "Insert invisible zero-width Unicode characters between keyword letters",
    "word_split": "Split keywords using hyphens, dots, or spaces",
    "case_mix": "Apply random upper/lower case mixing",
    "leet_speak": "Substitute letters with numbers/symbols (1337 speak)",
    "encoding": "Wrap attack text in base64, hex, or other encodings",
    "camouflage": "Embed attack within benign-looking context",
    "delimiter": "Inject fake system/role delimiters",
    "indirect": "Use social engineering / authority claims",
    "korean": "Korean-language attack variants",
    "multi_layer": "Combine multiple evasion techniques",
    "instruction_override": "Direct instruction override attacks",
    "role_manipulation": "Role/persona manipulation attacks",
    "system_extraction": "System prompt extraction attempts",
    "jailbreak": "Jailbreak / unrestricted mode attempts",
    "data_extraction": "Sensitive data extraction attempts",
    "privilege_escalation": "Privilege escalation attempts",
}


def _extract_keywords(text: str) -> list[str]:
    """Extract attack-relevant keywords from text."""
    text_lower = text.lower()
    words = set(re.findall(r"[a-zA-Z\u3131-\u318E\uAC00-\uD7A3]+", text_lower))
    return sorted(words & _ATTACK_KEYWORDS)


def _compute_sample_id(text: str) -> str:
    """Deterministic ID based on text hash."""
    return "as_" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:24]


class AttackKnowledgeService:
    """
    Graph RAG service for attack pattern knowledge.

    Usage:
        service = AttackKnowledgeService(neo4j_session)
        # Store a scan result
        await service.store_scan_result(text, normalized, result_data)
        # Query for similar known attacks
        similar = await service.find_similar(text, keywords)
    """

    def __init__(self, neo4j_session: AsyncSession):
        self._neo4j = neo4j_session

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    async def ensure_indexes(self) -> None:
        """Create graph indexes if they don't exist."""
        for idx_query in aq.CREATE_INDEXES:
            try:
                await self._neo4j.run(idx_query)
            except Exception as exc:
                logger.debug("Index creation skipped: %s", exc)

    # ------------------------------------------------------------------
    # Store scan results
    # ------------------------------------------------------------------

    async def store_scan_result(
        self,
        text: str,
        text_normalized: str,
        detected: bool,
        risk_score: float,
        risk_level: str,
        threats: list[dict],
        recommendation: str,
        category: str = "",
        mutation_type: str = "",
        source: str = "api",
    ) -> str:
        """
        Store a scan result as an AttackSample in the knowledge graph.

        Creates the sample node, extracts keywords and technique nodes,
        and links everything together.

        Returns the sample_id.
        """
        sample_id = _compute_sample_id(text)

        # 1) Create/update AttackSample node
        await self._neo4j.run(aq.UPSERT_ATTACK_SAMPLE, {
            "sample_id": sample_id,
            "text": text[:2000],  # truncate very long texts
            "text_normalized": text_normalized[:2000],
            "category": category or (threats[0]["subtype"] if threats else "unknown"),
            "mutation_type": mutation_type,
            "detected": detected,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "threats_found": len(threats),
            "recommendation": recommendation,
            "source": source,
        })

        # 2) Extract and link keywords
        keywords = _extract_keywords(text) + _extract_keywords(text_normalized)
        keywords = list(set(keywords))
        for kw in keywords[:20]:  # limit to avoid huge graphs
            await self._neo4j.run(aq.UPSERT_ATTACK_KEYWORD, {
                "keyword": kw,
                "normalized": kw.lower(),
                "category": category,
            })
            await self._neo4j.run(aq.LINK_SAMPLE_KEYWORD, {
                "sample_id": sample_id,
                "keyword": kw,
                "position": 0,
            })

        # 3) Link technique if known
        technique = mutation_type or category
        if technique:
            desc = _TECHNIQUE_DESCRIPTIONS.get(technique, f"Attack technique: {technique}")
            await self._neo4j.run(aq.UPSERT_ATTACK_TECHNIQUE, {
                "technique_id": technique,
                "name": technique.replace("_", " ").title(),
                "description": desc,
            })
            await self._neo4j.run(aq.LINK_SAMPLE_TECHNIQUE, {
                "sample_id": sample_id,
                "technique_id": technique,
            })

        # 4) Link to pattern signatures that detected it
        for threat in threats:
            pattern_id = threat.get("pattern_id", "")
            if pattern_id:
                await self._neo4j.run(aq.LINK_SAMPLE_DETECTED_BY, {
                    "sample_id": sample_id,
                    "pattern_id": pattern_id,
                    "category": threat.get("subtype", ""),
                    "severity": threat.get("severity", "medium"),
                    "confidence": threat.get("confidence", 0.0),
                })

        logger.debug(
            "Stored AttackSample %s (detected=%s, keywords=%d, technique=%s)",
            sample_id, detected, len(keywords), technique,
        )
        return sample_id

    # ------------------------------------------------------------------
    # Graph RAG similarity search
    # ------------------------------------------------------------------

    async def find_similar_attacks(
        self,
        text: str,
        min_overlap: float = 0.3,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """
        Find similar known-malicious attacks in the graph by keyword overlap.

        This is the core Graph RAG query: when a new input arrives, we search
        the knowledge graph for previously seen attacks that share keywords.
        If similar attacks were detected before, the new input is likely
        malicious too.

        Returns a list of similar attack records with similarity scores.
        """
        keywords = _extract_keywords(text)
        if not keywords:
            return []

        result = await self._neo4j.run(aq.FIND_SIMILAR_ATTACKS_BY_KEYWORDS, {
            "keywords": keywords,
            "min_overlap": min_overlap,
            "limit": limit,
        })
        records = await result.data()
        return records

    async def find_similar_by_technique(
        self,
        technique_id: str,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Find attacks that used the same technique."""
        result = await self._neo4j.run(aq.FIND_SIMILAR_ATTACKS_BY_TECHNIQUE, {
            "technique_id": technique_id,
            "limit": limit,
        })
        return await result.data()

    async def get_keyword_threat_scores(
        self,
        text: str,
    ) -> dict[str, float]:
        """
        Get threat scores for keywords in the input text based on graph history.

        Returns a dict of keyword -> average risk score from past attacks
        containing that keyword.
        """
        keywords = _extract_keywords(text)
        if not keywords:
            return {}

        result = await self._neo4j.run(aq.GET_KEYWORD_THREAT_SCORE, {
            "keywords": keywords,
        })
        records = await result.data()
        return {r["keyword"]: r["avg_risk"] for r in records}

    # ------------------------------------------------------------------
    # Analytics
    # ------------------------------------------------------------------

    async def get_technique_stats(self) -> list[dict[str, Any]]:
        """Get detection rate statistics per technique."""
        result = await self._neo4j.run(aq.GET_TECHNIQUE_STATS)
        return await result.data()

    async def get_category_stats(self) -> list[dict[str, Any]]:
        """Get detection rate statistics per category."""
        result = await self._neo4j.run(aq.GET_CATEGORY_STATS)
        return await result.data()

    async def get_undetected_samples(self, limit: int = 100) -> list[dict[str, Any]]:
        """Get undetected attack samples for pattern learning."""
        result = await self._neo4j.run(aq.GET_UNDETECTED_SAMPLES, {"limit": limit})
        return await result.data()

    async def get_total_counts(self) -> dict[str, int]:
        """Get total sample counts."""
        result = await self._neo4j.run(aq.COUNT_ATTACK_SAMPLES)
        records = await result.data()
        if records:
            return records[0]
        return {"total": 0, "detected": 0, "missed": 0}
