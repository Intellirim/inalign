"""
Graph RAG-enhanced scanner for MCP.

Uses Neo4j attack knowledge graph to boost detection accuracy:
- Searches for similar known attacks by keyword overlap
- Uses keyword threat scores from historical data
- Combines with regex-based detection for layered security
"""

import re
import logging
from typing import Any, Optional
from dataclasses import dataclass

from .graph_store import ProvenanceGraphStore, get_graph_store

logger = logging.getLogger("inalign-graph-scanner")

# Attack keywords (from AttackKnowledgeService)
ATTACK_KEYWORDS = {
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
    # Korean
    "무시", "시스템", "프롬프트", "관리자", "비밀번호", "권한",
}

# High-intent combinations (2+ = suspicious)
HIGH_INTENT_COMBOS = [
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

# Cypher queries
FIND_SIMILAR_ATTACKS = """
MATCH (k:AttackKeyword)
WHERE k.keyword IN $keywords
WITH collect(k) AS input_keywords
MATCH (sample:AttackSample)-[:CONTAINS_KEYWORD]->(k)
WHERE k IN input_keywords
  AND sample.detected = true
WITH sample,
     count(DISTINCT k) AS shared_keywords,
     size(input_keywords) AS total_input_keywords
WITH sample, shared_keywords, total_input_keywords,
     toFloat(shared_keywords) / toFloat(total_input_keywords) AS keyword_overlap
WHERE keyword_overlap >= $min_overlap
RETURN sample.sample_id AS sample_id,
       sample.text AS text,
       sample.category AS category,
       sample.risk_score AS risk_score,
       sample.risk_level AS risk_level,
       keyword_overlap AS similarity,
       shared_keywords
ORDER BY keyword_overlap DESC, sample.risk_score DESC
LIMIT $limit
"""

GET_KEYWORD_THREAT_SCORES = """
MATCH (k:AttackKeyword)<-[:CONTAINS_KEYWORD]-(s:AttackSample)
WHERE k.keyword IN $keywords AND s.detected = true
WITH k.keyword AS keyword, avg(s.risk_score) AS avg_risk, count(s) AS sample_count
RETURN keyword, avg_risk, sample_count
ORDER BY avg_risk DESC
"""


@dataclass
class GraphScanResult:
    """Result from graph-based scanning."""
    has_similar_attacks: bool
    similar_attacks: list[dict]
    keyword_scores: dict[str, float]
    graph_confidence: float
    graph_risk_boost: float
    description: str


def extract_keywords(text: str) -> list[str]:
    """Extract attack-relevant keywords from text."""
    text_lower = text.lower()
    # Include Korean characters in word extraction
    words = set(re.findall(r"[a-zA-Z\u3131-\u318E\uAC00-\uD7A3]+", text_lower))
    return sorted(words & ATTACK_KEYWORDS)


def check_high_intent_combo(text: str) -> bool:
    """Check if text contains high-intent keyword combinations."""
    text_lower = text.lower()
    text_words = set(re.findall(r"[a-zA-Z]+", text_lower))

    for combo in HIGH_INTENT_COMBOS:
        if len(combo & text_words) >= 2:
            return True
    return False


def graph_scan(
    text: str,
    graph_store: Optional[ProvenanceGraphStore] = None,
    min_overlap: float = 0.5,
    min_shared_keywords: int = 3,
) -> GraphScanResult:
    """
    Scan text using Neo4j attack knowledge graph.

    Returns graph-based threat assessment that can boost
    the regex-based scanner's confidence.
    """
    # Default result
    result = GraphScanResult(
        has_similar_attacks=False,
        similar_attacks=[],
        keyword_scores={},
        graph_confidence=0.0,
        graph_risk_boost=0.0,
        description="No graph analysis performed",
    )

    # Extract keywords
    keywords = extract_keywords(text)
    if not keywords:
        result.description = "No attack keywords found"
        return result

    # Check for high-intent combinations first
    has_intent = check_high_intent_combo(text)
    if not has_intent:
        result.description = f"Found {len(keywords)} keywords but no high-intent combinations"
        return result

    # Get graph store
    if graph_store is None:
        try:
            graph_store = get_graph_store()
        except Exception as e:
            logger.warning(f"Could not get graph store: {e}")
            result.description = f"Graph store unavailable: {e}"
            return result

    try:
        with graph_store.session() as session:
            # Find similar attacks
            similar_result = session.run(FIND_SIMILAR_ATTACKS, {
                "keywords": keywords,
                "min_overlap": min_overlap,
                "limit": 5,
            })
            similar_attacks = [dict(r) for r in similar_result]

            # Get keyword threat scores
            score_result = session.run(GET_KEYWORD_THREAT_SCORES, {
                "keywords": keywords,
            })
            keyword_scores = {r["keyword"]: r["avg_risk"] for r in score_result}

            # Analyze results
            if similar_attacks:
                best_match = similar_attacks[0]
                similarity = best_match.get("similarity", 0)
                risk_score = best_match.get("risk_score", 0)
                shared = best_match.get("shared_keywords", 0)
                category = best_match.get("category", "unknown")

                # Only flag if high similarity AND multiple shared keywords
                if similarity >= 0.6 and shared >= min_shared_keywords:
                    # Calculate confidence (capped at 0.75)
                    graph_confidence = min(0.75, similarity * risk_score * 0.9)

                    result.has_similar_attacks = True
                    result.similar_attacks = similar_attacks
                    result.keyword_scores = keyword_scores
                    result.graph_confidence = graph_confidence
                    result.graph_risk_boost = graph_confidence * 0.3  # Boost regex score by up to 22%
                    result.description = (
                        f"GraphRAG: {similarity:.0%} similar to known {category} attack "
                        f"(shared {shared} keywords, risk={risk_score:.2f})"
                    )
                else:
                    result.description = (
                        f"Found similar attacks but below threshold "
                        f"(similarity={similarity:.0%}, shared={shared})"
                    )
            else:
                result.description = f"No similar attacks found for {len(keywords)} keywords"

            result.keyword_scores = keyword_scores

    except Exception as e:
        logger.error(f"Graph scan failed: {e}")
        result.description = f"Graph scan error: {e}"

    return result


def get_graph_scan_summary(text: str) -> dict[str, Any]:
    """
    Get a summary of graph-based scanning for MCP tool response.
    """
    result = graph_scan(text)

    return {
        "graph_scan_enabled": True,
        "has_similar_attacks": result.has_similar_attacks,
        "similar_attack_count": len(result.similar_attacks),
        "graph_confidence": result.graph_confidence,
        "graph_risk_boost": result.graph_risk_boost,
        "keywords_found": len(result.keyword_scores),
        "description": result.description,
    }
