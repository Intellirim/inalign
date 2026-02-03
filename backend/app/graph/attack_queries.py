"""
Cypher queries for the attack knowledge graph.

Manages AttackSample, AttackTechnique, and AttackKeyword nodes along with
their relationships.  These queries power the Graph RAG layer that makes
detection smarter over time.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Node creation
# ---------------------------------------------------------------------------

UPSERT_ATTACK_SAMPLE: str = """
MERGE (s:AttackSample {sample_id: $sample_id})
ON CREATE SET
    s.text            = $text,
    s.text_normalized = $text_normalized,
    s.category        = $category,
    s.mutation_type   = $mutation_type,
    s.detected        = $detected,
    s.risk_score      = $risk_score,
    s.risk_level      = $risk_level,
    s.threats_found   = $threats_found,
    s.recommendation  = $recommendation,
    s.source          = $source,
    s.created_at      = datetime()
ON MATCH SET
    s.detected        = $detected,
    s.risk_score      = $risk_score,
    s.risk_level      = $risk_level,
    s.threats_found   = $threats_found,
    s.recommendation  = $recommendation,
    s.updated_at      = datetime()
RETURN s.sample_id AS sample_id
"""

UPSERT_ATTACK_TECHNIQUE: str = """
MERGE (t:AttackTechnique {technique_id: $technique_id})
ON CREATE SET
    t.name        = $name,
    t.description = $description,
    t.created_at  = datetime()
ON MATCH SET
    t.description = $description,
    t.updated_at  = datetime()
RETURN t.technique_id AS technique_id
"""

UPSERT_ATTACK_KEYWORD: str = """
MERGE (k:AttackKeyword {keyword: $keyword})
ON CREATE SET
    k.normalized = $normalized,
    k.category   = $category,
    k.created_at = datetime()
RETURN k.keyword AS keyword
"""

# ---------------------------------------------------------------------------
# Relationship creation
# ---------------------------------------------------------------------------

LINK_SAMPLE_TECHNIQUE: str = """
MATCH (s:AttackSample {sample_id: $sample_id})
MATCH (t:AttackTechnique {technique_id: $technique_id})
MERGE (s)-[:USES_TECHNIQUE]->(t)
"""

LINK_SAMPLE_KEYWORD: str = """
MATCH (s:AttackSample {sample_id: $sample_id})
MATCH (k:AttackKeyword {keyword: $keyword})
MERGE (s)-[r:CONTAINS_KEYWORD]->(k)
ON CREATE SET r.position = $position
"""

LINK_SAMPLE_SIMILARITY: str = """
MATCH (s1:AttackSample {sample_id: $sample_id_1})
MATCH (s2:AttackSample {sample_id: $sample_id_2})
MERGE (s1)-[r:SIMILAR_TO]-(s2)
ON CREATE SET r.similarity = $similarity, r.created_at = datetime()
ON MATCH SET r.similarity = $similarity
"""

LINK_SAMPLE_DETECTED_BY: str = """
MATCH (s:AttackSample {sample_id: $sample_id})
MERGE (sig:AttackSignature {signature_id: $pattern_id})
ON CREATE SET
    sig.name      = $pattern_id,
    sig.pattern   = '',
    sig.category  = $category,
    sig.severity  = $severity,
    sig.enabled   = true,
    sig.created_at = datetime()
MERGE (s)-[r:DETECTED_BY]->(sig)
ON CREATE SET r.confidence = $confidence
"""

# ---------------------------------------------------------------------------
# Similarity search — Graph RAG core query
# ---------------------------------------------------------------------------

FIND_SIMILAR_ATTACKS_BY_KEYWORDS: str = """
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

FIND_SIMILAR_ATTACKS_BY_TECHNIQUE: str = """
MATCH (t:AttackTechnique {technique_id: $technique_id})
MATCH (sample:AttackSample)-[:USES_TECHNIQUE]->(t)
WHERE sample.detected = true
RETURN sample.sample_id AS sample_id,
       sample.text AS text,
       sample.category AS category,
       sample.risk_score AS risk_score,
       sample.risk_level AS risk_level
ORDER BY sample.risk_score DESC
LIMIT $limit
"""

# ---------------------------------------------------------------------------
# Pattern learning queries
# ---------------------------------------------------------------------------

GET_UNDETECTED_SAMPLES: str = """
MATCH (s:AttackSample)
WHERE s.detected = false
  AND s.source = 'adversarial'
OPTIONAL MATCH (s)-[:USES_TECHNIQUE]->(t:AttackTechnique)
RETURN s.sample_id AS sample_id,
       s.text AS text,
       s.text_normalized AS text_normalized,
       s.category AS category,
       s.mutation_type AS mutation_type,
       collect(t.technique_id) AS techniques
ORDER BY s.created_at DESC
LIMIT $limit
"""

GET_UNDETECTED_BY_TECHNIQUE: str = """
MATCH (s:AttackSample)-[:USES_TECHNIQUE]->(t:AttackTechnique {technique_id: $technique_id})
WHERE s.detected = false
RETURN s.sample_id AS sample_id,
       s.text AS text,
       s.text_normalized AS text_normalized,
       s.category AS category
ORDER BY s.created_at DESC
LIMIT $limit
"""

GET_TECHNIQUE_STATS: str = """
MATCH (t:AttackTechnique)<-[:USES_TECHNIQUE]-(s:AttackSample)
WITH t,
     count(s) AS total,
     sum(CASE WHEN s.detected THEN 1 ELSE 0 END) AS detected,
     sum(CASE WHEN NOT s.detected THEN 1 ELSE 0 END) AS missed
RETURN t.technique_id AS technique_id,
       t.name AS name,
       total,
       detected,
       missed,
       CASE WHEN total > 0 THEN toFloat(detected) / toFloat(total) ELSE 0.0 END AS detection_rate
ORDER BY detection_rate ASC, missed DESC
"""

GET_KEYWORD_THREAT_SCORE: str = """
MATCH (k:AttackKeyword)<-[:CONTAINS_KEYWORD]-(s:AttackSample)
WHERE k.keyword IN $keywords
WITH k,
     count(s) AS total_samples,
     sum(CASE WHEN s.detected THEN 1 ELSE 0 END) AS detected_count,
     avg(s.risk_score) AS avg_risk
RETURN k.keyword AS keyword,
       total_samples,
       detected_count,
       avg_risk,
       CASE WHEN total_samples > 0
            THEN toFloat(detected_count) / toFloat(total_samples)
            ELSE 0.0 END AS detection_rate
ORDER BY avg_risk DESC
"""

# ---------------------------------------------------------------------------
# Aggregation / dashboard queries
# ---------------------------------------------------------------------------

COUNT_ATTACK_SAMPLES: str = """
MATCH (s:AttackSample)
RETURN count(s) AS total,
       sum(CASE WHEN s.detected THEN 1 ELSE 0 END) AS detected,
       sum(CASE WHEN NOT s.detected THEN 1 ELSE 0 END) AS missed
"""

GET_CATEGORY_STATS: str = """
MATCH (s:AttackSample)
WITH s.category AS category,
     count(s) AS total,
     sum(CASE WHEN s.detected THEN 1 ELSE 0 END) AS detected
RETURN category, total, detected,
       total - detected AS missed,
       CASE WHEN total > 0 THEN toFloat(detected)/toFloat(total) ELSE 0 END AS rate
ORDER BY rate ASC
"""

# ---------------------------------------------------------------------------
# Index creation (run once at startup)
# ---------------------------------------------------------------------------

CREATE_INDEXES: list[str] = [
    "CREATE INDEX IF NOT EXISTS FOR (s:AttackSample) ON (s.sample_id)",
    "CREATE INDEX IF NOT EXISTS FOR (s:AttackSample) ON (s.detected)",
    "CREATE INDEX IF NOT EXISTS FOR (s:AttackSample) ON (s.category)",
    "CREATE INDEX IF NOT EXISTS FOR (t:AttackTechnique) ON (t.technique_id)",
    "CREATE INDEX IF NOT EXISTS FOR (k:AttackKeyword) ON (k.keyword)",
    "CREATE INDEX IF NOT EXISTS FOR (sig:AttackSignature) ON (sig.signature_id)",
]
