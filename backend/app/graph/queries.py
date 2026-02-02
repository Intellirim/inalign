"""
Cypher query constants for the AgentShield Neo4j graph layer.

All queries use parameterised placeholders ($param) to prevent injection and
allow the Neo4j driver to cache execution plans.  Queries are organised by
the CRUD operation they support and the primary node/relationship they target.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Node creation
# ---------------------------------------------------------------------------

CREATE_AGENT: str = """
MERGE (a:Agent {agent_id: $agent_id})
ON CREATE SET
    a.name        = $name,
    a.description = $description,
    a.owner       = $owner,
    a.created_at  = datetime(),
    a.updated_at  = datetime(),
    a.metadata    = $metadata
ON MATCH SET
    a.name        = $name,
    a.description = $description,
    a.owner       = $owner,
    a.updated_at  = datetime(),
    a.metadata    = $metadata
RETURN a.agent_id AS agent_id
"""

CREATE_SESSION: str = """
MERGE (s:Session {session_id: $session_id})
ON CREATE SET
    s.agent_id    = $agent_id,
    s.user_id     = $user_id,
    s.status      = $status,
    s.risk_score  = $risk_score,
    s.started_at  = datetime($started_at),
    s.updated_at  = datetime(),
    s.metadata    = $metadata
ON MATCH SET
    s.status      = $status,
    s.risk_score  = $risk_score,
    s.updated_at  = datetime(),
    s.metadata    = $metadata
WITH s
MATCH (a:Agent {agent_id: $agent_id})
MERGE (a)-[:OWNS_SESSION]->(s)
RETURN s.session_id AS session_id
"""

CREATE_ACTION: str = """
CREATE (act:Action {
    action_id:    $action_id,
    session_id:   $session_id,
    action_type:  $action_type,
    input:        $input,
    output:       $output,
    risk_score:   $risk_score,
    latency_ms:   $latency_ms,
    timestamp:    datetime($timestamp),
    metadata:     $metadata
})
WITH act
MATCH (s:Session {session_id: $session_id})
MERGE (s)-[:CONTAINS]->(act)
RETURN act.action_id AS action_id
"""

# ---------------------------------------------------------------------------
# Relationship creation
# ---------------------------------------------------------------------------

LINK_SESSION_ACTION: str = """
MATCH (s:Session {session_id: $session_id})
MATCH (act:Action {action_id: $action_id})
MERGE (s)-[:CONTAINS]->(act)
RETURN s.session_id AS session_id, act.action_id AS action_id
"""

LINK_ACTION_SEQUENCE: str = """
MATCH (a1:Action {action_id: $from_action_id})
MATCH (a2:Action {action_id: $to_action_id})
MERGE (a1)-[r:FOLLOWED_BY]->(a2)
ON CREATE SET r.delay_ms = $delay_ms
ON MATCH  SET r.delay_ms = $delay_ms
RETURN a1.action_id AS from_id, a2.action_id AS to_id
"""

LINK_ACTION_THREAT: str = """
MATCH (act:Action {action_id: $action_id})
MATCH (t:Threat {threat_id: $threat_id})
MERGE (act)-[:TRIGGERED]->(t)
RETURN act.action_id AS action_id, t.threat_id AS threat_id
"""

# ---------------------------------------------------------------------------
# Threat creation (action-linked)
# ---------------------------------------------------------------------------

CREATE_THREAT: str = """
CREATE (t:Threat {
    threat_id:       $threat_id,
    threat_type:     $threat_type,
    severity:        $severity,
    confidence:      $confidence,
    description:     $description,
    detector:        $detector,
    detected_at:     datetime(),
    metadata:        $metadata
})
WITH t
MATCH (act:Action {action_id: $action_id})
MERGE (act)-[:TRIGGERED]->(t)
RETURN t.threat_id AS threat_id
"""

# ---------------------------------------------------------------------------
# Read queries
# ---------------------------------------------------------------------------

GET_SESSION_GRAPH: str = """
MATCH (s:Session {session_id: $session_id})
OPTIONAL MATCH (s)-[:CONTAINS]->(act:Action)
OPTIONAL MATCH (act)-[:TRIGGERED]->(t:Threat)
OPTIONAL MATCH (act)-[fb:FOLLOWED_BY]->(next:Action)
RETURN s                          AS session,
       collect(DISTINCT act)      AS actions,
       collect(DISTINCT t)        AS threats,
       collect(DISTINCT {
           from_action: act.action_id,
           to_action:   next.action_id,
           delay_ms:    fb.delay_ms
       })                         AS sequences
"""

GET_SESSION_ACTIONS: str = """
MATCH (s:Session {session_id: $session_id})-[:CONTAINS]->(act:Action)
RETURN act
ORDER BY act.timestamp ASC
"""

GET_SUSPICIOUS_SESSIONS: str = """
MATCH (s:Session)
WHERE s.risk_score >= $min_risk_score
  AND s.status IN ['active', 'flagged']
RETURN s
ORDER BY s.risk_score DESC, s.updated_at DESC
LIMIT $limit
"""

FIND_SIMILAR_SESSIONS: str = """
MATCH (s1:Session {session_id: $session_id})-[:CONTAINS]->(a1:Action)
WITH s1, collect(DISTINCT a1.action_type) AS types1
MATCH (s2:Session)-[:CONTAINS]->(a2:Action)
WHERE s2.session_id <> s1.session_id
WITH s1, s2, types1, collect(DISTINCT a2.action_type) AS types2
WITH s1, s2, types1, types2,
     [x IN types1 WHERE x IN types2] AS intersection
WITH s2,
     toFloat(size(intersection)) /
       CASE WHEN size(types1) + size(types2) - size(intersection) = 0
            THEN 1
            ELSE toFloat(size(types1) + size(types2) - size(intersection))
       END AS jaccard
WHERE jaccard >= $min_similarity
RETURN s2 AS session, jaccard AS similarity
ORDER BY jaccard DESC
LIMIT $limit
"""

# ---------------------------------------------------------------------------
# Update queries
# ---------------------------------------------------------------------------

UPDATE_SESSION_RISK: str = """
MATCH (s:Session {session_id: $session_id})
SET s.risk_score = $risk_score,
    s.updated_at = datetime()
RETURN s.session_id AS session_id, s.risk_score AS risk_score
"""

# ---------------------------------------------------------------------------
# Agent queries
# ---------------------------------------------------------------------------

GET_AGENT_SESSIONS: str = """
MATCH (a:Agent {agent_id: $agent_id})-[:OWNS_SESSION]->(s:Session)
RETURN s
ORDER BY s.started_at DESC
LIMIT $limit
"""

# ---------------------------------------------------------------------------
# Aggregation / metric queries
# ---------------------------------------------------------------------------

COUNT_SESSION_ACTIONS: str = """
MATCH (s:Session {session_id: $session_id})-[:CONTAINS]->(act:Action)
RETURN count(act) AS action_count
"""

GET_SESSION_THREATS: str = """
MATCH (s:Session {session_id: $session_id})-[:CONTAINS]->(act:Action)-[:TRIGGERED]->(t:Threat)
RETURN t, act.action_id AS source_action_id
ORDER BY t.detected_at ASC
"""

# ---------------------------------------------------------------------------
# Maintenance
# ---------------------------------------------------------------------------

CLEANUP_OLD_SESSIONS: str = """
MATCH (s:Session)
WHERE s.updated_at < datetime() - duration({days: $retention_days})
  AND s.status = 'closed'
OPTIONAL MATCH (s)-[:CONTAINS]->(act:Action)
OPTIONAL MATCH (act)-[:TRIGGERED]->(t:Threat)
DETACH DELETE t, act, s
RETURN count(DISTINCT s) AS deleted_sessions
"""
