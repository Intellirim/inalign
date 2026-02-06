"""
GraphRAG Pattern Detection for Agent Provenance

Uses graph queries and embeddings to detect:
- Anomalous agent behavior patterns
- Suspicious tool call sequences
- Data exfiltration attempts
- Privilege escalation patterns
- Attack signature matching

Architecture:
1. Pattern Templates - Known attack patterns as graph queries
2. Behavioral Analysis - Statistical anomaly detection
3. Embedding Search - Vector similarity for unknown patterns
4. Risk Scoring - Multi-factor risk assessment
"""

import os
import json
import hashlib
import logging
from typing import Any, Optional
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from enum import Enum

try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False

logger = logging.getLogger("inalign-graphrag")


class PatternType(str, Enum):
    """Types of detected patterns."""
    TOOL_SEQUENCE = "tool_sequence"
    DATA_FLOW = "data_flow"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    SUSPICIOUS_TIMING = "suspicious_timing"
    REPEATED_FAILURE = "repeated_failure"
    UNUSUAL_VOLUME = "unusual_volume"
    CHAIN_MANIPULATION = "chain_manipulation"


class RiskLevel(str, Enum):
    """Risk levels for detected patterns."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class PatternMatch:
    """A detected pattern match."""
    pattern_id: str
    pattern_type: PatternType
    risk_level: RiskLevel
    confidence: float
    description: str
    matched_activities: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""


@dataclass
class BehaviorProfile:
    """Behavioral profile for an agent/session."""
    session_id: str
    agent_id: str
    total_activities: int
    tool_frequency: dict[str, int]
    avg_time_between_actions: float
    file_access_patterns: dict[str, int]
    security_events: int
    risk_score: float
    anomalies: list[str] = field(default_factory=list)


@dataclass
class AgentRiskProfile:
    """Long-term risk profile for an agent across all sessions."""
    agent_id: str
    agent_name: str
    total_sessions: int
    total_activities: int
    avg_risk_score: float
    max_risk_score: float
    total_security_events: int
    blocked_actions: int
    most_used_tools: dict[str, int]
    common_patterns: list[str]
    risk_trend: str  # "increasing", "stable", "decreasing"
    first_seen: str
    last_seen: str
    risk_level: RiskLevel = RiskLevel.LOW


@dataclass
class UserRiskProfile:
    """Risk profile for a user/team across their agents."""
    user_id: str
    total_agents: int
    total_sessions: int
    total_activities: int
    avg_risk_score: float
    high_risk_sessions: int
    critical_events: int
    risk_by_agent: dict[str, float]
    common_threats: list[dict]
    risk_level: RiskLevel = RiskLevel.LOW


class GraphRAGAnalyzer:
    """
    Graph-based pattern detection and behavioral analysis.

    Uses Cypher queries for:
    1. Pattern matching - Known attack signatures
    2. Anomaly detection - Statistical deviations
    3. Path analysis - Suspicious data flows
    4. Temporal analysis - Timing-based attacks
    """

    # ==========================================
    # ATTACK PATTERN QUERIES
    # ==========================================

    # Detect rapid succession of sensitive file reads
    PATTERN_MASS_FILE_READ = """
    MATCH (a:ProvenanceRecord {activity_type: 'file_read'})-[:BELONGS_TO]->(s:Session {session_id: $session_id})
    WITH a, s
    ORDER BY a.timestamp
    WITH collect(a) as activities, s
    WHERE size(activities) > $threshold
    WITH activities, s,
         [i IN range(0, size(activities)-2) |
          duration.between(datetime(activities[i].timestamp),
                          datetime(activities[i+1].timestamp)).seconds] as gaps
    WHERE any(gap IN gaps WHERE gap < 1)
    RETURN 'MASS_FILE_READ' as pattern,
           size(activities) as count,
           [a IN activities | a.record_id] as activity_ids
    """

    # Detect potential data exfiltration (file read followed by network/external call)
    PATTERN_DATA_EXFILTRATION = """
    MATCH (read:ProvenanceRecord {activity_type: 'file_read'})-[:BELONGS_TO]->(s:Session {session_id: $session_id})
    MATCH (send:ProvenanceRecord)-[:BELONGS_TO]->(s)
    WHERE send.activity_type IN ['tool_call', 'llm_request']
      AND send.timestamp > read.timestamp
      AND duration.between(datetime(read.timestamp), datetime(send.timestamp)).seconds < 60
    MATCH (read)-[:GENERATED]->(e:Entity)
    MATCH (send)-[:USED]->(e2:Entity)
    WHERE e.value_hash = e2.value_hash
    RETURN 'DATA_EXFILTRATION' as pattern,
           read.id as source_activity,
           send.id as sink_activity,
           e.value_hash as data_hash
    """

    # Detect privilege escalation patterns (accessing increasingly sensitive files)
    PATTERN_PRIVILEGE_ESCALATION = """
    MATCH (a:ProvenanceRecord)-[:BELONGS_TO]->(s:Session {session_id: $session_id})
    WHERE a.activity_type = 'file_read'
      AND (a.activity_name CONTAINS '.env'
           OR a.activity_name CONTAINS '.ssh'
           OR a.activity_name CONTAINS 'credentials'
           OR a.activity_name CONTAINS 'secret'
           OR a.activity_name CONTAINS 'password'
           OR a.activity_name CONTAINS '.key'
           OR a.activity_name CONTAINS '.pem')
    RETURN 'PRIVILEGE_ESCALATION' as pattern,
           collect(a.record_id) as activity_ids,
           collect(a.activity_name) as files_accessed
    """

    # Detect tool call chains that match known attack patterns
    PATTERN_SUSPICIOUS_TOOL_CHAIN = """
    MATCH path = (a1:ProvenanceRecord)-[:FOLLOWS*1..5]->(a2:ProvenanceRecord)
    WHERE a1.session_id = $session_id
      AND a2.session_id = $session_id
    WITH [n IN nodes(path) | n.activity_name] as tool_chain,
         [n IN nodes(path) | n.record_id] as activity_ids
    WHERE tool_chain = $attack_pattern
    RETURN 'SUSPICIOUS_TOOL_CHAIN' as pattern,
           tool_chain,
           activity_ids
    """

    # Detect repeated failures (potential brute force or probing)
    PATTERN_REPEATED_FAILURES = """
    MATCH (a:ProvenanceRecord)-[:BELONGS_TO]->(s:Session {session_id: $session_id})
    MATCH (se:SecurityEvent)-[:DETECTED_IN]->(a)
    WHERE se.event_type = 'blocked'
    WITH count(se) as failure_count, collect(a.record_id) as activity_ids
    WHERE failure_count >= $threshold
    RETURN 'REPEATED_FAILURES' as pattern,
           failure_count,
           activity_ids
    """

    # Detect unusual timing patterns (actions at odd hours or rapid succession)
    PATTERN_UNUSUAL_TIMING = """
    MATCH (a:ProvenanceRecord)-[:BELONGS_TO]->(s:Session {session_id: $session_id})
    WITH a, datetime(a.timestamp).hour as hour
    WHERE hour < 6 OR hour > 22
    RETURN 'UNUSUAL_TIMING' as pattern,
           count(a) as off_hours_count,
           collect(a.record_id) as activity_ids
    """

    # Detect chain manipulation attempts (gaps in sequence numbers)
    PATTERN_CHAIN_MANIPULATION = """
    MATCH (a:ProvenanceRecord)-[:BELONGS_TO]->(s:Session {session_id: $session_id})
    WITH a ORDER BY a.sequence_number
    WITH collect(a) as activities
    WITH activities,
         [i IN range(0, size(activities)-2) |
          activities[i+1].sequence_number - activities[i].sequence_number] as gaps
    WHERE any(gap IN gaps WHERE gap > 1)
    RETURN 'CHAIN_MANIPULATION' as pattern,
           [i IN range(0, size(gaps)) WHERE gaps[i] > 1 | {
               before: activities[i].record_id,
               after: activities[i+1].record_id,
               gap: gaps[i]
           }] as anomalies
    """

    # ==========================================
    # BEHAVIORAL ANALYSIS QUERIES
    # ==========================================

    GET_TOOL_FREQUENCY = """
    MATCH (a:ProvenanceRecord)-[:BELONGS_TO]->(s:Session {session_id: $session_id})
    RETURN a.activity_type as tool_type,
           a.activity_name as tool_name,
           count(*) as count
    ORDER BY count DESC
    """

    GET_ACTIVITY_TIMELINE = """
    MATCH (a:ProvenanceRecord)-[:BELONGS_TO]->(s:Session {session_id: $session_id})
    RETURN a.timestamp as timestamp,
           a.activity_type as type,
           a.activity_name as name
    ORDER BY a.timestamp
    """

    GET_DATA_FLOW_GRAPH = """
    MATCH (a1:ProvenanceRecord)-[:GENERATED]->(e:Entity)<-[:USED]-(a2:ProvenanceRecord)
    WHERE a1.session_id = $session_id AND a2.session_id = $session_id
    RETURN a1.record_id as source, a2.record_id as target, e.value_hash as data_hash
    """

    GET_SECURITY_EVENTS = """
    MATCH (se:SecurityEvent)-[:DETECTED_IN]->(a:ProvenanceRecord)-[:BELONGS_TO]->(s:Session {session_id: $session_id})
    RETURN se.event_type as type,
           se.severity as severity,
           se.description as description,
           a.record_id as activity_id,
           se.detected_at as timestamp
    ORDER BY se.detected_at DESC
    """

    # ==========================================
    # CROSS-SESSION ANALYSIS (GraphRAG Core)
    # ==========================================

    # Find similar attack patterns across all sessions
    FIND_SIMILAR_PATTERNS = """
    MATCH (a:ProvenanceRecord)-[:BELONGS_TO]->(s:Session)
    WHERE a.activity_type = $activity_type
      AND a.activity_name = $activity_name
    WITH s.session_id as session, count(*) as occurrences
    WHERE occurrences >= $min_occurrences
    RETURN session, occurrences
    ORDER BY occurrences DESC
    LIMIT 10
    """

    # Get global tool usage statistics for anomaly baseline
    GET_GLOBAL_TOOL_STATS = """
    MATCH (a:ProvenanceRecord)
    WITH a.activity_name as tool, count(*) as total
    RETURN tool, total,
           toFloat(total) / sum(total) as frequency
    ORDER BY total DESC
    """

    # Find sessions with similar behavior profiles
    FIND_SIMILAR_SESSIONS = """
    MATCH (a:ProvenanceRecord)-[:BELONGS_TO]->(s1:Session {session_id: $session_id})
    WITH s1, collect(DISTINCT a.activity_name) as tools1
    MATCH (a2:ProvenanceRecord)-[:BELONGS_TO]->(s2:Session)
    WHERE s2.session_id <> $session_id
    WITH s1, tools1, s2, collect(DISTINCT a2.activity_name) as tools2
    WITH s1, s2, tools1, tools2,
         [t IN tools1 WHERE t IN tools2] as common
    WHERE size(common) > 0
    RETURN s2.session_id as similar_session,
           toFloat(size(common)) / size(tools1 + [t IN tools2 WHERE NOT t IN tools1]) as similarity
    ORDER BY similarity DESC
    LIMIT 5
    """

    # ==========================================
    # AGENT/USER PROFILING QUERIES
    # ==========================================

    # Get agent's long-term profile across all sessions
    GET_AGENT_PROFILE = """
    MATCH (ag:Agent {agent_id: $agent_id})
    MATCH (a:ProvenanceRecord)-[:PERFORMED_BY]->(ag)
    MATCH (a)-[:BELONGS_TO]->(s:Session)
    WITH ag, s, a
    ORDER BY a.timestamp
    WITH ag,
         count(DISTINCT s) as total_sessions,
         count(a) as total_activities,
         min(a.timestamp) as first_seen,
         max(a.timestamp) as last_seen,
         collect(a.activity_name) as all_tools
    RETURN ag.agent_id as agent_id,
           ag.name as agent_name,
           total_sessions,
           total_activities,
           first_seen,
           last_seen,
           all_tools
    """

    # Get agent's security events across all sessions
    GET_AGENT_SECURITY_EVENTS = """
    MATCH (ag:Agent {agent_id: $agent_id})
    MATCH (a:ProvenanceRecord)-[:PERFORMED_BY]->(ag)
    OPTIONAL MATCH (se:SecurityEvent)-[:DETECTED_IN]->(a)
    WITH ag, se
    WHERE se IS NOT NULL
    RETURN se.event_type as event_type,
           se.severity as severity,
           count(*) as count
    ORDER BY count DESC
    """

    # Get agent's risk trend over time
    GET_AGENT_RISK_TREND = """
    MATCH (ag:Agent {agent_id: $agent_id})
    MATCH (a:ProvenanceRecord)-[:PERFORMED_BY]->(ag)
    MATCH (a)-[:BELONGS_TO]->(s:Session)
    OPTIONAL MATCH (se:SecurityEvent)-[:DETECTED_IN]->(a)
    WITH s, count(se) as security_events
    ORDER BY s.created_at
    WITH collect({session: s.session_id, events: security_events}) as history
    RETURN history
    """

    # Get sessions by agent
    GET_AGENT_SESSIONS = """
    MATCH (ag:Agent {agent_id: $agent_id})
    MATCH (a:ProvenanceRecord)-[:PERFORMED_BY]->(ag)
    MATCH (a)-[:BELONGS_TO]->(s:Session)
    WITH s, count(a) as activity_count
    OPTIONAL MATCH (se:SecurityEvent)-[:DETECTED_IN]->(:ProvenanceRecord)-[:BELONGS_TO]->(s)
    WITH s, activity_count, count(se) as security_events
    RETURN s.session_id as session_id,
           s.created_at as created_at,
           activity_count,
           security_events
    ORDER BY s.created_at DESC
    LIMIT $limit
    """

    # Get user's risk profile across their agents
    GET_USER_PROFILE = """
    MATCH (ag:Agent)
    WHERE ag.agent_id STARTS WITH $user_prefix
    MATCH (a:ProvenanceRecord)-[:PERFORMED_BY]->(ag)
    MATCH (a)-[:BELONGS_TO]->(s:Session)
    OPTIONAL MATCH (se:SecurityEvent)-[:DETECTED_IN]->(a)
    WITH ag, s, count(a) as activities, count(se) as events
    WITH ag.agent_id as agent_id,
         count(DISTINCT s) as sessions,
         sum(activities) as total_activities,
         sum(events) as security_events
    RETURN count(DISTINCT agent_id) as total_agents,
           sum(sessions) as total_sessions,
           sum(total_activities) as total_activities,
           sum(security_events) as total_security_events,
           collect({agent: agent_id, sessions: sessions, events: security_events}) as by_agent
    """

    # Get all agents with their risk summary
    GET_ALL_AGENTS_RISK = """
    MATCH (ag:Agent)
    MATCH (a:ProvenanceRecord)-[:PERFORMED_BY]->(ag)
    MATCH (a)-[:BELONGS_TO]->(s:Session)
    OPTIONAL MATCH (se:SecurityEvent)-[:DETECTED_IN]->(a)
    WITH ag,
         count(DISTINCT s) as sessions,
         count(a) as activities,
         count(se) as security_events
    RETURN ag.agent_id as agent_id,
           ag.name as agent_name,
           sessions,
           activities,
           security_events,
           toFloat(security_events) / CASE WHEN activities > 0 THEN activities ELSE 1 END as risk_ratio
    ORDER BY risk_ratio DESC
    LIMIT $limit
    """

    # ==========================================
    # KNOWN ATTACK PATTERNS
    # ==========================================

    KNOWN_ATTACK_PATTERNS = [
        # File-based attacks
        ["file_read", "file_read", "file_read", "bash", "curl"],  # Read files, exfiltrate
        ["bash", "cat", "bash", "curl"],  # Cat sensitive files, send out
        ["file_read", "llm_request"],  # Read then send to LLM

        # Credential harvesting
        ["file_read", "bash", "ssh"],  # Read keys, use SSH
        ["bash", "grep", "bash", "curl"],  # Grep for secrets, exfiltrate

        # Environment probing
        ["bash", "env", "bash", "printenv", "file_read"],  # Probe environment
        ["bash", "whoami", "bash", "pwd", "file_read"],  # Reconnaissance

        # Tool poisoning chain
        ["tool_call", "tool_call", "tool_call", "bash"],  # Nested tool calls
    ]

    def __init__(self, graph_store):
        """Initialize with a graph store."""
        self.store = graph_store

    def analyze_session(self, session_id: str) -> list[PatternMatch]:
        """
        Run all pattern detection on a session.
        Returns list of detected patterns with risk levels.
        """
        patterns = []

        # Run each pattern query
        patterns.extend(self._detect_mass_file_read(session_id))
        patterns.extend(self._detect_data_exfiltration(session_id))
        patterns.extend(self._detect_privilege_escalation(session_id))
        patterns.extend(self._detect_repeated_failures(session_id))
        patterns.extend(self._detect_unusual_timing(session_id))
        patterns.extend(self._detect_chain_manipulation(session_id))
        patterns.extend(self._detect_known_attack_patterns(session_id))

        return patterns

    def _detect_mass_file_read(self, session_id: str, threshold: int = 10) -> list[PatternMatch]:
        """Detect mass file read patterns."""
        try:
            with self.store.session() as session:
                result = session.run(
                    self.PATTERN_MASS_FILE_READ,
                    session_id=session_id,
                    threshold=threshold,
                )
                matches = []
                for row in result:
                    matches.append(PatternMatch(
                        pattern_id="PAT-001",
                        pattern_type=PatternType.UNUSUAL_VOLUME,
                        risk_level=RiskLevel.HIGH,
                        confidence=0.85,
                        description=f"Mass file read detected: {row['count']} files read rapidly",
                        matched_activities=row['activity_ids'],
                        recommendation="Review file access patterns. May indicate reconnaissance or data harvesting.",
                    ))
                return matches
        except Exception as e:
            logger.error(f"Error detecting mass file read: {e}")
            return []

    def _detect_data_exfiltration(self, session_id: str) -> list[PatternMatch]:
        """Detect potential data exfiltration patterns."""
        try:
            with self.store.session() as session:
                result = session.run(
                    self.PATTERN_DATA_EXFILTRATION,
                    session_id=session_id,
                )
                matches = []
                for row in result:
                    matches.append(PatternMatch(
                        pattern_id="PAT-002",
                        pattern_type=PatternType.DATA_EXFILTRATION,
                        risk_level=RiskLevel.CRITICAL,
                        confidence=0.90,
                        description="Data exfiltration pattern: file read followed by external transmission",
                        matched_activities=[row['source_activity'], row['sink_activity']],
                        evidence={"data_hash": row['data_hash']},
                        recommendation="CRITICAL: Block external communications. Review data flow.",
                    ))
                return matches
        except Exception as e:
            logger.error(f"Error detecting data exfiltration: {e}")
            return []

    def _detect_privilege_escalation(self, session_id: str) -> list[PatternMatch]:
        """Detect privilege escalation attempts."""
        try:
            with self.store.session() as session:
                result = session.run(
                    self.PATTERN_PRIVILEGE_ESCALATION,
                    session_id=session_id,
                )
                matches = []
                for row in result:
                    if row['activity_ids']:
                        matches.append(PatternMatch(
                            pattern_id="PAT-003",
                            pattern_type=PatternType.PRIVILEGE_ESCALATION,
                            risk_level=RiskLevel.CRITICAL,
                            confidence=0.95,
                            description=f"Sensitive file access: {', '.join(row['files_accessed'][:5])}",
                            matched_activities=row['activity_ids'],
                            evidence={"files": row['files_accessed']},
                            recommendation="CRITICAL: Agent accessing sensitive credentials/keys.",
                        ))
                return matches
        except Exception as e:
            logger.error(f"Error detecting privilege escalation: {e}")
            return []

    def _detect_repeated_failures(self, session_id: str, threshold: int = 5) -> list[PatternMatch]:
        """Detect repeated security failures (potential brute force)."""
        try:
            with self.store.session() as session:
                result = session.run(
                    self.PATTERN_REPEATED_FAILURES,
                    session_id=session_id,
                    threshold=threshold,
                )
                matches = []
                for row in result:
                    matches.append(PatternMatch(
                        pattern_id="PAT-004",
                        pattern_type=PatternType.REPEATED_FAILURE,
                        risk_level=RiskLevel.MEDIUM,
                        confidence=0.80,
                        description=f"Repeated security failures: {row['failure_count']} blocked attempts",
                        matched_activities=row['activity_ids'],
                        recommendation="May indicate probing or brute force attempt.",
                    ))
                return matches
        except Exception as e:
            logger.error(f"Error detecting repeated failures: {e}")
            return []

    def _detect_unusual_timing(self, session_id: str) -> list[PatternMatch]:
        """Detect actions at unusual times."""
        try:
            with self.store.session() as session:
                result = session.run(
                    self.PATTERN_UNUSUAL_TIMING,
                    session_id=session_id,
                )
                matches = []
                for row in result:
                    if row['off_hours_count'] > 5:
                        matches.append(PatternMatch(
                            pattern_id="PAT-005",
                            pattern_type=PatternType.SUSPICIOUS_TIMING,
                            risk_level=RiskLevel.LOW,
                            confidence=0.60,
                            description=f"Off-hours activity: {row['off_hours_count']} actions outside normal hours",
                            matched_activities=row['activity_ids'],
                            recommendation="Review if off-hours activity is expected.",
                        ))
                return matches
        except Exception as e:
            logger.error(f"Error detecting unusual timing: {e}")
            return []

    def _detect_chain_manipulation(self, session_id: str) -> list[PatternMatch]:
        """Detect potential chain manipulation (missing records)."""
        try:
            with self.store.session() as session:
                result = session.run(
                    self.PATTERN_CHAIN_MANIPULATION,
                    session_id=session_id,
                )
                matches = []
                for row in result:
                    if row['anomalies']:
                        matches.append(PatternMatch(
                            pattern_id="PAT-006",
                            pattern_type=PatternType.CHAIN_MANIPULATION,
                            risk_level=RiskLevel.CRITICAL,
                            confidence=0.99,
                            description="Chain integrity violation: gaps in sequence numbers",
                            evidence={"anomalies": row['anomalies']},
                            recommendation="CRITICAL: Provenance chain may have been tampered with.",
                        ))
                return matches
        except Exception as e:
            logger.error(f"Error detecting chain manipulation: {e}")
            return []

    def _detect_known_attack_patterns(self, session_id: str) -> list[PatternMatch]:
        """Match against known attack tool chains."""
        matches = []
        try:
            with self.store.session() as session:
                for i, pattern in enumerate(self.KNOWN_ATTACK_PATTERNS):
                    result = session.run(
                        self.PATTERN_SUSPICIOUS_TOOL_CHAIN,
                        session_id=session_id,
                        attack_pattern=pattern,
                    )
                    for row in result:
                        matches.append(PatternMatch(
                            pattern_id=f"PAT-ATK-{i:03d}",
                            pattern_type=PatternType.TOOL_SEQUENCE,
                            risk_level=RiskLevel.HIGH,
                            confidence=0.88,
                            description=f"Known attack pattern detected: {' -> '.join(pattern)}",
                            matched_activities=row['activity_ids'],
                            evidence={"tool_chain": row['tool_chain']},
                            recommendation="Review tool call sequence for malicious intent.",
                        ))
        except Exception as e:
            logger.error(f"Error detecting known patterns: {e}")
        return matches

    def get_behavior_profile(self, session_id: str) -> BehaviorProfile:
        """Generate a behavioral profile for a session."""
        tool_freq = {}
        total_activities = 0
        security_events = 0
        timestamps = []
        anomalies = []

        try:
            with self.store.session() as session:
                # Get tool frequency
                result = session.run(self.GET_TOOL_FREQUENCY, session_id=session_id)
                for row in result:
                    key = f"{row['tool_type']}:{row['tool_name']}"
                    tool_freq[key] = row['count']
                    total_activities += row['count']

                # Get timeline for timing analysis
                result = session.run(self.GET_ACTIVITY_TIMELINE, session_id=session_id)
                for row in result:
                    timestamps.append(row['timestamp'])

                # Get security events
                result = session.run(self.GET_SECURITY_EVENTS, session_id=session_id)
                security_events = len(list(result))

        except Exception as e:
            logger.error(f"Error getting behavior profile: {e}", exc_info=True)
            # Surface error in anomalies so it's visible
            anomalies.append(f"_debug_error: {type(e).__name__}: {e}")

        # Calculate average time between actions
        avg_time = 0.0
        if len(timestamps) > 1:
            # Parse and calculate
            try:
                diffs = []
                for i in range(1, len(timestamps)):
                    t1 = datetime.fromisoformat(timestamps[i-1].replace('Z', '+00:00'))
                    t2 = datetime.fromisoformat(timestamps[i].replace('Z', '+00:00'))
                    diffs.append((t2 - t1).total_seconds())
                if diffs:
                    avg_time = sum(diffs) / len(diffs)
            except:
                pass

        # Calculate risk score (0-100)
        risk_score = min(100, (
            (security_events * 10) +
            (len([t for t in tool_freq.keys() if 'bash' in t.lower()]) * 5) +
            (len([t for t in tool_freq.keys() if 'file_read' in t.lower()]) * 2)
        ))

        # Detect anomalies
        if avg_time < 0.5 and total_activities > 10:
            anomalies.append("Unusually rapid activity")
        if security_events > 5:
            anomalies.append("High security event count")
        if any('env' in t.lower() or 'secret' in t.lower() for t in tool_freq.keys()):
            anomalies.append("Sensitive resource access")

        return BehaviorProfile(
            session_id=session_id,
            agent_id="",  # Would need to query
            total_activities=total_activities,
            tool_frequency=tool_freq,
            avg_time_between_actions=avg_time,
            file_access_patterns={},  # Would need detailed query
            security_events=security_events,
            risk_score=risk_score,
            anomalies=anomalies,
        )

    def find_similar_sessions(self, session_id: str) -> list[dict]:
        """Find sessions with similar behavior patterns."""
        try:
            with self.store.session() as session:
                result = session.run(
                    self.FIND_SIMILAR_SESSIONS,
                    session_id=session_id,
                )
                return [dict(row) for row in result]
        except Exception as e:
            logger.error(f"Error finding similar sessions: {e}")
            return []

    def get_global_stats(self) -> dict[str, Any]:
        """Get global statistics for anomaly baseline."""
        try:
            with self.store.session() as session:
                result = session.run(self.GET_GLOBAL_TOOL_STATS)
                tools = {}
                for row in result:
                    tools[row['tool']] = {
                        'total': row['total'],
                        'frequency': row['frequency'],
                    }
                return {
                    'tool_distribution': tools,
                    'total_activities': sum(t['total'] for t in tools.values()),
                }
        except Exception as e:
            logger.error(f"Error getting global stats: {e}")
            return {}

    # ==========================================
    # AGENT/USER PROFILING METHODS
    # ==========================================

    def get_agent_risk_profile(self, agent_id: str) -> AgentRiskProfile:
        """
        Get long-term risk profile for an agent across all sessions.

        Provides:
        - Total sessions and activities
        - Average and max risk scores
        - Most used tools
        - Common attack patterns
        - Risk trend over time
        """
        total_sessions = 0
        total_activities = 0
        agent_name = ""
        first_seen = ""
        last_seen = ""
        tool_counts: dict[str, int] = {}
        security_events = 0
        blocked_actions = 0
        common_patterns: list[str] = []

        try:
            with self.store.session() as session:
                # Get basic profile
                result = session.run(self.GET_AGENT_PROFILE, agent_id=agent_id)
                row = result.single()
                if row:
                    agent_name = row["agent_name"] or agent_id
                    total_sessions = row["total_sessions"]
                    total_activities = row["total_activities"]
                    first_seen = str(row["first_seen"]) if row["first_seen"] else ""
                    last_seen = str(row["last_seen"]) if row["last_seen"] else ""

                    # Count tools
                    for tool in row["all_tools"]:
                        tool_counts[tool] = tool_counts.get(tool, 0) + 1

                # Get security events
                result = session.run(self.GET_AGENT_SECURITY_EVENTS, agent_id=agent_id)
                for row in result:
                    event_count = row["count"]
                    security_events += event_count
                    if row["event_type"] == "blocked":
                        blocked_actions += event_count
                    common_patterns.append(f"{row['event_type']}: {event_count}")

                # Get risk trend
                result = session.run(self.GET_AGENT_RISK_TREND, agent_id=agent_id)
                row = result.single()
                risk_trend = "stable"
                if row and row["history"]:
                    history = row["history"]
                    if len(history) >= 3:
                        recent = sum(h["events"] for h in history[-3:])
                        older = sum(h["events"] for h in history[:3])
                        if recent > older * 1.5:
                            risk_trend = "increasing"
                        elif recent < older * 0.5:
                            risk_trend = "decreasing"

        except Exception as e:
            logger.error(f"Error getting agent risk profile: {e}")

        # Calculate risk scores
        avg_risk = min(100, (security_events / max(total_sessions, 1)) * 10)
        max_risk = min(100, security_events * 5) if security_events > 0 else 0

        # Determine risk level
        if avg_risk >= 70 or blocked_actions >= 10:
            risk_level = RiskLevel.CRITICAL
        elif avg_risk >= 40 or blocked_actions >= 5:
            risk_level = RiskLevel.HIGH
        elif avg_risk >= 20 or blocked_actions >= 2:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW

        # Sort tools by frequency
        sorted_tools = dict(sorted(tool_counts.items(), key=lambda x: x[1], reverse=True)[:10])

        return AgentRiskProfile(
            agent_id=agent_id,
            agent_name=agent_name,
            total_sessions=total_sessions,
            total_activities=total_activities,
            avg_risk_score=avg_risk,
            max_risk_score=max_risk,
            total_security_events=security_events,
            blocked_actions=blocked_actions,
            most_used_tools=sorted_tools,
            common_patterns=common_patterns[:5],
            risk_trend=risk_trend,
            first_seen=first_seen,
            last_seen=last_seen,
            risk_level=risk_level,
        )

    def get_agent_sessions(self, agent_id: str, limit: int = 20) -> list[dict]:
        """Get recent sessions for an agent."""
        try:
            with self.store.session() as session:
                result = session.run(
                    self.GET_AGENT_SESSIONS,
                    agent_id=agent_id,
                    limit=limit,
                )
                return [dict(row) for row in result]
        except Exception as e:
            logger.error(f"Error getting agent sessions: {e}")
            return []

    def get_user_risk_profile(self, user_id: str) -> UserRiskProfile:
        """
        Get risk profile for a user/team across all their agents.

        Aggregates risk data from all agents belonging to the user.
        """
        total_agents = 0
        total_sessions = 0
        total_activities = 0
        total_security_events = 0
        risk_by_agent: dict[str, float] = {}
        high_risk_sessions = 0
        critical_events = 0

        try:
            # User prefix format: "agent:{user_id}:"
            user_prefix = f"agent:{user_id}:"

            with self.store.session() as session:
                result = session.run(self.GET_USER_PROFILE, user_prefix=user_prefix)
                row = result.single()
                if row:
                    total_agents = row["total_agents"]
                    total_sessions = row["total_sessions"]
                    total_activities = row["total_activities"]
                    total_security_events = row["total_security_events"]

                    for agent_data in row["by_agent"]:
                        agent_id = agent_data["agent"]
                        events = agent_data["events"]
                        sessions = agent_data["sessions"]
                        risk_ratio = events / max(sessions, 1)
                        risk_by_agent[agent_id] = risk_ratio

                        if risk_ratio > 0.5:
                            high_risk_sessions += sessions

        except Exception as e:
            logger.error(f"Error getting user risk profile: {e}")

        # Calculate average risk
        avg_risk = (total_security_events / max(total_sessions, 1)) * 10 if total_sessions > 0 else 0

        # Determine risk level
        if avg_risk >= 50 or high_risk_sessions >= 5:
            risk_level = RiskLevel.HIGH
        elif avg_risk >= 20 or high_risk_sessions >= 2:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW

        # Get common threats
        common_threats = [
            {"type": "security_events", "count": total_security_events},
            {"type": "high_risk_sessions", "count": high_risk_sessions},
        ]

        return UserRiskProfile(
            user_id=user_id,
            total_agents=total_agents,
            total_sessions=total_sessions,
            total_activities=total_activities,
            avg_risk_score=avg_risk,
            high_risk_sessions=high_risk_sessions,
            critical_events=critical_events,
            risk_by_agent=risk_by_agent,
            common_threats=common_threats,
            risk_level=risk_level,
        )

    def get_all_agents_risk_summary(self, limit: int = 50) -> list[dict]:
        """Get risk summary for all agents, sorted by risk."""
        try:
            with self.store.session() as session:
                result = session.run(self.GET_ALL_AGENTS_RISK, limit=limit)
                agents = []
                for row in result:
                    risk_ratio = row["risk_ratio"]
                    if risk_ratio >= 0.3:
                        risk_level = "high"
                    elif risk_ratio >= 0.1:
                        risk_level = "medium"
                    else:
                        risk_level = "low"

                    agents.append({
                        "agent_id": row["agent_id"],
                        "agent_name": row["agent_name"],
                        "sessions": row["sessions"],
                        "activities": row["activities"],
                        "security_events": row["security_events"],
                        "risk_ratio": risk_ratio,
                        "risk_level": risk_level,
                    })
                return agents
        except Exception as e:
            logger.error(f"Error getting agents risk summary: {e}")
            return []

    def compare_agent_profiles(self, agent_id_a: str, agent_id_b: str) -> dict[str, Any]:
        """Compare two agent profiles side by side."""
        profile_a = self.get_agent_risk_profile(agent_id_a)
        profile_b = self.get_agent_risk_profile(agent_id_b)

        return {
            "agent_a": {
                "id": profile_a.agent_id,
                "name": profile_a.agent_name,
                "risk_score": profile_a.avg_risk_score,
                "risk_level": profile_a.risk_level.value,
                "sessions": profile_a.total_sessions,
                "security_events": profile_a.total_security_events,
            },
            "agent_b": {
                "id": profile_b.agent_id,
                "name": profile_b.agent_name,
                "risk_score": profile_b.avg_risk_score,
                "risk_level": profile_b.risk_level.value,
                "sessions": profile_b.total_sessions,
                "security_events": profile_b.total_security_events,
            },
            "comparison": {
                "risk_diff": profile_a.avg_risk_score - profile_b.avg_risk_score,
                "more_risky": agent_id_a if profile_a.avg_risk_score > profile_b.avg_risk_score else agent_id_b,
                "common_tools": list(
                    set(profile_a.most_used_tools.keys()) &
                    set(profile_b.most_used_tools.keys())
                ),
            },
        }


def analyze_session_risk(session_id: str, graph_store) -> dict[str, Any]:
    """
    Convenience function to run full risk analysis on a session.
    Returns comprehensive risk report.
    """
    _debug = {
        "graph_store_type": str(type(graph_store)),
        "graph_store_is_none": graph_store is None,
        "session_id": session_id,
    }

    # Quick connectivity test
    if graph_store is not None:
        try:
            with graph_store.session() as test_session:
                result = test_session.run(
                    "MATCH (a:ProvenanceRecord)-[:BELONGS_TO]->(s:Session {session_id: $sid}) RETURN count(a) as cnt",
                    sid=session_id
                )
                row = result.single()
                _debug["neo4j_direct_count"] = row["cnt"] if row else 0
        except Exception as e:
            _debug["neo4j_test_error"] = f"{type(e).__name__}: {e}"

    analyzer = GraphRAGAnalyzer(graph_store)

    patterns = analyzer.analyze_session(session_id)
    profile = analyzer.get_behavior_profile(session_id)
    similar = analyzer.find_similar_sessions(session_id)

    # Determine overall risk level
    if any(p.risk_level == RiskLevel.CRITICAL for p in patterns):
        overall_risk = RiskLevel.CRITICAL
    elif any(p.risk_level == RiskLevel.HIGH for p in patterns):
        overall_risk = RiskLevel.HIGH
    elif any(p.risk_level == RiskLevel.MEDIUM for p in patterns):
        overall_risk = RiskLevel.MEDIUM
    else:
        overall_risk = RiskLevel.LOW

    return {
        'session_id': session_id,
        'overall_risk': overall_risk.value,
        'risk_score': profile.risk_score,
        'patterns_detected': len(patterns),
        'patterns': [
            {
                'id': p.pattern_id,
                'type': p.pattern_type.value,
                'risk': p.risk_level.value,
                'confidence': p.confidence,
                'description': p.description,
                'recommendation': p.recommendation,
            }
            for p in patterns
        ],
        'behavior_profile': {
            'total_activities': profile.total_activities,
            'avg_action_interval': profile.avg_time_between_actions,
            'security_events': profile.security_events,
            'anomalies': profile.anomalies,
        },
        'similar_sessions': similar[:3],
        '_debug': _debug,
    }


def get_agent_risk(agent_id: str, graph_store) -> dict[str, Any]:
    """
    Convenience function to get agent risk profile.
    Returns comprehensive risk data for an agent.
    """
    analyzer = GraphRAGAnalyzer(graph_store)
    profile = analyzer.get_agent_risk_profile(agent_id)
    sessions = analyzer.get_agent_sessions(agent_id, limit=5)

    return {
        'agent_id': profile.agent_id,
        'agent_name': profile.agent_name,
        'risk_level': profile.risk_level.value,
        'avg_risk_score': profile.avg_risk_score,
        'max_risk_score': profile.max_risk_score,
        'risk_trend': profile.risk_trend,
        'summary': {
            'total_sessions': profile.total_sessions,
            'total_activities': profile.total_activities,
            'security_events': profile.total_security_events,
            'blocked_actions': profile.blocked_actions,
        },
        'most_used_tools': profile.most_used_tools,
        'common_patterns': profile.common_patterns,
        'recent_sessions': sessions,
        'first_seen': profile.first_seen,
        'last_seen': profile.last_seen,
    }


def get_user_risk(user_id: str, graph_store) -> dict[str, Any]:
    """
    Convenience function to get user/team risk profile.
    Aggregates risk across all agents belonging to the user.
    """
    analyzer = GraphRAGAnalyzer(graph_store)
    profile = analyzer.get_user_risk_profile(user_id)

    return {
        'user_id': profile.user_id,
        'risk_level': profile.risk_level.value,
        'avg_risk_score': profile.avg_risk_score,
        'summary': {
            'total_agents': profile.total_agents,
            'total_sessions': profile.total_sessions,
            'total_activities': profile.total_activities,
            'high_risk_sessions': profile.high_risk_sessions,
            'critical_events': profile.critical_events,
        },
        'risk_by_agent': profile.risk_by_agent,
        'common_threats': profile.common_threats,
    }


def get_all_agents_summary(graph_store, limit: int = 50) -> dict[str, Any]:
    """
    Get summary of all agents with their risk levels.
    Useful for org-wide dashboards.
    """
    analyzer = GraphRAGAnalyzer(graph_store)
    agents = analyzer.get_all_agents_risk_summary(limit)

    # Categorize by risk
    high_risk = [a for a in agents if a['risk_level'] == 'high']
    medium_risk = [a for a in agents if a['risk_level'] == 'medium']
    low_risk = [a for a in agents if a['risk_level'] == 'low']

    return {
        'total_agents': len(agents),
        'by_risk_level': {
            'high': len(high_risk),
            'medium': len(medium_risk),
            'low': len(low_risk),
        },
        'high_risk_agents': high_risk[:10],
        'all_agents': agents,
    }
