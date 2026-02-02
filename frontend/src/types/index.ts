// ── Enums (string unions) ──────────────────────────────────────────────

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// ── Threat & PII ───────────────────────────────────────────────────────

export interface ThreatInfo {
  type: string;
  category: string;
  severity: Severity;
  confidence: number;
  description: string;
  evidence?: string;
  mitigations?: string[];
}

export interface PIIInfo {
  type: string;
  value: string;
  start: number;
  end: number;
  sanitized_value?: string;
  confidence: number;
}

// ── Scan ────────────────────────────────────────────────────────────────

export interface ScanInputRequest {
  session_id: string;
  agent_id: string;
  input_text: string;
  metadata?: Record<string, unknown>;
}

export interface ScanInputResponse {
  request_id: string;
  session_id: string;
  risk_level: RiskLevel;
  threats: ThreatInfo[];
  pii_detected: PIIInfo[];
  sanitized_input?: string;
  blocked: boolean;
  processing_time_ms: number;
}

export interface ScanOutputRequest {
  session_id: string;
  agent_id: string;
  output_text: string;
  metadata?: Record<string, unknown>;
}

export interface ScanOutputResponse {
  request_id: string;
  session_id: string;
  risk_level: RiskLevel;
  threats: ThreatInfo[];
  pii_detected: PIIInfo[];
  sanitized_output?: string;
  blocked: boolean;
  processing_time_ms: number;
}

// ── Log / Action ────────────────────────────────────────────────────────

export interface AnomalyInfo {
  type: string;
  description: string;
  severity: Severity;
  confidence: number;
  baseline_value?: number;
  observed_value?: number;
}

export interface LogActionRequest {
  session_id: string;
  agent_id: string;
  action_type: string;
  action_details: Record<string, unknown>;
  resource?: string;
  metadata?: Record<string, unknown>;
}

export interface LogActionResponse {
  request_id: string;
  session_id: string;
  risk_level: RiskLevel;
  anomalies: AnomalyInfo[];
  blocked: boolean;
  processing_time_ms: number;
}

// ── Sessions ────────────────────────────────────────────────────────────

export interface SessionStats {
  total_requests: number;
  threats_detected: number;
  threats_blocked: number;
  pii_detected: number;
  pii_sanitized: number;
  anomalies_detected: number;
  avg_risk_score: number;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  event_type: string;
  description: string;
  risk_level: RiskLevel;
  details?: Record<string, unknown>;
}

export interface GraphSummary {
  node_count: number;
  edge_count: number;
  risk_hotspots: string[];
  graph_data?: Record<string, unknown>;
}

export interface SessionResponse {
  id: string;
  agent_id: string;
  status: 'active' | 'completed' | 'terminated';
  risk_level: RiskLevel;
  risk_score: number;
  started_at: string;
  last_activity: string;
  ended_at?: string;
  stats: SessionStats;
  timeline: TimelineEvent[];
  graph_summary?: GraphSummary;
  metadata?: Record<string, unknown>;
}

export interface SessionListResponse {
  sessions: SessionResponse[];
  total: number;
  page: number;
  page_size: number;
}

// ── Reports ─────────────────────────────────────────────────────────────

export interface AttackVector {
  name: string;
  description: string;
  severity: Severity;
  evidence: string[];
  mitre_mapping?: string;
}

export interface BehaviorPattern {
  pattern: string;
  description: string;
  frequency: number;
  risk_level: RiskLevel;
  first_seen: string;
  last_seen: string;
}

export interface SimilarAttack {
  id: string;
  description: string;
  similarity_score: number;
  date: string;
}

export interface Recommendation {
  id: string;
  title: string;
  description: string;
  priority: Severity;
  category: string;
  implemented: boolean;
}

export interface ReportSummary {
  overall_risk: RiskLevel;
  risk_score: number;
  total_events: number;
  threats_found: number;
  pii_exposures: number;
  primary_concerns: string[];
}

export interface ReportAnalysis {
  attack_vectors: AttackVector[];
  behavior_patterns: BehaviorPattern[];
  similar_attacks: SimilarAttack[];
  recommendations: Recommendation[];
  timeline_summary: string;
}

export interface ReportResponse {
  id: string;
  session_id: string;
  generated_at: string;
  summary: ReportSummary;
  analysis: ReportAnalysis;
  metadata?: Record<string, unknown>;
}

export interface ReportRequest {
  session_id: string;
  include_recommendations?: boolean;
  include_similar_attacks?: boolean;
  format?: 'json' | 'pdf' | 'markdown';
}

// ── Alerts ──────────────────────────────────────────────────────────────

export interface AlertResponse {
  id: string;
  session_id: string;
  agent_id: string;
  severity: Severity;
  title: string;
  description: string;
  threat_type: string;
  created_at: string;
  acknowledged: boolean;
  acknowledged_at?: string;
  acknowledged_by?: string;
  metadata?: Record<string, unknown>;
}

export interface AlertListResponse {
  alerts: AlertResponse[];
  total: number;
  page: number;
  page_size: number;
}

// ── Dashboard ───────────────────────────────────────────────────────────

export interface DashboardStats {
  total_requests: number;
  threats_blocked: number;
  pii_sanitized: number;
  active_sessions: number;
  requests_trend: number;
  threats_trend: number;
  pii_trend: number;
  sessions_trend: number;
}

export interface TrendData {
  timestamp: string;
  injection_attempts: number;
  pii_detections: number;
  anomalies: number;
}

export interface TopThreat {
  type: string;
  count: number;
  severity: Severity;
  last_seen: string;
}

// ── Users & API Keys ────────────────────────────────────────────────────

export interface User {
  id: string;
  email: string;
  name: string;
  role: 'admin' | 'user' | 'viewer';
  created_at: string;
  last_login?: string;
  avatar_url?: string;
}

export interface APIKey {
  id: string;
  name: string;
  key_prefix: string;
  permissions: string[];
  created_at: string;
  last_used?: string;
  expires_at?: string;
  is_active: boolean;
}

export interface APIKeyCreateRequest {
  name: string;
  permissions: string[];
  expires_in_days?: number;
}
