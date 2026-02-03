// ── Enums (string unions) ──────────────────────────────────────────────

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// ── Threat & PII ───────────────────────────────────────────────────────

export interface ThreatInfo {
  type: string;
  subtype?: string;
  pattern_id?: string;
  matched_text?: string;
  position?: number[];
  confidence: number;
  severity: Severity;
  description: string;
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
  text: string;
  agent_id?: string;
  session_id?: string;
  metadata?: Record<string, unknown>;
}

export interface ScanInputResponse {
  request_id: string;
  safe: boolean;
  risk_level: RiskLevel;
  risk_score: number;
  latency_ms: number;
  threats: ThreatInfo[];
  recommendation: string;
  action_taken: string;
}

export interface ScanOutputRequest {
  text: string;
  agent_id?: string;
  session_id?: string;
  auto_sanitize?: boolean;
}

export interface ScanOutputResponse {
  request_id: string;
  safe: boolean;
  risk_level: RiskLevel;
  risk_score: number;
  latency_ms: number;
  pii_detected: PIIInfo[];
  original_text: string;
  sanitized_text: string;
  recommendation: string;
  action_taken: string;
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

export interface ActionInfo {
  type: string;
  target?: string;
  parameters?: Record<string, unknown>;
}

export interface LogActionRequest {
  agent_id: string;
  session_id: string;
  action: ActionInfo;
  context?: Record<string, unknown>;
  timestamp?: string;
}

export interface LogActionResponse {
  request_id: string;
  logged: boolean;
  action_id: string;
  node_id?: string;
  anomaly_detected: boolean;
  anomalies: AnomalyInfo[];
  session_risk_score: number;
  alerts_triggered: string[];
}

// ── Sessions ────────────────────────────────────────────────────────────

export interface SessionStats {
  total_actions: number;
  input_scans: number;
  output_scans: number;
  threats_detected: number;
  pii_detected: number;
  anomalies_detected: number;
}

export interface TimelineEvent {
  timestamp: string;
  type: string;
  severity: string;
  description: string;
}

export interface GraphSummary {
  nodes: number;
  edges: number;
  clusters: number;
}

export interface SessionResponse {
  session_id: string;
  agent_id: string;
  status: string;
  risk_level: RiskLevel;
  risk_score: number;
  started_at: string | null;
  last_activity_at: string | null;
  stats: SessionStats;
  timeline: TimelineEvent[];
  graph_summary: GraphSummary;
}

export interface SessionListResponse {
  items: SessionResponse[];
  total: number;
  page: number;
  size: number;
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
  request_id?: string;
  report_id: string;
  session_id: string;
  status: string;
  generated_at: string;
  generation_time_ms?: number;
  summary: ReportSummary;
  analysis: ReportAnalysis;
  recommendations: Recommendation[];
  raw_graph_data?: Record<string, unknown>;
}

export interface ReportRequest {
  report_type?: string;
  include_recommendations?: boolean;
  language?: string;
}

// ── Alerts ──────────────────────────────────────────────────────────────

export interface AlertResponse {
  id: string;
  session_id: string;
  agent_id: string;
  alert_type: string;
  severity: Severity;
  title: string;
  description: string;
  details?: Record<string, unknown> | null;
  is_acknowledged: boolean;
  acknowledged_by?: string | null;
  acknowledged_at?: string | null;
  created_at: string | null;
}

export interface AlertListResponse {
  items: AlertResponse[];
  total: number;
  page: number;
  size: number;
}

// ── Dashboard ───────────────────────────────────────────────────────────

export interface DashboardStats {
  total_requests: number;
  threats_blocked: number;
  pii_sanitized: number;
  active_sessions: number;
  anomalies_detected: number;
  risk_distribution?: Record<string, number>;
  [key: string]: unknown;
}

export interface TrendData {
  timestamp: string;
  count: number;
}

export interface TopThreat {
  type: string;
  count: number;
  severity: Severity;
}

// ── Users & API Keys ────────────────────────────────────────────────────

export interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  is_active: boolean;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export interface APIKey {
  id: string;
  name: string;
  key_prefix: string;
  permissions: string[];
  is_active: boolean;
  last_used_at?: string | null;
  expires_at?: string | null;
  created_at: string | null;
  key?: string | null;
}

export interface APIKeyCreateRequest {
  name: string;
  permissions: string[];
  expires_in_days?: number;
}
