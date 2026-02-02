/**
 * Configuration options for the AgentShield client.
 */
export interface AgentShieldConfig {
  /** Base URL for the AgentShield API. */
  baseUrl?: string;
  /** Request timeout in milliseconds. */
  timeout?: number;
  /** Custom headers to include in requests. */
  headers?: Record<string, string>;
}

/**
 * Information about a detected threat.
 */
export interface ThreatInfo {
  /** Type of threat (e.g., "prompt_injection", "jailbreak"). */
  type: string;
  /** Severity level: "low", "medium", "high", "critical". */
  severity: string;
  /** Confidence score between 0.0 and 1.0. */
  confidence: number;
  /** Human-readable description of the threat. */
  description: string;
  /** Pattern that triggered the detection, if any. */
  matched_pattern?: string;
}

/**
 * Information about detected personally identifiable information.
 */
export interface PIIInfo {
  /** Type of PII (e.g., "ssn", "email", "phone", "credit_card"). */
  type: string;
  /** The detected PII value (may be masked). */
  value: string;
  /** Start character index in the original text. */
  start: number;
  /** End character index in the original text. */
  end: number;
  /** Detection confidence score. */
  confidence: number;
}

/**
 * Request payload for scanning user input.
 */
export interface ScanInputRequest {
  /** The user input text to scan. */
  text: string;
  /** Identifier of the AI agent. */
  agent_id: string;
  /** Current session identifier. */
  session_id: string;
  /** Optional additional metadata. */
  metadata?: Record<string, unknown>;
}

/**
 * Response from scanning user input.
 */
export interface ScanInputResponse {
  /** Unique identifier for this scan. */
  scan_id: string;
  /** Whether the input is considered safe. */
  is_safe: boolean;
  /** Overall risk level: "low", "medium", "high", "critical". */
  risk_level: string;
  /** Numeric risk score from 0.0 to 1.0. */
  risk_score: number;
  /** List of detected threats. */
  threats: ThreatInfo[];
  /** List of detected PII. */
  pii_detected: PIIInfo[];
  /** Recommended actions. */
  recommendations: string[];
  /** Processing time in milliseconds. */
  processing_time_ms: number;
}

/**
 * Request payload for scanning agent output.
 */
export interface ScanOutputRequest {
  /** The agent output text to scan. */
  text: string;
  /** Identifier of the AI agent. */
  agent_id: string;
  /** Current session identifier. */
  session_id: string;
  /** Whether to automatically redact sensitive data. */
  auto_sanitize?: boolean;
}

/**
 * Response from scanning agent output.
 */
export interface ScanOutputResponse {
  /** Unique identifier for this scan. */
  scan_id: string;
  /** Whether the output is considered safe. */
  is_safe: boolean;
  /** Overall risk level. */
  risk_level: string;
  /** Numeric risk score from 0.0 to 1.0. */
  risk_score: number;
  /** List of detected PII in output. */
  pii_detected: PIIInfo[];
  /** Whether data leakage was detected. */
  data_leakage_risk: boolean;
  /** Sanitized version of the text if auto_sanitize was enabled. */
  sanitized_text: string | null;
  /** List of issues found. */
  issues: string[];
  /** Processing time in milliseconds. */
  processing_time_ms: number;
}

/**
 * Request payload for logging an agent action.
 */
export interface LogActionRequest {
  /** Identifier of the AI agent. */
  agent_id: string;
  /** Current session identifier. */
  session_id: string;
  /** Type of action (e.g., "tool_call", "api_request"). */
  action_type: string;
  /** Name of the action performed. */
  name: string;
  /** Target resource of the action. */
  target?: string;
  /** Action parameters. */
  parameters?: Record<string, unknown>;
  /** Summary of the action result. */
  result_summary?: string;
  /** Duration of the action in milliseconds. */
  duration_ms?: number;
  /** Additional context information. */
  context?: Record<string, unknown>;
}

/**
 * Information about a detected anomaly.
 */
export interface AnomalyInfo {
  /** Type of anomaly. */
  type: string;
  /** Severity level. */
  severity: string;
  /** Human-readable description. */
  description: string;
  /** Anomaly score. */
  score: number;
  /** Deviation from baseline behavior. */
  baseline_deviation?: number;
}

/**
 * Response from logging an agent action.
 */
export interface LogActionResponse {
  /** Unique identifier for the logged action. */
  action_id: string;
  /** Status of the action log. */
  status: string;
  /** Risk level assessed for this action. */
  risk_level: string;
  /** Detected anomalies. */
  anomalies: AnomalyInfo[];
  /** Whether the action was flagged as anomalous. */
  is_anomalous: boolean;
  /** Recommended actions. */
  recommendations: string[];
}

/**
 * Response containing session details.
 */
export interface SessionResponse {
  /** The session identifier. */
  session_id: string;
  /** The agent identifier. */
  agent_id: string;
  /** Session status. */
  status: string;
  /** Overall session risk level. */
  risk_level: string;
  /** Overall risk score. */
  risk_score: number;
  /** ISO 8601 timestamp of session start. */
  start_time: string;
  /** ISO 8601 timestamp of session end. */
  end_time: string | null;
  /** Total number of actions in the session. */
  total_actions: number;
  /** Total number of scans performed. */
  total_scans: number;
  /** Number of threats detected. */
  threats_detected: number;
  /** Number of anomalies detected. */
  anomalies_detected: number;
  /** Additional session metadata. */
  metadata: Record<string, unknown>;
}

/**
 * Parameters for listing sessions.
 */
export interface ListSessionsParams {
  /** Filter by session status. */
  status?: string;
  /** Filter by risk level. */
  risk_level?: string;
  /** Page number. */
  page?: number;
  /** Items per page. */
  size?: number;
}

/**
 * Paginated response wrapper.
 */
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
}

/**
 * Response for listing sessions.
 */
export type ListSessionsResponse = PaginatedResponse<SessionResponse>;

/**
 * Request payload for generating a report.
 */
export interface ReportRequest {
  /** The session identifier. */
  session_id: string;
  /** Type of report to generate. */
  report_type?: string;
  /** Language for the report. */
  language?: string;
}

/**
 * A security recommendation from a report.
 */
export interface Recommendation {
  /** Priority level. */
  priority: string;
  /** Category of recommendation. */
  category: string;
  /** Short title. */
  title: string;
  /** Detailed description. */
  description: string;
  /** List of affected action IDs. */
  affected_actions: string[];
}

/**
 * Response containing a generated security report.
 */
export interface ReportResponse {
  /** Unique identifier for the report. */
  report_id: string;
  /** The session this report covers. */
  session_id: string;
  /** Type of report generated. */
  report_type: string;
  /** Language of the report. */
  language: string;
  /** Report title. */
  title: string;
  /** Executive summary. */
  summary: string;
  /** Overall risk assessment. */
  risk_level: string;
  /** Overall risk score. */
  risk_score: number;
  /** Total events analyzed. */
  total_events: number;
  /** Number of threats found. */
  threats_found: number;
  /** Number of anomalies found. */
  anomalies_found: number;
  /** Security recommendations. */
  recommendations: Recommendation[];
  /** ISO 8601 timestamp of report generation. */
  generated_at: string;
  /** Full report content in markdown. */
  content: string | null;
}

/**
 * Parameters for listing alerts.
 */
export interface ListAlertsParams {
  /** Filter by severity. */
  severity?: string;
  /** Filter by acknowledgement status. */
  acknowledged?: boolean;
  /** Page number. */
  page?: number;
  /** Items per page. */
  size?: number;
}

/**
 * Response containing alert details.
 */
export interface AlertResponse {
  /** Unique identifier for the alert. */
  alert_id: string;
  /** Associated session identifier. */
  session_id: string;
  /** Associated agent identifier. */
  agent_id: string;
  /** Alert severity. */
  severity: string;
  /** Type of alert. */
  type: string;
  /** Alert title. */
  title: string;
  /** Detailed alert description. */
  description: string;
  /** Whether the alert has been acknowledged. */
  acknowledged: boolean;
  /** ISO 8601 timestamp of acknowledgement. */
  acknowledged_at: string | null;
  /** ISO 8601 timestamp of alert creation. */
  created_at: string;
  /** Additional alert metadata. */
  metadata: Record<string, unknown>;
}

/**
 * Response for listing alerts.
 */
export type ListAlertsResponse = PaginatedResponse<AlertResponse>;

/**
 * Error response from the AgentShield API.
 */
export interface AgentShieldErrorResponse {
  /** Error detail message. */
  detail: string;
  /** Error code, if available. */
  code?: string;
}
