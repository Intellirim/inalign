import type {
  InALignConfig,
  ScanInputRequest,
  ScanInputResponse,
  ScanOutputRequest,
  ScanOutputResponse,
  LogActionRequest,
  LogActionResponse,
  SessionResponse,
  ListSessionsParams,
  ListSessionsResponse,
  ReportRequest,
  ReportResponse,
  ListAlertsParams,
  ListAlertsResponse,
  InALignErrorResponse,
} from "./types";

/**
 * Error thrown by the InALign SDK.
 */
export class InALignError extends Error {
  public readonly statusCode: number;
  public readonly detail: string;
  public readonly code?: string;

  constructor(message: string, statusCode: number, detail: string, code?: string) {
    super(message);
    this.name = "InALignError";
    this.statusCode = statusCode;
    this.detail = detail;
    this.code = code;
  }
}

export class AuthenticationError extends InALignError {
  constructor(detail: string, statusCode = 401) {
    super(`Authentication failed: ${detail}`, statusCode, detail);
    this.name = "AuthenticationError";
  }
}

export class RateLimitError extends InALignError {
  constructor(detail: string) {
    super(`Rate limit exceeded: ${detail}`, 429, detail);
    this.name = "RateLimitError";
  }
}

export class NotFoundError extends InALignError {
  constructor(detail: string) {
    super(`Not found: ${detail}`, 404, detail);
    this.name = "NotFoundError";
  }
}

export class ValidationError extends InALignError {
  constructor(detail: string) {
    super(`Validation failed: ${detail}`, 422, detail);
    this.name = "ValidationError";
  }
}

export class ServerError extends InALignError {
  constructor(detail: string, statusCode = 500) {
    super(`Server error: ${detail}`, statusCode, detail);
    this.name = "ServerError";
  }
}

/**
 * InALign SDK client for JavaScript/TypeScript.
 *
 * @example
 * ```typescript
 * const shield = new InALign("your-api-key");
 *
 * const result = await shield.scanInput({
 *   text: "My SSN is 123-45-6789",
 *   agent_id: "agent-1",
 *   session_id: "sess-abc",
 * });
 *
 * console.log(result.is_safe);
 * console.log(result.threats);
 * ```
 */
export class InALign {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeout: number;
  private readonly customHeaders: Record<string, string>;

  constructor(apiKey: string, options?: InALignConfig) {
    if (!apiKey) {
      throw new Error("apiKey is required and cannot be empty.");
    }

    this.apiKey = apiKey;
    this.baseUrl = (options?.baseUrl ?? "https://api.inalign.io").replace(/\/+$/, "");
    this.timeout = options?.timeout ?? 30000;
    this.customHeaders = options?.headers ?? {};
  }

  /**
   * Make an HTTP request to the InALign API.
   */
  private async _request<T>(
    method: string,
    path: string,
    body?: Record<string, unknown>,
    params?: Record<string, string | number | boolean | undefined>,
  ): Promise<T> {
    const url = new URL(`${this.baseUrl}/${path.replace(/^\//, "")}`);

    // Add query parameters
    if (params) {
      for (const [key, value] of Object.entries(params)) {
        if (value !== undefined) {
          url.searchParams.set(key, String(value));
        }
      }
    }

    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.apiKey}`,
      "Content-Type": "application/json",
      Accept: "application/json",
      "User-Agent": "@inalign/sdk-js/0.1.0",
      ...this.customHeaders,
    };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const fetchOptions: RequestInit = {
        method,
        headers,
        signal: controller.signal,
      };

      if (body && method !== "GET") {
        fetchOptions.body = JSON.stringify(body);
      }

      const response = await fetch(url.toString(), fetchOptions);

      if (!response.ok) {
        let errorBody: InALignErrorResponse;
        try {
          errorBody = (await response.json()) as InALignErrorResponse;
        } catch {
          errorBody = { detail: response.statusText };
        }

        const detail = errorBody.detail || `HTTP ${response.status} error`;

        switch (response.status) {
          case 401:
          case 403:
            throw new AuthenticationError(detail, response.status);
          case 404:
            throw new NotFoundError(detail);
          case 422:
            throw new ValidationError(detail);
          case 429:
            throw new RateLimitError(detail);
          default:
            if (response.status >= 500) {
              throw new ServerError(detail, response.status);
            }
            throw new InALignError(detail, response.status, detail, errorBody.code);
        }
      }

      return (await response.json()) as T;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Scan user input for threats and PII before processing.
   */
  async scanInput(request: ScanInputRequest): Promise<ScanInputResponse> {
    return this._request<ScanInputResponse>("POST", "/v1/scan/input", {
      text: request.text,
      agent_id: request.agent_id,
      session_id: request.session_id,
      ...(request.metadata !== undefined && { metadata: request.metadata }),
    });
  }

  /**
   * Scan agent output for sensitive data leakage.
   */
  async scanOutput(request: ScanOutputRequest): Promise<ScanOutputResponse> {
    return this._request<ScanOutputResponse>("POST", "/v1/scan/output", {
      text: request.text,
      agent_id: request.agent_id,
      session_id: request.session_id,
      auto_sanitize: request.auto_sanitize ?? false,
    });
  }

  /**
   * Log an agent action for audit and anomaly detection.
   */
  async logAction(request: LogActionRequest): Promise<LogActionResponse> {
    return this._request<LogActionResponse>("POST", "/v1/actions/log", {
      agent_id: request.agent_id,
      session_id: request.session_id,
      action_type: request.action_type,
      name: request.name,
      target: request.target ?? "",
      parameters: request.parameters ?? {},
      result_summary: request.result_summary ?? "",
      duration_ms: request.duration_ms ?? 0,
      ...(request.context !== undefined && { context: request.context }),
    });
  }

  /**
   * Retrieve detailed information about a session.
   */
  async getSession(sessionId: string): Promise<SessionResponse> {
    return this._request<SessionResponse>("GET", `/v1/sessions/${sessionId}`);
  }

  /**
   * List sessions with optional filtering.
   */
  async listSessions(params?: ListSessionsParams): Promise<ListSessionsResponse> {
    return this._request<ListSessionsResponse>("GET", "/v1/sessions", undefined, {
      status: params?.status,
      risk_level: params?.risk_level,
      page: params?.page ?? 1,
      size: params?.size ?? 20,
    });
  }

  /**
   * Generate a security analysis report for a session.
   */
  async generateReport(request: ReportRequest): Promise<ReportResponse> {
    return this._request<ReportResponse>("POST", "/v1/reports/generate", {
      session_id: request.session_id,
      report_type: request.report_type ?? "security_analysis",
      language: request.language ?? "ko",
    });
  }

  /**
   * Retrieve security alerts with optional filtering.
   */
  async getAlerts(params?: ListAlertsParams): Promise<ListAlertsResponse> {
    return this._request<ListAlertsResponse>("GET", "/v1/alerts", undefined, {
      severity: params?.severity,
      acknowledged: params?.acknowledged,
      page: params?.page ?? 1,
      size: params?.size ?? 20,
    });
  }

  /**
   * Acknowledge a security alert.
   */
  async acknowledgeAlert(alertId: string): Promise<{ acknowledged: boolean; acknowledged_at: string }> {
    return this._request("PATCH", `/v1/alerts/${alertId}/acknowledge`);
  }
}
