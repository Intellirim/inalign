import * as http from 'http';

export interface ProxyStats {
    total_requests: number;
    blocked_requests: number;
    forwarded_requests: number;
    cached_responses: number;
    tokens_saved: number;
    cost_saved_usd: number;
    optimizations_applied: number;
    pii_masked: number;
    attacks_blocked: number;
    security_features: {
        injection_detector: string;
        pii_detector: string;
        context_extractor: string;
    };
}

export interface HealthResponse {
    status: string;
    stats: ProxyStats;
}

export interface ContextStats {
    active_sessions: number;
    total_interactions: number;
    contexts: Record<string, any>;
}

export class ProxyClient {
    private baseUrl: string;

    constructor(baseUrl: string = 'http://localhost:8080') {
        this.baseUrl = baseUrl.replace(/\/$/, '');
    }

    private request<T>(path: string): Promise<T> {
        return new Promise((resolve, reject) => {
            const url = new URL(path, this.baseUrl);

            const req = http.get(url.toString(), { timeout: 5000 }, (res) => {
                let data = '';

                res.on('data', (chunk) => {
                    data += chunk;
                });

                res.on('end', () => {
                    try {
                        if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                            resolve(JSON.parse(data) as T);
                        } else {
                            reject(new Error(`HTTP ${res.statusCode}: ${data}`));
                        }
                    } catch (e) {
                        reject(e);
                    }
                });
            });

            req.on('error', reject);
            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });
        });
    }

    async getHealth(): Promise<HealthResponse> {
        return this.request<HealthResponse>('/health');
    }

    async getStats(): Promise<ProxyStats> {
        return this.request<ProxyStats>('/stats');
    }

    async getContext(): Promise<ContextStats> {
        return this.request<ContextStats>('/context');
    }

    setBaseUrl(url: string) {
        this.baseUrl = url.replace(/\/$/, '');
    }
}
