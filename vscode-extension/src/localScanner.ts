/**
 * In-A-Lign Local Scanner
 *
 * Fast, local-only security scanning without proxy or API calls.
 * Works for Max subscription users without API keys.
 *
 * Features:
 * - Injection detection (multi-language)
 * - PII detection
 * - Prompt optimization hints
 */

export interface ScanResult {
    ok: boolean;
    reason?: string;
    riskScore: number;
    riskLevel: 'negligible' | 'low' | 'medium' | 'high' | 'critical';
    threats: ThreatInfo[];
    pii: PIIInfo;
    optimization?: OptimizationHint;
}

export interface ThreatInfo {
    type: string;
    patternId: string;
    matchedText: string;
    confidence: number;
    severity: 'low' | 'medium' | 'high';
}

export interface PIIInfo {
    found: boolean;
    types: { [key: string]: number };
}

export interface OptimizationHint {
    tokenEstimate: number;
    suggestions: string[];
}

// Multi-language injection patterns
const INJECTION_PATTERNS: Array<{ pattern: RegExp; id: string; confidence: number }> = [
    // Instruction Override
    { pattern: /\bignore\b.*\b(previous|above|prior|all|earlier|initial|original)\b.*\b(instructions?|rules?|prompts?|guidelines?|directives?)\b/i, id: 'INJ-001', confidence: 0.9 },
    { pattern: /\b(forget|disregard|skip|drop|abandon|neglect)\b.*\b(everything|all|instructions?|rules?|previous|prior)\b/i, id: 'INJ-002', confidence: 0.85 },
    { pattern: /\b(override|overwrite|replace|cancel|void|nullify)\b.*\b(instructions?|rules?|prompts?|directives?|settings?)\b/i, id: 'INJ-003', confidence: 0.85 },
    { pattern: /\b(do\s+not|don't|stop)\s+(follow|obey|listen|adhere|comply)/i, id: 'INJ-004', confidence: 0.8 },
    { pattern: /\bnew\s+(instruction|rule|prompt|session|directive|command)\b/i, id: 'INJ-005', confidence: 0.7 },
    { pattern: /\b(erase|clear|wipe|purge|reset)\b.*\b(memory|context|instructions?|rules?|previous)\b/i, id: 'INJ-006', confidence: 0.85 },

    // System Prompt Extraction
    { pattern: /\b(system|initial|original|hidden|secret|internal)\s*(prompt|instruction|rules?|config)\b/i, id: 'INJ-010', confidence: 0.85 },
    { pattern: /\b(show|reveal|display|print|output|expose|dump|leak|extract)\b.*\b(prompt|instruction|config|rules?|settings?)\b/i, id: 'INJ-011', confidence: 0.8 },
    { pattern: /\bwhat\s+(were\s+you|are\s+your|is\s+your)\s+(told|instructions?|rules?|prompt)\b/i, id: 'INJ-012', confidence: 0.75 },
    { pattern: /\brepeat\b.*\b(system|initial|original|first)\b.*\b(message|prompt|instruction)\b/i, id: 'INJ-014', confidence: 0.75 },

    // Jailbreak & Restriction Bypass
    { pattern: /\b(you\s+are\s+now|become|switch\s+to|transform\s+into)\s+(dan|dude|evil|unrestricted|jailbreak|uncensored)\b/i, id: 'INJ-020', confidence: 0.95 },
    { pattern: /\b(developer|debug|maintenance|sudo|admin|god|root|super|master)\s*mode\b/i, id: 'INJ-021', confidence: 0.9 },
    { pattern: /\b(no|without|remove|disable|bypass|circumvent|ignore)\s*(restrictions?|filters?|safety|limits?|rules?|censorship|guardrails?)\b/i, id: 'INJ-022', confidence: 0.85 },
    { pattern: /\b(jailbreak|unlock|unshackle|unleash|liberate|free)\b/i, id: 'INJ-023', confidence: 0.9 },
    { pattern: /\b(unrestricted|unlimited|unfiltered|uncensored|unmoderated)\s+(mode|access|version)\b/i, id: 'INJ-027', confidence: 0.9 },

    // Roleplay & Identity Manipulation
    { pattern: /\b(pretend|act\s+as|roleplay|imagine|play\s+the\s+role|assume\s+the\s+identity)\s+(you\s+are|being|as|of)\b/i, id: 'INJ-030', confidence: 0.7 },
    { pattern: /\b(evil|malicious|rogue|dangerous|harmful|unethical)\s*(ai|bot|assistant|agent)\b/i, id: 'INJ-031', confidence: 0.8 },
    { pattern: /\bfrom\s+now\s+on\s+(you\s+are|act\s+as|be|become)\b/i, id: 'INJ-032', confidence: 0.75 },

    // Code & Command Injection
    { pattern: /\b(eval|exec|system|subprocess|__import__|require|os\.)\s*\(/i, id: 'INJ-050', confidence: 0.9 },
    { pattern: /[`$]\([^)]+\)/i, id: 'INJ-051', confidence: 0.85 },
    { pattern: /;\s*(rm|del|drop|delete|truncate|format)\s/i, id: 'INJ-052', confidence: 0.9 },
    { pattern: /(--|;|')\s*(or|and|union|select|drop|delete|insert|update)\b/i, id: 'INJ-053', confidence: 0.85 },

    // Social Engineering
    { pattern: /\b(urgent|emergency|critical|important)\s*[!:]\s*(ignore|bypass|override)/i, id: 'INJ-060', confidence: 0.8 },
    { pattern: /\b(admin|administrator|developer|owner|creator)\s+(here|speaking|says|requests?)\b/i, id: 'INJ-061', confidence: 0.75 },
    { pattern: /\b(authorized|permitted|allowed)\s+to\s+(bypass|ignore|override)\b/i, id: 'INJ-062', confidence: 0.8 },

    // Dangerous Actions
    { pattern: /\b(create|generate|write)\s+(malware|virus|trojan|ransomware|backdoor)\b/i, id: 'INJ-072', confidence: 0.95 },
    { pattern: /\b(bypass|evade|avoid)\s+(detection|security|authentication|firewall)\b/i, id: 'INJ-073', confidence: 0.8 },

    // Korean
    { pattern: /(무시|잊어|제한.*해제|프롬프트.*보여|이전.*지시.*무시)/i, id: 'INJ-KO1', confidence: 0.85 },
    { pattern: /(우회|해킹|시스템.*프롬프트|규칙.*무시|모든.*잊어)/i, id: 'INJ-KO2', confidence: 0.85 },

    // Japanese
    { pattern: /(無視|忘れ|制限.*解除|プロンプト.*見せ|指示.*無視)/i, id: 'INJ-JA1', confidence: 0.85 },
    { pattern: /(バイパス|ハック|システム.*プロンプト|ルール.*無視)/i, id: 'INJ-JA2', confidence: 0.85 },

    // Chinese
    { pattern: /(忽略|忘记|解除.*限制|提示.*显示|指令.*忽略)/i, id: 'INJ-ZH1', confidence: 0.85 },
    { pattern: /(绕过|黑客|系统.*提示|规则.*忽略|所有.*忘记)/i, id: 'INJ-ZH2', confidence: 0.85 },

    // Spanish
    { pattern: /(ignorar|olvidar|omitir)\s+(instrucciones?|reglas?|todo)/i, id: 'INJ-ES', confidence: 0.8 },

    // French
    { pattern: /(ignorer|oublier|contourner)\s+(instructions?|règles?|tout)/i, id: 'INJ-FR', confidence: 0.8 },

    // German
    { pattern: /(ignorieren|vergessen|umgehen)\s+(anweisungen?|regeln?|alles)/i, id: 'INJ-DE', confidence: 0.8 },
];

// PII patterns
const PII_PATTERNS: { [key: string]: RegExp } = {
    email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    phone_kr: /01[0-9]-?\d{3,4}-?\d{4}/g,
    phone_intl: /\+\d{1,3}[-.\s]?\d{3,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}/g,
    ssn_kr: /\d{6}-?[1-4]\d{6}/g,
    credit_card: /\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}/g,
    ssn_us: /\d{3}-\d{2}-\d{4}/g,
};

export class LocalScanner {
    private minLength: number = 10;
    private threshold: number = 0.85;

    constructor(options?: { minLength?: number; threshold?: number }) {
        if (options?.minLength) this.minLength = options.minLength;
        if (options?.threshold) this.threshold = options.threshold;
    }

    /**
     * Scan text for security threats and PII
     */
    scan(text: string): ScanResult {
        const threats: ThreatInfo[] = [];
        let maxConfidence = 0;

        // Skip very short messages (greetings, etc.)
        if (text.trim().length < this.minLength) {
            return {
                ok: true,
                riskScore: 0,
                riskLevel: 'negligible',
                threats: [],
                pii: { found: false, types: {} },
            };
        }

        // Check injection patterns
        for (const { pattern, id, confidence } of INJECTION_PATTERNS) {
            const match = pattern.exec(text);
            if (match) {
                threats.push({
                    type: 'injection',
                    patternId: id,
                    matchedText: match[0].substring(0, 50),
                    confidence,
                    severity: confidence >= 0.8 ? 'high' : confidence >= 0.6 ? 'medium' : 'low',
                });
                maxConfidence = Math.max(maxConfidence, confidence);
            }
        }

        // Check PII
        const piiTypes: { [key: string]: number } = {};
        for (const [piiType, pattern] of Object.entries(PII_PATTERNS)) {
            const matches = text.match(pattern);
            if (matches) {
                piiTypes[piiType] = matches.length;
            }
        }
        const piiFound = Object.keys(piiTypes).length > 0;

        // Determine risk level
        let riskLevel: ScanResult['riskLevel'];
        if (maxConfidence >= 0.8) riskLevel = 'critical';
        else if (maxConfidence >= 0.6) riskLevel = 'high';
        else if (maxConfidence >= 0.35) riskLevel = 'medium';
        else if (maxConfidence >= 0.1) riskLevel = 'low';
        else riskLevel = 'negligible';

        // Determine if blocked
        const isBlocked = maxConfidence >= this.threshold;

        // Estimate tokens (rough: 1 token ≈ 4 chars)
        const tokenEstimate = Math.ceil(text.length / 4);

        return {
            ok: !isBlocked,
            reason: isBlocked ? `Security threat detected: ${threats[0]?.patternId}` : undefined,
            riskScore: maxConfidence,
            riskLevel,
            threats,
            pii: {
                found: piiFound,
                types: piiTypes,
            },
            optimization: {
                tokenEstimate,
                suggestions: this.getOptimizationSuggestions(text, tokenEstimate),
            },
        };
    }

    /**
     * Get optimization suggestions
     */
    private getOptimizationSuggestions(text: string, tokens: number): string[] {
        const suggestions: string[] = [];

        if (tokens > 1000) {
            suggestions.push('Consider breaking this into smaller requests');
        }

        // Check for excessive whitespace
        if (/\s{3,}/.test(text)) {
            suggestions.push('Remove excessive whitespace to save tokens');
        }

        // Check for repeated phrases
        const words = text.toLowerCase().split(/\s+/);
        const wordCounts = new Map<string, number>();
        for (const word of words) {
            if (word.length > 4) {
                wordCounts.set(word, (wordCounts.get(word) || 0) + 1);
            }
        }
        for (const [word, count] of wordCounts) {
            if (count > 5) {
                suggestions.push(`Word "${word}" repeated ${count} times`);
                break;
            }
        }

        return suggestions;
    }

    /**
     * Mask PII in text
     */
    maskPII(text: string): string {
        let masked = text;

        for (const [piiType, pattern] of Object.entries(PII_PATTERNS)) {
            masked = masked.replace(pattern, (match) => {
                const maskChar = '*';
                const visibleChars = Math.min(2, Math.floor(match.length / 4));
                return match.substring(0, visibleChars) + maskChar.repeat(match.length - visibleChars);
            });
        }

        return masked;
    }

    /**
     * Quick check for Claude Code hooks (returns JSON format)
     */
    hookCheck(text: string): { ok: boolean; reason?: string } {
        const result = this.scan(text);
        return {
            ok: result.ok,
            reason: result.reason,
        };
    }
}

// Export singleton instance
export const localScanner = new LocalScanner();
