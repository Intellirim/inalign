/**
 * In-A-Lign Browser Extension - Content Script
 * Security + Prompt Optimization for all LLMs
 */

(function() {
    'use strict';

    // ==================== CONFIGURATION ====================
    const CONFIG = {
        enabled: true,
        blockThreshold: 0.85,
        showWarnings: true,
        autoPIIMask: true,
        showTokenCount: true,
        autoOptimize: true,  // 프롬프트 자동 최적화
        showOptimizeButton: true  // 최적화 버튼 표시
    };

    // ==================== CURRENT LLM DETECTION ====================
    function detectCurrentLLM() {
        const hostname = window.location.hostname;
        if (hostname.includes('claude.ai')) return 'claude';
        if (hostname.includes('chat.openai.com') || hostname.includes('chatgpt.com')) return 'chatgpt';
        if (hostname.includes('gemini.google.com')) return 'gemini';
        if (hostname.includes('perplexity.ai')) return 'perplexity';
        if (hostname.includes('copilot.microsoft.com')) return 'copilot';
        return 'generic';
    }

    const CURRENT_LLM = detectCurrentLLM();

    // ==================== PROMPT OPTIMIZER ====================
    const PromptOptimizer = {
        // 태스크 유형 감지
        detectTaskType(text) {
            const lower = text.toLowerCase();

            if (/코드|code|프로그램|script|함수|function|클래스|class/i.test(text)) return 'coding';
            if (/번역|translate|translation/i.test(text)) return 'translation';
            if (/요약|summarize|summary|정리/i.test(text)) return 'summarize';
            if (/설명|explain|알려|tell me|what is|뭐야|무엇/i.test(text)) return 'explain';
            if (/작성|write|써줘|만들어|create|generate/i.test(text)) return 'writing';
            if (/분석|analyze|analysis|검토|review/i.test(text)) return 'analysis';
            if (/비교|compare|차이|difference/i.test(text)) return 'compare';
            if (/추천|recommend|suggest|best/i.test(text)) return 'recommend';
            if (/검색|search|찾아|find/i.test(text)) return 'search';

            return 'general';
        },

        // 언어 감지
        detectLanguage(text) {
            if (/[가-힣]/.test(text)) return 'ko';
            if (/[ひらがなカタカナ]/.test(text) || /[\u4E00-\u9FAF]/.test(text) && /[の|は|が|を]/.test(text)) return 'ja';
            if (/[\u4E00-\u9FAF]/.test(text)) return 'zh';
            return 'en';
        },

        // 핵심 키워드 추출
        extractKeywords(text) {
            // 불용어 제거
            const stopwords = ['the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
                             '은', '는', '이', '가', '을', '를', '의', '에', '에서', '으로', '로',
                             '좀', '해줘', '해주세요', '알려줘', '알려주세요', 'please', 'can', 'you'];

            const words = text.split(/\s+/).filter(w =>
                w.length > 1 && !stopwords.includes(w.toLowerCase())
            );

            return words.slice(0, 10);
        },

        // Claude 최적화
        optimizeForClaude(text, taskType, lang) {
            const keywords = this.extractKeywords(text);

            const templates = {
                coding: {
                    ko: `다음 요구사항에 맞는 코드를 작성해주세요:

**요구사항:** ${text}

**조건:**
- 깔끔하고 읽기 쉬운 코드
- 주석으로 주요 로직 설명
- 에러 핸들링 포함
- 모범 사례(best practices) 적용`,
                    en: `Please write code for the following requirement:

**Requirement:** ${text}

**Guidelines:**
- Clean, readable code
- Comments explaining key logic
- Include error handling
- Follow best practices`
                },
                explain: {
                    ko: `다음에 대해 명확하게 설명해주세요:

**주제:** ${text}

다음 형식으로 답변해주세요:
1. 핵심 개념 (한 문장)
2. 상세 설명
3. 실제 예시
4. 주의사항 (있다면)`,
                    en: `Please explain the following clearly:

**Topic:** ${text}

Format your response as:
1. Core concept (one sentence)
2. Detailed explanation
3. Practical example
4. Caveats (if any)`
                },
                writing: {
                    ko: `다음 내용을 작성해주세요:

**요청:** ${text}

**스타일 가이드:**
- 명확하고 간결한 문체
- 논리적 구조
- 구체적인 내용`,
                    en: `Please write the following:

**Request:** ${text}

**Style guide:**
- Clear and concise
- Logical structure
- Specific content`
                },
                general: {
                    ko: `${text}

명확하고 구조화된 형식으로 답변해주세요.`,
                    en: `${text}

Please respond in a clear, structured format.`
                }
            };

            const template = templates[taskType] || templates.general;
            return template[lang] || template.en;
        },

        // ChatGPT 최적화
        optimizeForChatGPT(text, taskType, lang) {
            const templates = {
                coding: {
                    ko: `당신은 시니어 소프트웨어 개발자입니다.

**작업:** ${text}

요구사항:
1. 프로덕션 수준의 코드 작성
2. 타입 힌트 및 문서화 포함
3. 테스트 케이스 예시 제공
4. 시간/공간 복잡도 설명`,
                    en: `You are a senior software developer.

**Task:** ${text}

Requirements:
1. Production-quality code
2. Include type hints and documentation
3. Provide test case examples
4. Explain time/space complexity`
                },
                explain: {
                    ko: `당신은 전문 교육자입니다.

**설명할 주제:** ${text}

다음을 포함해 설명해주세요:
- ELI5 (쉬운 설명)
- 기술적 세부사항
- 실제 활용 사례`,
                    en: `You are an expert educator.

**Topic to explain:** ${text}

Include in your explanation:
- ELI5 (simple explanation)
- Technical details
- Real-world applications`
                },
                general: {
                    ko: `${text}

단계별로 체계적으로 답변해주세요.`,
                    en: `${text}

Please respond systematically, step by step.`
                }
            };

            const template = templates[taskType] || templates.general;
            return template[lang] || template.en;
        },

        // Perplexity 최적화 (검색 중심)
        optimizeForPerplexity(text, taskType, lang) {
            const keywords = this.extractKeywords(text);

            // Perplexity는 검색 엔진이므로 간결한 쿼리가 효과적
            const templates = {
                search: {
                    ko: `${keywords.join(' ')} 최신 정보 2024`,
                    en: `${keywords.join(' ')} latest 2024`
                },
                coding: {
                    ko: `${keywords.join(' ')} 코드 예제 best practices 2024`,
                    en: `${keywords.join(' ')} code example best practices 2024`
                },
                explain: {
                    ko: `${keywords.join(' ')} 설명 개념 정의`,
                    en: `${keywords.join(' ')} explanation concept definition`
                },
                compare: {
                    ko: `${keywords.join(' ')} 비교 장단점 차이점`,
                    en: `${keywords.join(' ')} comparison pros cons differences`
                },
                general: {
                    ko: `${text}`,
                    en: `${text}`
                }
            };

            const template = templates[taskType] || templates.general;
            return template[lang] || template.en;
        },

        // Gemini 최적화
        optimizeForGemini(text, taskType, lang) {
            const templates = {
                coding: {
                    ko: `코드 작성 요청:

작업: ${text}

출력 형식:
1. 완성된 코드
2. 코드 설명
3. 사용 예시`,
                    en: `Code request:

Task: ${text}

Output format:
1. Complete code
2. Code explanation
3. Usage example`
                },
                general: {
                    ko: `${text}

상세하고 정확하게 답변해주세요.`,
                    en: `${text}

Please provide a detailed and accurate response.`
                }
            };

            const template = templates[taskType] || templates.general;
            return template[lang] || template.en;
        },

        // 메인 최적화 함수
        optimize(text, llm = CURRENT_LLM) {
            if (!text || text.trim().length < 5) return text;

            const taskType = this.detectTaskType(text);
            const lang = this.detectLanguage(text);

            let optimized;
            switch (llm) {
                case 'claude':
                    optimized = this.optimizeForClaude(text, taskType, lang);
                    break;
                case 'chatgpt':
                    optimized = this.optimizeForChatGPT(text, taskType, lang);
                    break;
                case 'perplexity':
                    optimized = this.optimizeForPerplexity(text, taskType, lang);
                    break;
                case 'gemini':
                    optimized = this.optimizeForGemini(text, taskType, lang);
                    break;
                default:
                    optimized = this.optimizeForClaude(text, taskType, lang); // Claude as default
            }

            return optimized;
        },

        // 미리보기 생성
        preview(text, llm = CURRENT_LLM) {
            const optimized = this.optimize(text, llm);
            const originalTokens = Math.ceil(text.length / 4);
            const optimizedTokens = Math.ceil(optimized.length / 4);

            return {
                original: text,
                optimized: optimized,
                originalTokens,
                optimizedTokens,
                llm,
                taskType: this.detectTaskType(text)
            };
        }
    };

    // ==================== INJECTION PATTERNS ====================
    const INJECTION_PATTERNS = [
        { pattern: /\bignore\b.*\b(previous|above|prior|all)\b.*\b(instructions?|rules?)\b/i, id: 'INJ-001', score: 0.9 },
        { pattern: /\b(forget|disregard)\b.*\b(everything|all|instructions?|rules?)\b/i, id: 'INJ-002', score: 0.85 },
        { pattern: /\b(override|replace|cancel)\b.*\b(instructions?|rules?|prompts?)\b/i, id: 'INJ-003', score: 0.85 },
        { pattern: /\b(system|initial|hidden|secret)\s*(prompt|instruction|rules?)\b/i, id: 'INJ-010', score: 0.85 },
        { pattern: /\b(show|reveal|display|expose)\b.*\b(prompt|instruction|config)\b/i, id: 'INJ-011', score: 0.8 },
        { pattern: /\b(you\s+are\s+now|become)\s+(dan|evil|unrestricted|jailbreak)\b/i, id: 'INJ-020', score: 0.95 },
        { pattern: /\b(developer|debug|sudo|admin|god)\s*mode\b/i, id: 'INJ-021', score: 0.9 },
        { pattern: /\bjailbreak\b/i, id: 'INJ-023', score: 0.9 },
        { pattern: /\b(create|generate|write)\s+(malware|virus|trojan|ransomware)\b/i, id: 'INJ-072', score: 0.95 },
        { pattern: /(무시|잊어|시스템.*프롬프트|우회|해킹)/i, id: 'INJ-KO', score: 0.85 },
        { pattern: /(無視|忘れ|制限.*解除)/i, id: 'INJ-JA', score: 0.85 },
        { pattern: /(忽略|忘记|解除.*限制)/i, id: 'INJ-ZH', score: 0.85 },
    ];

    // ==================== PII PATTERNS ====================
    const PII_PATTERNS = {
        email: { pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, mask: '[EMAIL]' },
        phone_kr: { pattern: /01[0-9]-?\d{3,4}-?\d{4}/g, mask: '[PHONE]' },
        phone_intl: { pattern: /\+\d{1,3}[-.\s]?\d{3,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}/g, mask: '[PHONE]' },
        ssn_kr: { pattern: /\d{6}-?[1-4]\d{6}/g, mask: '[SSN]' },
        credit_card: { pattern: /\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}/g, mask: '[CARD]' },
        ssn_us: { pattern: /\d{3}-\d{2}-\d{4}/g, mask: '[SSN]' },
    };

    // ==================== STATS ====================
    let stats = {
        scanned: 0,
        blocked: 0,
        piiMasked: 0,
        tokensEstimated: 0,
        promptsOptimized: 0
    };

    if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.get(['inalign_stats'], (result) => {
            if (result.inalign_stats) stats = { ...stats, ...result.inalign_stats };
        });
    }

    function saveStats() {
        if (typeof chrome !== 'undefined' && chrome.storage) {
            chrome.storage.local.set({ inalign_stats: stats });
        }
    }

    // ==================== DETECTION FUNCTIONS ====================
    function detectInjection(text) {
        if (!text || text.trim().length < 10) return { isAttack: false, score: 0, id: null };

        let maxScore = 0;
        let matchedId = null;

        for (const { pattern, id, score } of INJECTION_PATTERNS) {
            if (pattern.test(text)) {
                if (score > maxScore) {
                    maxScore = score;
                    matchedId = id;
                }
            }
        }

        return { isAttack: maxScore >= CONFIG.blockThreshold, score: maxScore, id: matchedId };
    }

    function detectAndMaskPII(text) {
        let masked = text;
        let count = 0;

        for (const [type, { pattern, mask }] of Object.entries(PII_PATTERNS)) {
            const matches = masked.match(pattern);
            if (matches) {
                count += matches.length;
                masked = masked.replace(pattern, mask);
            }
        }

        return { masked, count };
    }

    function estimateTokens(text) {
        return Math.ceil(text.length / 4);
    }

    // ==================== UI FUNCTIONS ====================
    function showNotification(message, type = 'info') {
        const existing = document.getElementById('inalign-notification');
        if (existing) existing.remove();

        const notification = document.createElement('div');
        notification.id = 'inalign-notification';
        notification.className = `inalign-notification inalign-${type}`;
        notification.innerHTML = `
            <div class="inalign-notification-content">
                <span class="inalign-icon">${type === 'blocked' ? '🛡️' : type === 'warning' ? '⚠️' : type === 'success' ? '✨' : 'ℹ️'}</span>
                <span class="inalign-message">${message}</span>
                <button class="inalign-close">&times;</button>
            </div>
        `;

        document.body.appendChild(notification);
        notification.querySelector('.inalign-close').addEventListener('click', () => notification.remove());
        setTimeout(() => notification.parentNode && notification.remove(), 5000);
    }

    function showTokenBadge(input, tokens, optimized = false) {
        let badge = input.parentElement?.querySelector('.inalign-token-badge');
        if (!badge && input.parentElement) {
            badge = document.createElement('div');
            badge.className = 'inalign-token-badge';
            input.parentElement.style.position = 'relative';
            input.parentElement.appendChild(badge);
        }
        if (badge) {
            badge.textContent = optimized ? `✨ ~${tokens} tokens` : `~${tokens} tokens`;
            badge.style.background = optimized ? 'rgba(34, 197, 94, 0.9)' : 'rgba(0, 0, 0, 0.7)';
        }
    }

    function createOptimizeButton(input) {
        if (!CONFIG.showOptimizeButton) return;

        let btn = input.parentElement?.querySelector('.inalign-optimize-btn');
        if (!btn && input.parentElement) {
            btn = document.createElement('button');
            btn.className = 'inalign-optimize-btn';
            btn.innerHTML = '✨ 최적화';
            btn.title = 'In-A-Lign: 프롬프트 최적화';
            btn.style.cssText = `
                position: absolute;
                bottom: 8px;
                right: 100px;
                background: linear-gradient(135deg, #4a90d9, #357abd);
                color: white;
                border: none;
                padding: 4px 12px;
                border-radius: 12px;
                font-size: 12px;
                cursor: pointer;
                z-index: 100;
                font-family: -apple-system, BlinkMacSystemFont, sans-serif;
                transition: transform 0.2s, box-shadow 0.2s;
            `;

            btn.addEventListener('mouseenter', () => {
                btn.style.transform = 'scale(1.05)';
                btn.style.boxShadow = '0 2px 8px rgba(74, 144, 217, 0.4)';
            });
            btn.addEventListener('mouseleave', () => {
                btn.style.transform = 'scale(1)';
                btn.style.boxShadow = 'none';
            });

            btn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();

                const text = input.innerText || input.value || '';
                if (text.trim().length < 5) {
                    showNotification('텍스트가 너무 짧습니다', 'warning');
                    return;
                }

                const optimized = PromptOptimizer.optimize(text);

                if (input.innerText !== undefined) {
                    input.innerText = optimized;
                } else {
                    input.value = optimized;
                }

                // Trigger input event for frameworks
                input.dispatchEvent(new Event('input', { bubbles: true }));

                stats.promptsOptimized++;
                saveStats();

                showNotification(`✨ ${CURRENT_LLM.toUpperCase()}에 최적화됨!`, 'success');
                showTokenBadge(input, estimateTokens(optimized), true);
            });

            input.parentElement.appendChild(btn);
        }
    }

    // ==================== MAIN PROCESSING ====================
    function processInput(text, inputElement) {
        stats.scanned++;

        // 1. Security check
        const injection = detectInjection(text);
        if (injection.isAttack) {
            stats.blocked++;
            saveStats();
            showNotification(`🛡️ 보안 위협 차단! (${injection.id})`, 'blocked');
            return { blocked: true, text: null };
        }

        // 2. PII masking
        let processedText = text;
        if (CONFIG.autoPIIMask) {
            const pii = detectAndMaskPII(text);
            if (pii.count > 0) {
                stats.piiMasked += pii.count;
                processedText = pii.masked;
                showNotification(`🔒 ${pii.count}개 개인정보 마스킹됨`, 'warning');
            }
        }

        // 3. Auto-optimize (optional)
        if (CONFIG.autoOptimize && processedText.length > 20) {
            processedText = PromptOptimizer.optimize(processedText);
            stats.promptsOptimized++;
        }

        // 4. Token estimation
        const tokens = estimateTokens(processedText);
        stats.tokensEstimated += tokens;

        if (CONFIG.showTokenCount && inputElement) {
            showTokenBadge(inputElement, tokens, CONFIG.autoOptimize);
        }

        saveStats();
        return { blocked: false, text: processedText };
    }

    // ==================== SITE HANDLERS ====================
    function setupGenericHandler() {
        const observer = new MutationObserver(() => {
            const inputs = document.querySelectorAll(
                '[contenteditable="true"], textarea, input[type="text"]'
            );

            inputs.forEach(input => {
                if (input.dataset.inalignAttached) return;
                input.dataset.inalignAttached = 'true';

                // Create optimize button
                createOptimizeButton(input);

                // Form submission handler
                const form = input.closest('form');
                if (form && !form.dataset.inalignAttached) {
                    form.dataset.inalignAttached = 'true';
                    form.addEventListener('submit', (e) => {
                        const text = input.innerText || input.value || '';
                        const result = processInput(text, input);

                        if (result.blocked) {
                            e.preventDefault();
                            e.stopPropagation();
                            return false;
                        }

                        if (result.text && result.text !== text) {
                            if (input.innerText !== undefined) {
                                input.innerText = result.text;
                            } else {
                                input.value = result.text;
                            }
                            input.dispatchEvent(new Event('input', { bubbles: true }));
                        }
                    }, true);
                }

                // Input handler for token count
                input.addEventListener('input', () => {
                    const text = input.innerText || input.value || '';
                    if (text.length > 0) {
                        showTokenBadge(input, estimateTokens(text));
                    }
                });
            });
        });

        observer.observe(document.body, { childList: true, subtree: true });
    }

    // ==================== INITIALIZE ====================
    function init() {
        console.log(`In-A-Lign AI Guard initialized for ${CURRENT_LLM}`);

        // Add global styles
        const style = document.createElement('style');
        style.textContent = `
            .inalign-notification {
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 999999;
                max-width: 400px;
                border-radius: 12px;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
                animation: inalign-slide-in 0.3s ease-out;
                font-family: -apple-system, BlinkMacSystemFont, sans-serif;
            }
            @keyframes inalign-slide-in {
                from { opacity: 0; transform: translateX(100px); }
                to { opacity: 1; transform: translateX(0); }
            }
            .inalign-notification-content {
                display: flex;
                align-items: center;
                gap: 12px;
                padding: 16px 20px;
            }
            .inalign-icon { font-size: 24px; }
            .inalign-message { flex: 1; font-size: 14px; font-weight: 500; }
            .inalign-close {
                background: none;
                border: none;
                font-size: 20px;
                cursor: pointer;
                opacity: 0.6;
                padding: 0;
            }
            .inalign-close:hover { opacity: 1; }
            .inalign-blocked { background: linear-gradient(135deg, #ff4444, #cc0000); color: white; }
            .inalign-warning { background: linear-gradient(135deg, #ffaa00, #ff8800); color: white; }
            .inalign-info { background: linear-gradient(135deg, #4a90d9, #357abd); color: white; }
            .inalign-success { background: linear-gradient(135deg, #22c55e, #16a34a); color: white; }
            .inalign-token-badge {
                position: absolute;
                bottom: 8px;
                right: 12px;
                background: rgba(0, 0, 0, 0.7);
                color: white;
                font-size: 11px;
                padding: 4px 8px;
                border-radius: 12px;
                pointer-events: none;
                z-index: 100;
                font-family: -apple-system, BlinkMacSystemFont, sans-serif;
            }
        `;
        document.head.appendChild(style);

        // Setup handler
        setupGenericHandler();

        // Message listener
        if (typeof chrome !== 'undefined' && chrome.runtime) {
            chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
                if (request.action === 'getStats') sendResponse(stats);
                if (request.action === 'updateConfig') Object.assign(CONFIG, request.config);
                if (request.action === 'optimizeText') {
                    sendResponse(PromptOptimizer.preview(request.text, request.llm));
                }
            });
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
