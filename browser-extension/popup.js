/**
 * In-A-Lign Browser Extension - Popup Script
 */

document.addEventListener('DOMContentLoaded', () => {
    loadStats();
    loadConfig();
    detectCurrentLLM();

    document.getElementById('resetBtn').addEventListener('click', resetStats);
    document.getElementById('securityEnabled').addEventListener('change', updateConfig);
    document.getElementById('autoOptimize').addEventListener('change', updateConfig);
    document.getElementById('piiMaskEnabled').addEventListener('change', updateConfig);
    document.getElementById('tokenCountEnabled').addEventListener('change', updateConfig);
});

function loadStats() {
    chrome.runtime.sendMessage({ action: 'getStats' }, (stats) => {
        if (stats) {
            document.getElementById('scanned').textContent = formatNumber(stats.scanned || 0);
            document.getElementById('blocked').textContent = formatNumber(stats.blocked || 0);
            document.getElementById('piiMasked').textContent = formatNumber(stats.piiMasked || 0);
            document.getElementById('optimized').textContent = formatNumber(stats.promptsOptimized || 0);
            document.getElementById('tokens').textContent = formatNumber(stats.tokensEstimated || 0);
        }
    });
}

function loadConfig() {
    chrome.runtime.sendMessage({ action: 'getConfig' }, (config) => {
        if (config) {
            document.getElementById('securityEnabled').checked = config.enabled !== false;
            document.getElementById('autoOptimize').checked = config.autoOptimize === true;
            document.getElementById('piiMaskEnabled').checked = config.autoPIIMask !== false;
            document.getElementById('tokenCountEnabled').checked = config.showTokenCount !== false;
        }
    });
}

function detectCurrentLLM() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0] && tabs[0].url) {
            const url = tabs[0].url;
            let llm = 'Unknown';
            let icon = '⚪';

            if (url.includes('claude.ai')) {
                llm = 'Claude';
                icon = '🟣';
            } else if (url.includes('chat.openai.com') || url.includes('chatgpt.com')) {
                llm = 'ChatGPT';
                icon = '🟢';
            } else if (url.includes('gemini.google.com')) {
                llm = 'Gemini';
                icon = '🔵';
            } else if (url.includes('perplexity.ai')) {
                llm = 'Perplexity';
                icon = '🟠';
            } else if (url.includes('copilot.microsoft.com')) {
                llm = 'Copilot';
                icon = '🔷';
            }

            document.getElementById('currentLLM').textContent = `${icon} ${llm}`;

            // Highlight active LLM icon
            const icons = document.querySelectorAll('.llm-icon');
            icons.forEach(i => i.classList.remove('active'));
            const llmMap = {
                'Claude': 0,
                'ChatGPT': 1,
                'Gemini': 2,
                'Perplexity': 3,
                'Copilot': 4
            };
            if (llmMap[llm] !== undefined) {
                icons[llmMap[llm]].classList.add('active');
            }
        }
    });
}

function updateConfig() {
    const config = {
        enabled: document.getElementById('securityEnabled').checked,
        autoOptimize: document.getElementById('autoOptimize').checked,
        autoPIIMask: document.getElementById('piiMaskEnabled').checked,
        showTokenCount: document.getElementById('tokenCountEnabled').checked
    };

    chrome.runtime.sendMessage({ action: 'updateConfig', config });

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) {
            chrome.tabs.sendMessage(tabs[0].id, { action: 'updateConfig', config });
        }
    });
}

function resetStats() {
    chrome.runtime.sendMessage({ action: 'resetStats' }, () => {
        loadStats();
    });
}

function formatNumber(num) {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
}
