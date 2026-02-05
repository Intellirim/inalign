/**
 * In-A-Lign Browser Extension - Background Service Worker
 */

// Initialize default stats
chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.local.set({
        inalign_stats: {
            scanned: 0,
            blocked: 0,
            piiMasked: 0,
            tokensEstimated: 0
        },
        inalign_config: {
            enabled: true,
            blockThreshold: 0.85,
            showWarnings: true,
            autoPIIMask: true,
            showTokenCount: true
        }
    });

    console.log('In-A-Lign AI Guard installed');
});

// Handle messages from popup or content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getStats') {
        chrome.storage.local.get(['inalign_stats'], (result) => {
            sendResponse(result.inalign_stats || {
                scanned: 0,
                blocked: 0,
                piiMasked: 0,
                tokensEstimated: 0
            });
        });
        return true; // Will respond asynchronously
    }

    if (request.action === 'resetStats') {
        const emptyStats = {
            scanned: 0,
            blocked: 0,
            piiMasked: 0,
            tokensEstimated: 0
        };
        chrome.storage.local.set({ inalign_stats: emptyStats });
        sendResponse(emptyStats);
        return true;
    }

    if (request.action === 'getConfig') {
        chrome.storage.local.get(['inalign_config'], (result) => {
            sendResponse(result.inalign_config);
        });
        return true;
    }

    if (request.action === 'updateConfig') {
        chrome.storage.local.get(['inalign_config'], (result) => {
            const newConfig = { ...result.inalign_config, ...request.config };
            chrome.storage.local.set({ inalign_config: newConfig });
            sendResponse(newConfig);
        });
        return true;
    }
});

// Badge update based on blocked count
function updateBadge() {
    chrome.storage.local.get(['inalign_stats'], (result) => {
        const stats = result.inalign_stats;
        if (stats && stats.blocked > 0) {
            chrome.action.setBadgeText({ text: stats.blocked.toString() });
            chrome.action.setBadgeBackgroundColor({ color: '#ff4444' });
        } else {
            chrome.action.setBadgeText({ text: '' });
        }
    });
}

// Listen for storage changes to update badge
chrome.storage.onChanged.addListener((changes, namespace) => {
    if (namespace === 'local' && changes.inalign_stats) {
        updateBadge();
    }
});
