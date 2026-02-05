import * as vscode from 'vscode';
import { ProxyClient, ProxyStats } from './proxyClient';

export class StatusBarManager implements vscode.Disposable {
    private statusBarItem: vscode.StatusBarItem;
    private proxyClient: ProxyClient;
    private pollTimer: NodeJS.Timeout | null = null;
    private isOnline: boolean = false;

    constructor(proxyClient: ProxyClient) {
        this.proxyClient = proxyClient;

        // Create status bar item on the right side
        this.statusBarItem = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Right,
            100
        );

        this.statusBarItem.command = 'inalign.showDashboard';
        this.statusBarItem.tooltip = 'Click to open In-A-Lign Dashboard';
        this.setOffline();
        this.statusBarItem.show();
    }

    startPolling(intervalMs: number = 5000) {
        if (this.pollTimer) {
            clearInterval(this.pollTimer);
        }

        // Initial fetch
        this.updateStats();

        // Start polling
        this.pollTimer = setInterval(() => {
            this.updateStats();
        }, intervalMs);
    }

    stopPolling() {
        if (this.pollTimer) {
            clearInterval(this.pollTimer);
            this.pollTimer = null;
        }
    }

    private async updateStats() {
        try {
            const stats = await this.proxyClient.getStats();
            this.setOnline(stats);
        } catch (error) {
            this.setOffline();
        }
    }

    setOnline(stats: ProxyStats) {
        this.isOnline = true;

        // Create a compact status line
        const blocked = stats.attacks_blocked;
        const saved = stats.tokens_saved;
        const pii = stats.pii_masked;

        // Use icons for compact display
        // 🛡️ = security, ⚡ = efficiency, 🔒 = PII
        let text = `$(shield) ${blocked}`;

        if (saved > 0) {
            text += ` $(zap) ${this.formatNumber(saved)}`;
        }

        if (pii > 0) {
            text += ` $(lock) ${pii}`;
        }

        this.statusBarItem.text = text;
        this.statusBarItem.backgroundColor = undefined;
        this.statusBarItem.tooltip = this.createTooltip(stats);
    }

    setOffline() {
        this.isOnline = false;
        this.statusBarItem.text = '$(shield) Offline';
        this.statusBarItem.backgroundColor = new vscode.ThemeColor(
            'statusBarItem.warningBackground'
        );
        this.statusBarItem.tooltip = 'In-A-Lign: Proxy server not connected\nClick to open dashboard';
    }

    private createTooltip(stats: ProxyStats): string {
        return `In-A-Lign AI Guard
━━━━━━━━━━━━━━━━━━
🛡️ Attacks Blocked: ${stats.attacks_blocked}
🔒 PII Masked: ${stats.pii_masked}
⚡ Tokens Saved: ${this.formatNumber(stats.tokens_saved)}
💰 Cost Saved: $${stats.cost_saved_usd.toFixed(4)}
📊 Total Requests: ${stats.total_requests}
📦 Cached: ${stats.cached_responses}
━━━━━━━━━━━━━━━━━━
Security: ${stats.security_features.injection_detector}
Click to open dashboard`;
    }

    private formatNumber(num: number): string {
        if (num >= 1000000) {
            return (num / 1000000).toFixed(1) + 'M';
        }
        if (num >= 1000) {
            return (num / 1000).toFixed(1) + 'K';
        }
        return num.toString();
    }

    dispose() {
        this.stopPolling();
        this.statusBarItem.dispose();
    }
}
