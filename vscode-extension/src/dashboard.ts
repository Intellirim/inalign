import * as vscode from 'vscode';
import { ProxyClient } from './proxyClient';

export class DashboardPanel {
    public static currentPanel: DashboardPanel | undefined;
    private static readonly viewType = 'inalignDashboard';

    private readonly panel: vscode.WebviewPanel;
    private readonly extensionUri: vscode.Uri;
    private readonly proxyClient: ProxyClient;
    private disposables: vscode.Disposable[] = [];
    private updateInterval: NodeJS.Timeout | null = null;

    public static createOrShow(extensionUri: vscode.Uri, proxyClient: ProxyClient) {
        const column = vscode.window.activeTextEditor
            ? vscode.window.activeTextEditor.viewColumn
            : undefined;

        if (DashboardPanel.currentPanel) {
            DashboardPanel.currentPanel.panel.reveal(column);
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            DashboardPanel.viewType,
            'In-A-Lign Dashboard',
            column || vscode.ViewColumn.One,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
            }
        );

        DashboardPanel.currentPanel = new DashboardPanel(panel, extensionUri, proxyClient);
    }

    private constructor(
        panel: vscode.WebviewPanel,
        extensionUri: vscode.Uri,
        proxyClient: ProxyClient
    ) {
        this.panel = panel;
        this.extensionUri = extensionUri;
        this.proxyClient = proxyClient;

        this.update();

        // Start auto-refresh
        this.updateInterval = setInterval(() => this.update(), 3000);

        this.panel.onDidDispose(() => this.dispose(), null, this.disposables);

        this.panel.webview.onDidReceiveMessage(
            async (message) => {
                switch (message.command) {
                    case 'refresh':
                        this.update();
                        break;
                    case 'openSettings':
                        vscode.commands.executeCommand('workbench.action.openSettings', 'inalign');
                        break;
                }
            },
            null,
            this.disposables
        );
    }

    private async update() {
        try {
            const stats = await this.proxyClient.getStats();
            const context = await this.proxyClient.getContext().catch(() => null);
            this.panel.webview.html = this.getHtmlForWebview(stats, context);
        } catch (error) {
            this.panel.webview.html = this.getOfflineHtml();
        }
    }

    private getHtmlForWebview(stats: any, context: any): string {
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>In-A-Lign Dashboard</title>
    <style>
        :root {
            --bg-primary: #1e1e1e;
            --bg-secondary: #252526;
            --bg-card: #2d2d30;
            --text-primary: #cccccc;
            --text-secondary: #858585;
            --accent-blue: #007acc;
            --accent-green: #4ec9b0;
            --accent-red: #f14c4c;
            --accent-yellow: #dcdcaa;
            --accent-purple: #c586c0;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 20px;
        }

        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--bg-card);
        }

        .header h1 {
            margin: 0;
            font-size: 24px;
            font-weight: 600;
        }

        .header .status {
            display: flex;
            align-items: center;
            gap: 8px;
            color: var(--accent-green);
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--accent-green);
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .card {
            background: var(--bg-card);
            border-radius: 8px;
            padding: 20px;
        }

        .card-title {
            font-size: 12px;
            text-transform: uppercase;
            color: var(--text-secondary);
            margin-bottom: 8px;
        }

        .card-value {
            font-size: 32px;
            font-weight: 600;
        }

        .card-value.security { color: var(--accent-red); }
        .card-value.efficiency { color: var(--accent-green); }
        .card-value.privacy { color: var(--accent-purple); }
        .card-value.cost { color: var(--accent-yellow); }

        .section {
            background: var(--bg-card);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 16px;
        }

        .section-title {
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 16px;
            color: var(--text-primary);
        }

        .feature-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .feature-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .feature-name {
            color: var(--text-secondary);
        }

        .feature-status {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
        }

        .feature-status.on {
            background: rgba(78, 201, 176, 0.2);
            color: var(--accent-green);
        }

        .feature-status.off {
            background: rgba(241, 76, 76, 0.2);
            color: var(--accent-red);
        }

        .btn {
            padding: 8px 16px;
            border-radius: 4px;
            border: none;
            cursor: pointer;
            font-size: 13px;
        }

        .btn-primary {
            background: var(--accent-blue);
            color: white;
        }

        .btn-primary:hover {
            opacity: 0.9;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ In-A-Lign Dashboard</h1>
        <div class="status">
            <span class="status-dot"></span>
            <span>Connected</span>
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <div class="card-title">Attacks Blocked</div>
            <div class="card-value security">${stats.attacks_blocked}</div>
        </div>
        <div class="card">
            <div class="card-title">Tokens Saved</div>
            <div class="card-value efficiency">${this.formatNumber(stats.tokens_saved)}</div>
        </div>
        <div class="card">
            <div class="card-title">PII Masked</div>
            <div class="card-value privacy">${stats.pii_masked}</div>
        </div>
        <div class="card">
            <div class="card-title">Cost Saved</div>
            <div class="card-value cost">$${stats.cost_saved_usd.toFixed(2)}</div>
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <div class="card-title">Total Requests</div>
            <div class="card-value">${stats.total_requests}</div>
        </div>
        <div class="card">
            <div class="card-title">Cached Responses</div>
            <div class="card-value">${stats.cached_responses}</div>
        </div>
        <div class="card">
            <div class="card-title">Blocked Requests</div>
            <div class="card-value">${stats.blocked_requests}</div>
        </div>
        <div class="card">
            <div class="card-title">Optimizations</div>
            <div class="card-value">${stats.optimizations_applied}</div>
        </div>
    </div>

    <div class="section">
        <div class="section-title">Security Features</div>
        <div class="feature-list">
            <div class="feature-item">
                <span class="feature-name">Injection Detector</span>
                <span class="feature-status ${stats.security_features.injection_detector !== 'disabled' ? 'on' : 'off'}">
                    ${stats.security_features.injection_detector.toUpperCase()}
                </span>
            </div>
            <div class="feature-item">
                <span class="feature-name">PII Detector</span>
                <span class="feature-status ${stats.security_features.pii_detector === 'enabled' ? 'on' : 'off'}">
                    ${stats.security_features.pii_detector.toUpperCase()}
                </span>
            </div>
            <div class="feature-item">
                <span class="feature-name">Context Extractor</span>
                <span class="feature-status ${stats.security_features.context_extractor === 'enabled' ? 'on' : 'off'}">
                    ${stats.security_features.context_extractor.toUpperCase()}
                </span>
            </div>
        </div>
    </div>

    ${context ? `
    <div class="section">
        <div class="section-title">Active Sessions</div>
        <div class="feature-list">
            <div class="feature-item">
                <span class="feature-name">Active Sessions</span>
                <span>${context.active_sessions || 0}</span>
            </div>
            <div class="feature-item">
                <span class="feature-name">Total Interactions</span>
                <span>${context.total_interactions || 0}</span>
            </div>
        </div>
    </div>
    ` : ''}

    <div style="margin-top: 24px; display: flex; gap: 12px;">
        <button class="btn btn-primary" onclick="refresh()">Refresh</button>
        <button class="btn btn-primary" onclick="openSettings()">Settings</button>
    </div>

    <script>
        const vscode = acquireVsCodeApi();

        function refresh() {
            vscode.postMessage({ command: 'refresh' });
        }

        function openSettings() {
            vscode.postMessage({ command: 'openSettings' });
        }
    </script>
</body>
</html>`;
    }

    private getOfflineHtml(): string {
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, sans-serif;
            background: #1e1e1e;
            color: #cccccc;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            text-align: center;
        }
        .offline {
            padding: 40px;
        }
        .offline h2 {
            color: #f14c4c;
            margin-bottom: 16px;
        }
        .offline p {
            color: #858585;
            margin-bottom: 24px;
        }
        code {
            background: #2d2d30;
            padding: 8px 16px;
            border-radius: 4px;
            display: block;
            margin-top: 16px;
        }
    </style>
</head>
<body>
    <div class="offline">
        <h2>🔌 Proxy Server Offline</h2>
        <p>Start the In-A-Lign proxy server to see your dashboard.</p>
        <code>python -m inalign.proxy.server</code>
    </div>
</body>
</html>`;
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

    public dispose() {
        DashboardPanel.currentPanel = undefined;

        if (this.updateInterval) {
            clearInterval(this.updateInterval);
        }

        this.panel.dispose();

        while (this.disposables.length) {
            const disposable = this.disposables.pop();
            if (disposable) {
                disposable.dispose();
            }
        }
    }
}
