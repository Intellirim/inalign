import * as vscode from 'vscode';
import { StatusBarManager } from './statusBar';
import { ProxyClient } from './proxyClient';
import { DashboardPanel } from './dashboard';
import { HooksManager } from './hooksManager';
import { localScanner } from './localScanner';

let statusBarManager: StatusBarManager;
let proxyClient: ProxyClient;
let hooksManager: HooksManager;

// Stats for local scanning (when proxy not available)
let localStats = {
    scanned: 0,
    blocked: 0,
    piiMasked: 0,
    tokensEstimated: 0,
};

export async function activate(context: vscode.ExtensionContext) {
    console.log('In-A-Lign AI Guard is now active!');

    // Initialize proxy client
    const config = vscode.workspace.getConfiguration('inalign');
    const proxyUrl = config.get<string>('proxyUrl') || 'http://localhost:8080';
    proxyClient = new ProxyClient(proxyUrl);

    // Initialize status bar
    statusBarManager = new StatusBarManager(proxyClient);
    context.subscriptions.push(statusBarManager);

    // Initialize hooks manager (for Claude Code integration)
    hooksManager = new HooksManager();

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('inalign.showStats', () => {
            showStatsQuickPick();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('inalign.showDashboard', () => {
            DashboardPanel.createOrShow(context.extensionUri, proxyClient);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('inalign.toggleProxy', async () => {
            await toggleProxy();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('inalign.setupHooks', async () => {
            await hooksManager.setupClaudeHooks();
            vscode.window.showInformationMessage('In-A-Lign: Claude Code hooks configured!');
        })
    );

    // New: Local scan command (for testing)
    context.subscriptions.push(
        vscode.commands.registerCommand('inalign.scanSelection', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showWarningMessage('No active editor');
                return;
            }

            const selection = editor.selection;
            const text = editor.document.getText(selection);

            if (!text) {
                vscode.window.showWarningMessage('No text selected');
                return;
            }

            const result = localScanner.scan(text);
            localStats.scanned++;
            localStats.tokensEstimated += result.optimization?.tokenEstimate || 0;

            if (!result.ok) {
                localStats.blocked++;
                vscode.window.showErrorMessage(
                    `In-A-Lign: Security threat detected! ${result.reason}`
                );
            } else if (result.pii.found) {
                localStats.piiMasked++;
                const piiTypes = Object.keys(result.pii.types).join(', ');
                vscode.window.showWarningMessage(
                    `In-A-Lign: PII detected (${piiTypes}). Consider masking before sending.`
                );
            } else {
                vscode.window.showInformationMessage(
                    `In-A-Lign: Safe! Risk: ${result.riskLevel}, Tokens: ~${result.optimization?.tokenEstimate}`
                );
            }
        })
    );

    // New: Setup local-only mode (no proxy needed)
    context.subscriptions.push(
        vscode.commands.registerCommand('inalign.setupLocalMode', async () => {
            await hooksManager.setupLocalHooks();
            vscode.window.showInformationMessage(
                'In-A-Lign: Local security mode enabled! No proxy required.'
            );
        })
    );

    // Start polling for stats
    if (config.get<boolean>('showStatusBar')) {
        statusBarManager.startPolling(config.get<number>('pollInterval') || 5000);
    }

    // Check proxy connection (non-blocking)
    checkProxyConnection();

    // Check if this is first activation
    const hasSetupHooks = context.globalState.get('hasSetupHooks');
    if (!hasSetupHooks) {
        const answer = await vscode.window.showInformationMessage(
            'In-A-Lign: Set up security protection?',
            'Local Mode (Fast)', 'Proxy Mode', 'Later'
        );
        if (answer === 'Local Mode (Fast)') {
            await hooksManager.setupLocalHooks();
            context.globalState.update('hasSetupHooks', true);
            vscode.window.showInformationMessage('In-A-Lign: Local security enabled!');
        } else if (answer === 'Proxy Mode') {
            await hooksManager.setupClaudeHooks();
            context.globalState.update('hasSetupHooks', true);
        }
    }
}

async function checkProxyConnection() {
    try {
        const health = await proxyClient.getHealth();
        if (health.status === 'healthy') {
            vscode.window.showInformationMessage(
                `In-A-Lign: Proxy connected! ${health.stats.attacks_blocked} attacks blocked.`
            );
        }
    } catch (error) {
        statusBarManager.setOffline();
        // Don't show warning - local mode works fine without proxy
        console.log('In-A-Lign: Proxy not running, using local mode');
    }
}

async function showStatsQuickPick() {
    try {
        // Try proxy stats first
        const stats = await proxyClient.getStats();
        const items = [
            `Attacks Blocked: ${stats.attacks_blocked}`,
            `PII Masked: ${stats.pii_masked}`,
            `Cached Responses: ${stats.cached_responses}`,
            `Tokens Saved: ${stats.tokens_saved}`,
            `Cost Saved: $${stats.cost_saved_usd.toFixed(4)}`,
            `---`,
            `Mode: Proxy (${stats.security_features.injection_detector})`,
        ];

        vscode.window.showQuickPick(items, {
            placeHolder: 'In-A-Lign Statistics (Proxy Mode)',
            canPickMany: false,
        });
    } catch (error) {
        // Fall back to local stats
        const items = [
            `Scanned: ${localStats.scanned}`,
            `Blocked: ${localStats.blocked}`,
            `PII Found: ${localStats.piiMasked}`,
            `Tokens Estimated: ${localStats.tokensEstimated}`,
            `---`,
            `Mode: Local (No Proxy)`,
        ];

        vscode.window.showQuickPick(items, {
            placeHolder: 'In-A-Lign Statistics (Local Mode)',
            canPickMany: false,
        });
    }
}

async function toggleProxy() {
    const config = vscode.workspace.getConfiguration('inalign');
    const currentState = config.get<boolean>('enabled') ?? true;

    await config.update('enabled', !currentState, vscode.ConfigurationTarget.Global);

    if (!currentState) {
        statusBarManager.startPolling();
        vscode.window.showInformationMessage('In-A-Lign: Proxy enabled');
    } else {
        statusBarManager.stopPolling();
        vscode.window.showInformationMessage('In-A-Lign: Proxy disabled');
    }
}

export function deactivate() {
    statusBarManager?.dispose();
}
