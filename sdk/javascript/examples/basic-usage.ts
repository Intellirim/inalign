/**
 * Basic usage example for the AgentShield JavaScript SDK.
 *
 * Run with: npx ts-node examples/basic-usage.ts
 */

import { AgentShield } from "../src";

const AGENT_ID = "customer-support-agent-01";
const SESSION_ID = "sess-abc-123";

async function main() {
  // Initialize the client
  const shield = new AgentShield(
    process.env.AGENTSHIELD_API_KEY || "your-api-key",
    {
      baseUrl: process.env.AGENTSHIELD_BASE_URL || "https://api.agentshield.io",
      timeout: 30000,
    },
  );

  // ----------------------------------------------------------------
  // Step 1: Scan user input before processing
  // ----------------------------------------------------------------
  console.log("[1] Scanning user input...");

  const inputResult = await shield.scanInput({
    text: "My name is John Doe and my SSN is 123-45-6789. Can you help me reset my password?",
    agent_id: AGENT_ID,
    session_id: SESSION_ID,
    metadata: { channel: "web", user_tier: "premium" },
  });

  console.log(`    Safe: ${inputResult.is_safe}`);
  console.log(`    Risk Level: ${inputResult.risk_level}`);
  console.log(`    Risk Score: ${inputResult.risk_score}`);

  if (inputResult.threats.length > 0) {
    console.log("    Threats detected:");
    for (const threat of inputResult.threats) {
      console.log(
        `      - ${threat.type} (severity: ${threat.severity}, confidence: ${threat.confidence})`,
      );
    }
  }

  if (inputResult.pii_detected.length > 0) {
    console.log("    PII detected:");
    for (const pii of inputResult.pii_detected) {
      console.log(`      - ${pii.type}: ${pii.value}`);
    }
  }

  // ----------------------------------------------------------------
  // Step 2: Log agent actions
  // ----------------------------------------------------------------
  console.log("\n[2] Logging agent action...");

  const actionResult = await shield.logAction({
    agent_id: AGENT_ID,
    session_id: SESSION_ID,
    action_type: "tool_call",
    name: "password_reset",
    target: "user_management_api",
    parameters: { user_id: "usr-456", method: "email" },
    result_summary: "Password reset email sent successfully.",
    duration_ms: 234,
    context: { triggered_by: "user_request" },
  });

  console.log(`    Action ID: ${actionResult.action_id}`);
  console.log(`    Status: ${actionResult.status}`);
  console.log(`    Anomalous: ${actionResult.is_anomalous}`);

  if (actionResult.anomalies.length > 0) {
    console.log("    Anomalies detected:");
    for (const anomaly of actionResult.anomalies) {
      console.log(`      - ${anomaly.type}: ${anomaly.description}`);
    }
  }

  // ----------------------------------------------------------------
  // Step 3: Scan agent output before sending to user
  // ----------------------------------------------------------------
  console.log("\n[3] Scanning agent output...");

  const outputResult = await shield.scanOutput({
    text: "Hi John! I've sent a password reset link to your email j.doe@example.com. Your account number is 9876543210.",
    agent_id: AGENT_ID,
    session_id: SESSION_ID,
    auto_sanitize: true,
  });

  console.log(`    Safe: ${outputResult.is_safe}`);
  console.log(`    Data Leakage Risk: ${outputResult.data_leakage_risk}`);

  if (outputResult.pii_detected.length > 0) {
    console.log("    PII in output:");
    for (const pii of outputResult.pii_detected) {
      console.log(`      - ${pii.type}: ${pii.value}`);
    }
  }

  if (outputResult.sanitized_text) {
    console.log(`    Sanitized text: ${outputResult.sanitized_text}`);
  }

  // ----------------------------------------------------------------
  // Step 4: Get session summary
  // ----------------------------------------------------------------
  console.log("\n[4] Getting session details...");

  const session = await shield.getSession(SESSION_ID);
  console.log(`    Session ID: ${session.session_id}`);
  console.log(`    Status: ${session.status}`);
  console.log(`    Risk Level: ${session.risk_level}`);
  console.log(`    Total Actions: ${session.total_actions}`);
  console.log(`    Threats Detected: ${session.threats_detected}`);

  // ----------------------------------------------------------------
  // Step 5: Generate a security report
  // ----------------------------------------------------------------
  console.log("\n[5] Generating security report...");

  const report = await shield.generateReport({
    session_id: SESSION_ID,
    report_type: "security_analysis",
    language: "ko",
  });

  console.log(`    Report ID: ${report.report_id}`);
  console.log(`    Title: ${report.title}`);
  console.log(`    Summary: ${report.summary}`);
  console.log(`    Risk Level: ${report.risk_level}`);

  if (report.recommendations.length > 0) {
    console.log("    Recommendations:");
    for (const rec of report.recommendations) {
      console.log(`      [${rec.priority}] ${rec.title}: ${rec.description}`);
    }
  }

  // ----------------------------------------------------------------
  // Step 6: Check alerts
  // ----------------------------------------------------------------
  console.log("\n[6] Checking security alerts...");

  const alerts = await shield.getAlerts({ severity: "high", page: 1, size: 5 });
  console.log(`    Total alerts: ${alerts.total}`);
  for (const alert of alerts.items) {
    console.log(`      - [${alert.severity}] ${alert.title}`);
  }

  console.log("\nDone!");
}

main().catch(console.error);
