"""Basic usage example for the AgentShield Python SDK.

This example demonstrates:
1. Scanning user input for threats and PII
2. Logging agent actions for audit trails
3. Scanning agent output for data leakage
4. Generating security reports
"""

import os

from agentshield import AgentShield

# Initialize the client
client = AgentShield(
    api_key=os.environ.get("AGENTSHIELD_API_KEY", "ask_your-api-key"),
    base_url=os.environ.get("AGENTSHIELD_BASE_URL", "https://api.agentshield.io"),
)

AGENT_ID = "customer-support-agent-01"
SESSION_ID = "sess-abc-123"


def main() -> None:
    # ----------------------------------------------------------------
    # Step 1: Scan user input before processing
    # ----------------------------------------------------------------
    user_message = "My name is John Doe and my SSN is 123-45-6789. Can you help me reset my password?"

    print("[1] Scanning user input...")
    scan_result = client.scan_input(
        text=user_message,
        agent_id=AGENT_ID,
        session_id=SESSION_ID,
        metadata={"channel": "web", "user_tier": "premium"},
    )

    print(f"    Safe: {scan_result.safe}")
    print(f"    Risk Level: {scan_result.risk_level}")
    print(f"    Risk Score: {scan_result.risk_score}")
    print(f"    Recommendation: {scan_result.recommendation}")

    if scan_result.threats:
        print("    Threats detected:")
        for threat in scan_result.threats:
            print(f"      - {threat.type} (severity: {threat.severity}, confidence: {threat.confidence})")

    # ----------------------------------------------------------------
    # Step 2: Log agent actions
    # ----------------------------------------------------------------
    print("\n[2] Logging agent action...")
    action_result = client.log_action(
        agent_id=AGENT_ID,
        session_id=SESSION_ID,
        action_type="tool_call",
        name="password_reset",
        target="user_management_api",
        parameters={"user_id": "usr-456", "method": "email"},
        result_summary="Password reset email sent successfully.",
        duration_ms=234,
        context={"triggered_by": "user_request"},
    )

    print(f"    Action ID: {action_result.action_id}")
    print(f"    Logged: {action_result.logged}")
    print(f"    Anomaly Detected: {action_result.anomaly_detected}")
    print(f"    Session Risk Score: {action_result.session_risk_score}")

    if action_result.anomalies:
        print("    Anomalies detected:")
        for anomaly in action_result.anomalies:
            print(f"      - {anomaly.type}: {anomaly.description}")

    if action_result.alerts_triggered:
        print(f"    Alerts triggered: {action_result.alerts_triggered}")

    # ----------------------------------------------------------------
    # Step 3: Scan agent output before sending to user
    # ----------------------------------------------------------------
    agent_response = (
        "Hi John! I've sent a password reset link to your email j.doe@example.com. "
        "Your account number is 9876543210. Please check your inbox."
    )

    print("\n[3] Scanning agent output...")
    output_result = client.scan_output(
        text=agent_response,
        agent_id=AGENT_ID,
        session_id=SESSION_ID,
        auto_sanitize=True,
    )

    print(f"    Safe: {output_result.safe}")
    print(f"    Recommendation: {output_result.recommendation}")

    if output_result.pii_detected:
        print("    PII in output:")
        for pii in output_result.pii_detected:
            print(f"      - {pii.type}: {pii.value}")

    if output_result.sanitized_text:
        print(f"    Sanitized text: {output_result.sanitized_text}")

    # ----------------------------------------------------------------
    # Step 4: Get session summary
    # ----------------------------------------------------------------
    print("\n[4] Getting session details...")
    session = client.get_session(SESSION_ID)
    print(f"    Session ID: {session.session_id}")
    print(f"    Status: {session.status}")
    print(f"    Risk Level: {session.risk_level}")
    print(f"    Total Actions: {session.stats.total_actions}")
    print(f"    Threats Detected: {session.stats.threats_detected}")

    # ----------------------------------------------------------------
    # Step 5: Generate a security report
    # ----------------------------------------------------------------
    print("\n[5] Generating security report...")
    report = client.generate_report(
        session_id=SESSION_ID,
        report_type="security_analysis",
        language="ko",
    )

    print(f"    Report ID: {report.report_id}")
    print(f"    Status: {report.status}")
    if report.summary:
        print(f"    Risk Level: {report.summary.risk_level}")
        print(f"    Risk Score: {report.summary.risk_score}")
        print(f"    Primary Concerns: {report.summary.primary_concerns}")

    if report.recommendations:
        print("    Recommendations:")
        for rec in report.recommendations:
            print(f"      [{rec.priority}] {rec.action}: {rec.reason}")

    # ----------------------------------------------------------------
    # Step 6: Check alerts
    # ----------------------------------------------------------------
    print("\n[6] Checking security alerts...")
    alerts_response = client.get_alerts(severity="high", page=1, size=5)
    print(f"    Total alerts: {alerts_response.total}")
    for alert in alerts_response.items:
        print(f"      - [{alert.severity}] {alert.title} (acknowledged: {alert.is_acknowledged})")

    # Clean up
    client.close()
    print("\nDone!")


if __name__ == "__main__":
    main()
