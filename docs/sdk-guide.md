# InALign SDK Guide

This guide covers installation, setup, and usage for the InALign Python and JavaScript SDKs.

## Python SDK

### Installation

```bash
pip install inalign
```

For development:

```bash
pip install inalign[dev]
```

### Setup

```python
from inalign import InALign

# Basic initialization
client = InALign(api_key="your-api-key")

# With custom configuration
client = InALign(
    api_key="your-api-key",
    base_url="https://api.inalign.io",
    timeout=30,  # seconds
)
```

### Async Client

```python
from inalign import AsyncInALign

async def main():
    async with AsyncInALign(api_key="your-api-key") as client:
        result = await client.scan_input(
            text="Hello",
            agent_id="agent-1",
            session_id="sess-abc",
        )
```

### Scanning Input

Scan user messages before they reach your AI agent:

```python
result = client.scan_input(
    text="My SSN is 123-45-6789. Reset my password.",
    agent_id="my-agent",
    session_id="session-123",
    metadata={"channel": "web"},
)

if not result.is_safe:
    print(f"Risk: {result.risk_level} ({result.risk_score})")

    # Check for threats
    for threat in result.threats:
        print(f"  Threat: {threat.type} - {threat.description}")
        print(f"  Severity: {threat.severity}, Confidence: {threat.confidence}")

    # Check for PII
    for pii in result.pii_detected:
        print(f"  PII: {pii.type} at [{pii.start}:{pii.end}]")

    # Block high-risk inputs
    if result.risk_level in ("high", "critical"):
        raise ValueError("Unsafe input blocked by InALign")
```

### Scanning Output

Scan AI agent responses before sending to users:

```python
result = client.scan_output(
    text="Your account number is 9876543210.",
    agent_id="my-agent",
    session_id="session-123",
    auto_sanitize=True,
)

if result.data_leakage_risk:
    print("Data leakage detected!")
    if result.sanitized_text:
        # Use the sanitized version
        response_to_user = result.sanitized_text
    else:
        response_to_user = "I cannot share that information."
```

### Logging Actions

Log agent actions for auditing and anomaly detection:

```python
result = client.log_action(
    agent_id="my-agent",
    session_id="session-123",
    action_type="tool_call",
    name="database_query",
    target="users_table",
    parameters={"query": "SELECT name FROM users WHERE id = 1"},
    result_summary="Returned 1 row",
    duration_ms=45,
    context={"triggered_by": "user_request"},
)

if result.is_anomalous:
    print(f"Anomaly detected! Risk: {result.risk_level}")
    for anomaly in result.anomalies:
        print(f"  {anomaly.type}: {anomaly.description}")
```

### Session Management

```python
# Get session details
session = client.get_session("session-123")
print(f"Status: {session.status}, Risk: {session.risk_level}")
print(f"Actions: {session.total_actions}, Threats: {session.threats_detected}")

# List active high-risk sessions
sessions = client.list_sessions(status="active", risk_level="high")
for item in sessions["items"]:
    print(f"  Session {item['session_id']}: {item['risk_level']}")
```

### Report Generation

```python
report = client.generate_report(
    session_id="session-123",
    report_type="security_analysis",
    language="ko",  # Korean
)

print(f"Report: {report.title}")
print(f"Summary: {report.summary}")
print(f"Risk: {report.risk_level} ({report.risk_score})")

for rec in report.recommendations:
    print(f"  [{rec.priority}] {rec.title}")
    print(f"    {rec.description}")
```

### Alert Management

```python
# Get unacknowledged critical alerts
alerts = client.get_alerts(severity="critical", acknowledged=False)

for alert in alerts["items"]:
    print(f"[{alert['severity']}] {alert['title']}")
    print(f"  {alert['description']}")

    # Acknowledge the alert
    client.acknowledge_alert(alert["alert_id"])
```

### Error Handling

```python
from inalign.exceptions import (
    InALignError,
    AuthenticationError,
    RateLimitError,
    NotFoundError,
    ValidationError,
    ServerError,
)

try:
    result = client.scan_input(text="test", agent_id="a", session_id="s")
except AuthenticationError:
    print("Invalid API key")
except RateLimitError:
    print("Rate limited - implement backoff")
except NotFoundError:
    print("Resource not found")
except ValidationError as e:
    print(f"Invalid request: {e.message}")
except ServerError:
    print("Server error - retry later")
except InALignError as e:
    print(f"Error {e.status_code}: {e.message}")
```

## JavaScript SDK

### Installation

```bash
npm install @inalign/sdk
```

### Setup

```typescript
import { InALign } from "@inalign/sdk";

const shield = new InALign("your-api-key", {
  baseUrl: "https://api.inalign.io",
  timeout: 30000, // milliseconds
});
```

### Scanning Input

```typescript
const result = await shield.scanInput({
  text: "My SSN is 123-45-6789",
  agent_id: "my-agent",
  session_id: "session-123",
  metadata: { channel: "web" },
});

if (!result.is_safe) {
  console.log(`Risk: ${result.risk_level}`);
  result.threats.forEach((threat) => {
    console.log(`  ${threat.type}: ${threat.description}`);
  });
}
```

### Scanning Output

```typescript
const result = await shield.scanOutput({
  text: "Your account number is 9876543210.",
  agent_id: "my-agent",
  session_id: "session-123",
  auto_sanitize: true,
});

const responseText = result.sanitized_text ?? originalText;
```

### Logging Actions

```typescript
const result = await shield.logAction({
  agent_id: "my-agent",
  session_id: "session-123",
  action_type: "tool_call",
  name: "database_query",
  target: "users_table",
  parameters: { query: "SELECT * FROM users" },
  result_summary: "Returned 5 rows",
  duration_ms: 120,
});

if (result.is_anomalous) {
  console.log("Anomaly detected!", result.anomalies);
}
```

### Session and Reports

```typescript
// Get session
const session = await shield.getSession("session-123");

// List sessions
const sessions = await shield.listSessions({
  status: "active",
  risk_level: "high",
});

// Generate report
const report = await shield.generateReport({
  session_id: "session-123",
  report_type: "security_analysis",
  language: "ko",
});
```

### Alert Management

```typescript
// Get alerts
const alerts = await shield.getAlerts({
  severity: "critical",
  acknowledged: false,
});

// Acknowledge alert
await shield.acknowledgeAlert("alert-123");
```

## LangChain Integration (Python)

InALign can be integrated as a LangChain callback handler to automatically protect your chains and agents.

### Setup

```python
from inalign import InALign
from langchain_core.callbacks import BaseCallbackHandler

class InALignCallbackHandler(BaseCallbackHandler):
    def __init__(self, api_key: str, agent_id: str):
        self.client = InALign(api_key=api_key)
        self.agent_id = agent_id
        self.session_id = str(uuid.uuid4())

    def on_llm_start(self, serialized, prompts, **kwargs):
        for prompt in prompts:
            result = self.client.scan_input(
                text=prompt,
                agent_id=self.agent_id,
                session_id=self.session_id,
            )
            if not result.is_safe and result.risk_level in ("high", "critical"):
                raise ValueError(f"Blocked: {result.risk_level}")

    def on_llm_end(self, response, **kwargs):
        for generations in response.generations:
            for gen in generations:
                self.client.scan_output(
                    text=gen.text,
                    agent_id=self.agent_id,
                    session_id=self.session_id,
                    auto_sanitize=True,
                )
```

### Usage with LangChain

```python
from langchain_openai import ChatOpenAI

handler = InALignCallbackHandler(
    api_key="your-inalign-key",
    agent_id="my-langchain-agent",
)

llm = ChatOpenAI(model="gpt-4", callbacks=[handler])
response = llm.invoke("What are the best practices for AI safety?")
```

## OpenAI Integration (Python)

Wrap the OpenAI client with InALign for automatic protection:

```python
from inalign import InALign
from openai import OpenAI

class ShieldedChat:
    def __init__(self, openai_key: str, shield_key: str):
        self.openai = OpenAI(api_key=openai_key)
        self.shield = InALign(api_key=shield_key)

    def chat(self, message: str, agent_id: str, session_id: str) -> str:
        # Scan input
        scan = self.shield.scan_input(
            text=message, agent_id=agent_id, session_id=session_id,
        )
        if not scan.is_safe and scan.risk_level in ("high", "critical"):
            return "I cannot process this request for security reasons."

        # Call OpenAI
        response = self.openai.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": message}],
        )
        output = response.choices[0].message.content

        # Scan output
        out_scan = self.shield.scan_output(
            text=output, agent_id=agent_id, session_id=session_id,
            auto_sanitize=True,
        )

        return out_scan.sanitized_text or output
```

## Best Practices

1. **Always scan inputs before processing** - Catch prompt injection and threats early.
2. **Scan outputs with auto_sanitize** - Prevent accidental PII leakage.
3. **Log all agent actions** - Build comprehensive audit trails.
4. **Use sessions consistently** - Group related interactions for better analysis.
5. **Handle errors gracefully** - Implement retry logic for rate limits and server errors.
6. **Monitor alerts** - Set up notification channels for real-time alerting.
7. **Generate regular reports** - Review session security periodically.
8. **Use the async client for high-throughput** - Better performance under load.
