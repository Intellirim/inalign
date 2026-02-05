# InALign Python SDK

Official Python SDK for [InALign](https://inalign.io) - AI Agent Security Platform.

Protect your AI agents with real-time threat detection, PII scanning, anomaly detection, and comprehensive audit logging.

## Installation

```bash
pip install inalign
```

## Quick Start

```python
from inalign import InALign

client = InALign(api_key="your-api-key")

# Scan user input for threats and PII
result = client.scan_input(
    text="My SSN is 123-45-6789. Help me reset my password.",
    agent_id="my-agent",
    session_id="session-123",
)

print(f"Safe: {result.is_safe}")
print(f"Risk Level: {result.risk_level}")
print(f"Threats: {[t.type for t in result.threats]}")
print(f"PII Found: {[p.type for p in result.pii_detected]}")
```

## Features

- **Input Scanning**: Detect prompt injection, jailbreak attempts, and PII in user messages
- **Output Scanning**: Prevent sensitive data leakage in AI agent responses
- **Action Logging**: Record and analyze agent actions for anomaly detection
- **Session Management**: Track and monitor agent sessions with risk scoring
- **Report Generation**: Generate detailed security analysis reports
- **Alert Management**: Receive and manage security alerts
- **Async Support**: Full async/await support with `AsyncInALign`
- **Type Safety**: Complete Pydantic models for all API responses

## Usage

### Synchronous Client

```python
from inalign import InALign

client = InALign(
    api_key="your-api-key",
    base_url="https://api.inalign.io",  # optional
    timeout=30,  # optional, in seconds
)

# Scan input
input_result = client.scan_input(
    text="User message here",
    agent_id="agent-1",
    session_id="sess-abc",
    metadata={"channel": "web"},
)

# Scan output
output_result = client.scan_output(
    text="Agent response here",
    agent_id="agent-1",
    session_id="sess-abc",
    auto_sanitize=True,
)

# Log an action
action_result = client.log_action(
    agent_id="agent-1",
    session_id="sess-abc",
    action_type="tool_call",
    name="database_query",
    target="users_table",
    parameters={"query": "SELECT * FROM users WHERE id = 1"},
    result_summary="Returned 1 row",
    duration_ms=45,
)

# Get session details
session = client.get_session("sess-abc")

# List sessions
sessions = client.list_sessions(status="active", risk_level="high")

# Generate a report
report = client.generate_report(
    session_id="sess-abc",
    report_type="security_analysis",
    language="ko",
)

# Get alerts
alerts = client.get_alerts(severity="high")

# Acknowledge an alert
client.acknowledge_alert("alert-123")

# Clean up
client.close()
```

### Async Client

```python
import asyncio
from inalign import AsyncInALign

async def main():
    async with AsyncInALign(api_key="your-api-key") as client:
        result = await client.scan_input(
            text="User message",
            agent_id="agent-1",
            session_id="sess-abc",
        )
        print(f"Safe: {result.is_safe}")

asyncio.run(main())
```

### Context Manager

Both clients support the context manager pattern:

```python
with InALign(api_key="your-key") as client:
    result = client.scan_input(text="Hello", agent_id="a", session_id="s")
```

### LangChain Integration

See `examples/with_langchain.py` for a complete LangChain callback handler that automatically protects your chains and agents.

```python
from examples.with_langchain import InALignCallbackHandler
from langchain_openai import ChatOpenAI

handler = InALignCallbackHandler(
    api_key="your-inalign-key",
    agent_id="my-langchain-agent",
)

llm = ChatOpenAI(model="gpt-4", callbacks=[handler])
response = llm.invoke("Tell me about AI safety")
```

### OpenAI Integration

See `examples/with_openai.py` for an OpenAI wrapper that adds automatic security scanning.

```python
from examples.with_openai import ShieldedOpenAI

client = ShieldedOpenAI(
    openai_api_key="sk-...",
    inalign_api_key="your-key",
    agent_id="my-openai-agent",
)

response = client.chat("What is zero-trust security?")
```

## Error Handling

The SDK raises typed exceptions for different error scenarios:

```python
from inalign.exceptions import (
    InALignError,       # Base exception
    AuthenticationError,    # 401/403
    RateLimitError,         # 429
    NotFoundError,          # 404
    ValidationError,        # 422
    ServerError,            # 500+
)

try:
    result = client.scan_input(text="test", agent_id="a", session_id="s")
except AuthenticationError:
    print("Check your API key")
except RateLimitError:
    print("Slow down, retrying...")
except InALignError as e:
    print(f"Error: {e.message} (status: {e.status_code})")
```

## Models

All API responses are returned as Pydantic models with full type hints:

- `ScanInputResponse` - Input scan results with threats and PII
- `ScanOutputResponse` - Output scan results with sanitization
- `LogActionResponse` - Action logging results with anomaly detection
- `SessionResponse` - Session details and security summary
- `ReportResponse` - Generated security reports with recommendations
- `AlertResponse` - Security alert details

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run linter
ruff check .
```

## License

MIT License. See LICENSE for details.
