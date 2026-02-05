# @inalign/sdk

Official JavaScript/TypeScript SDK for [InALign](https://inalign.io) - AI Agent Security Platform.

Protect your AI agents with real-time threat detection, PII scanning, anomaly detection, and comprehensive audit logging.

## Installation

```bash
npm install @inalign/sdk
# or
yarn add @inalign/sdk
# or
pnpm add @inalign/sdk
```

## Quick Start

```typescript
import { InALign } from "@inalign/sdk";

const shield = new InALign("your-api-key");

// Scan user input for threats and PII
const result = await shield.scanInput({
  text: "My SSN is 123-45-6789. Help me reset my password.",
  agent_id: "my-agent",
  session_id: "session-123",
});

console.log(`Safe: ${result.is_safe}`);
console.log(`Risk Level: ${result.risk_level}`);
console.log(`Threats: ${result.threats.map((t) => t.type)}`);
console.log(`PII Found: ${result.pii_detected.map((p) => p.type)}`);
```

## Features

- **Input Scanning**: Detect prompt injection, jailbreak attempts, and PII in user messages
- **Output Scanning**: Prevent sensitive data leakage in AI agent responses
- **Action Logging**: Record and analyze agent actions for anomaly detection
- **Session Management**: Track and monitor agent sessions with risk scoring
- **Report Generation**: Generate detailed security analysis reports
- **Alert Management**: Receive and manage security alerts
- **TypeScript Native**: Full type definitions included
- **Zero Dependencies**: Uses the built-in `fetch` API (Node.js 18+)

## Usage

### Initialize the Client

```typescript
import { InALign } from "@inalign/sdk";

const shield = new InALign("your-api-key", {
  baseUrl: "https://api.inalign.io", // optional
  timeout: 30000, // optional, in milliseconds
});
```

### Scan User Input

```typescript
const result = await shield.scanInput({
  text: "User message here",
  agent_id: "agent-1",
  session_id: "sess-abc",
  metadata: { channel: "web" },
});

if (!result.is_safe) {
  console.log("Threats:", result.threats);
  console.log("PII:", result.pii_detected);
}
```

### Scan Agent Output

```typescript
const result = await shield.scanOutput({
  text: "Agent response here",
  agent_id: "agent-1",
  session_id: "sess-abc",
  auto_sanitize: true,
});

if (result.sanitized_text) {
  // Use the sanitized version instead
  console.log(result.sanitized_text);
}
```

### Log Agent Actions

```typescript
const result = await shield.logAction({
  agent_id: "agent-1",
  session_id: "sess-abc",
  action_type: "tool_call",
  name: "database_query",
  target: "users_table",
  parameters: { query: "SELECT * FROM users WHERE id = 1" },
  result_summary: "Returned 1 row",
  duration_ms: 45,
});

if (result.is_anomalous) {
  console.log("Anomaly detected!", result.anomalies);
}
```

### Session Management

```typescript
// Get session details
const session = await shield.getSession("sess-abc");

// List sessions with filtering
const sessions = await shield.listSessions({
  status: "active",
  risk_level: "high",
  page: 1,
  size: 20,
});
```

### Generate Reports

```typescript
const report = await shield.generateReport({
  session_id: "sess-abc",
  report_type: "security_analysis",
  language: "ko",
});

console.log(report.title);
console.log(report.summary);
for (const rec of report.recommendations) {
  console.log(`[${rec.priority}] ${rec.title}`);
}
```

### Alert Management

```typescript
// Get alerts
const alerts = await shield.getAlerts({
  severity: "high",
  acknowledged: false,
});

// Acknowledge an alert
await shield.acknowledgeAlert("alert-123");
```

## Error Handling

The SDK throws typed errors for different scenarios:

```typescript
import { InALign } from "@inalign/sdk";
import {
  InALignError,
  AuthenticationError,
  RateLimitError,
  NotFoundError,
  ValidationError,
  ServerError,
} from "@inalign/sdk/client";

try {
  const result = await shield.scanInput({ ... });
} catch (error) {
  if (error instanceof AuthenticationError) {
    console.log("Check your API key");
  } else if (error instanceof RateLimitError) {
    console.log("Slow down, retrying...");
  } else if (error instanceof InALignError) {
    console.log(`Error: ${error.detail} (status: ${error.statusCode})`);
  }
}
```

## TypeScript Support

All request and response types are exported:

```typescript
import type {
  ScanInputRequest,
  ScanInputResponse,
  ScanOutputResponse,
  LogActionRequest,
  LogActionResponse,
  SessionResponse,
  ReportResponse,
  AlertResponse,
  ThreatInfo,
  PIIInfo,
  AnomalyInfo,
} from "@inalign/sdk";
```

## Requirements

- Node.js >= 18.0.0 (uses built-in `fetch`)
- TypeScript >= 5.0 (optional, for type checking)

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Lint
npm run lint

# Type check
npm run typecheck
```

## License

MIT License. See LICENSE for details.
