# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.2.x   | Yes                |
| < 0.2   | No                 |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in InALign, please report it responsibly.

**DO NOT** open a public GitHub issue for security vulnerabilities.

### How to Report

1. Email **security@in-a-lign.com** with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

2. You will receive an acknowledgment within **48 hours**.

3. We will investigate and provide a fix timeline within **7 days**.

### What to Expect

- We will keep you informed throughout the process
- Credit will be given in the release notes (unless you prefer to remain anonymous)
- We aim to patch critical vulnerabilities within 72 hours

### Scope

The following are in scope:

- MCP server (`inalign-mcp`)
- Provenance chain integrity
- Policy engine bypass
- Authentication / API key handling
- Data exfiltration through the platform
- Graph database injection

### Out of Scope

- Vulnerabilities in third-party dependencies (report to upstream)
- Social engineering attacks
- Denial of service (unless caused by a specific code vulnerability)

## Security Best Practices

When deploying InALign:

- Always use environment variables for API keys and credentials
- Enable TLS for Neo4j connections (`neo4j+s://`)
- Rotate API keys regularly via `inalign-clients`
- Set appropriate policy presets (`STRICT_ENTERPRISE` for production)
- Review audit reports periodically via the dashboard
