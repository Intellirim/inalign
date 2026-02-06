# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-02-06

### Added
- Web dashboard with Canvas-based graph visualization
- GraphRAG pattern detection (data exfiltration, privilege escalation, suspicious tool chains)
- 5-layer threat detection (regex, ML, graph, behavioral, contextual)
- W3C PROV-compatible provenance chains with cryptographic verification
- Security policy engine with presets (STRICT_ENTERPRISE, BALANCED, DEV_SANDBOX)
- Blockchain anchoring for tamper-proof audit trails (Polygon)
- Third-party verifiable proofs
- Client management with API key authentication
- Usage limiting and rate control
- Billing integration with Stripe
- Multi-agent IDE support (Claude Code, Cursor, Windsurf, Continue.dev, Cline)

### Fixed
- JS syntax errors in dashboard onclick handlers
- Graph visualization fallback when API returns empty results
- Customer data persistence (in-memory to JSON file storage)

## [0.1.0] - 2025-12-01

### Added
- Initial MCP server implementation
- Basic provenance recording (record_user_command, record_action)
- Provenance chain verification
- Neo4j graph storage
- Session-based audit logging
- Simple risk analysis
- REST query API
