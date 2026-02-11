# Changelog

## [0.2.7] - 2026-02-12

### Added
- **SQLite local persistent storage** — provenance records now persist across sessions at `~/.inalign/provenance.db`, zero configuration required
- `list_sessions` MCP tool — browse past audit sessions stored locally
- `export_report` MCP tool — generate visual HTML audit reports in any storage mode
- HTML report generator (`report.py`) — self-contained dark-theme audit report with chain visualization

### Changed
- Storage fallback chain: Neo4j → API → **SQLite** → Memory (SQLite is new default for local mode)
- `--local` install now uses SQLite persistent storage instead of volatile memory
- Fixed Neo4j `init_neo4j()` return value check — properly falls back when connection fails

## [0.2.6] - 2026-02-11

### Added
- Performance benchmarks in README (1000 actions ~50ms, 10000 verify <200ms)
- CHANGELOG.md version history

### Changed
- Test code cleanup (proper pytest style)
- Removed legacy install.py from root

## [0.2.5] - 2026-02-09

### Added
- Multi-client session isolation (API mode)
- `list_agents_risk` tool for org-wide security dashboard
- Usage metering per client (scan counts, blocked threats, PII detected)

## [0.2.4] - 2026-02-08

### Added
- Policy engine with 3 presets: `STRICT_ENTERPRISE`, `BALANCED`, `DEV_SANDBOX`
- `simulate_policy` tool — test policy changes against historical events
- Audit export in JSON, CSV, and summary formats

## [0.2.3] - 2026-02-07

### Changed
- API key hashing with SHA-256 (keys never stored in plaintext)
- Constant-time comparison for API key validation
- Rate limiting for authentication endpoints
- bcrypt password hashing for dashboard login

## [0.2.0] - 2026-02-06

### Added
- GraphRAG risk analysis: data exfiltration, privilege escalation, suspicious tool chains
- Behavioral profiling per session
- Agent and user risk aggregation across sessions

## [0.1.0] - 2026-02-04

### Added
- Initial release
- SHA-256 hash chain provenance tracking (W3C PROV compatible)
- 6 core MCP tools: record_action, record_user_command, get_provenance, verify_provenance, generate_audit_report, verify_third_party
- Memory and Neo4j storage backends
- `inalign-install` CLI for one-command setup
- Dashboard with login and session viewer
