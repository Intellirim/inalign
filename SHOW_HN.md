# Show HN Submission Draft

## Title (max 80 chars)

Show HN: InALign – Tamper-proof audit trails for AI coding agents

## URL

https://github.com/Intellirim/inalign

## Text (keep under ~300 words)

AI coding agents (Claude Code, Cursor, Copilot) do hundreds of actions per session — file reads, tool calls, code changes — but there's no way to audit what happened after the fact.

InALign is an open-source MCP server that automatically records every agent action into a SHA-256 hash chain. Each record links to the previous one — modify any record and the chain breaks.

**What it does:**

- **Full session capture**: Prompts, responses, tool calls, thinking — everything. Not just metadata.
- **Hash chain verification**: Tamper-proof provenance. Same principle as Git commits, applied to agent actions.
- **Interactive reports**: HTML reports with graph visualization, conversation timeline, search, and JSON/CSV export.
- **Auto-report on session end**: Install once, reports generate automatically when you close a session.
- **Risk analysis**: GraphRAG pattern detection for data exfiltration and suspicious tool chains.
- **Policy engine**: Strict/Balanced/Sandbox presets with simulation.

Try it:

```
pip install inalign-mcp
inalign-install --local
```

No API key, no account, no cloud. Runs 100% locally with SQLite. Restart your editor and every agent action is tracked. When a session ends, a full conversation report is auto-saved to `~/.inalign/sessions/`.

View your data anytime:
```
inalign-ingest --latest --save
```

This opens an interactive HTML report in your browser — full conversation graph, prompts, responses, tool calls with SHA-256 hashes on every record.

I built this because I use Claude Code daily and wanted cryptographic proof of what my agents do, especially for compliance and debugging "what prompt caused this code change?"

MIT licensed. Zero telemetry.

GitHub: https://github.com/Intellirim/inalign
PyPI: https://pypi.org/project/inalign-mcp/

---

## Submission Notes

- **Best time**: Tuesday-Thursday, 9-11am ET (HN peak hours)
- **Do NOT**: Ask for upvotes, self-promote in comments
- **DO**: Answer every comment honestly, admit limitations
- **Key talking points if asked**:
  - "Why not just use Git history?" -> Git shows file changes, not agent intent. InALign captures user command -> agent action -> outcome chain with full prompt/response content.
  - "Is the hash chain actually useful?" -> Same as Git's integrity model. Any tampering is immediately detectable via verify_provenance.
  - "What about performance?" -> MCP calls are async, hash computation is microseconds. No measurable impact.
  - "Why not just save the .jsonl logs?" -> InALign adds hash chain integrity, graph visualization, risk analysis, and policy enforcement on top of raw logs.
  - "Cloud version?" -> Free tier is 100% local. Pro ($29/mo) adds cloud Neo4j, web dashboard, and team management.

## Checklist
- [ ] GitHub Pages enabled (intellirim.github.io/inalign/)
- [ ] README updated with session ingest + auto-report features
- [ ] Submit Tuesday-Thursday, 9-11am ET
