# Show HN Submission Draft

## Title (max 80 chars)

Show HN: InALign – Tamper-proof audit trails for AI coding agents (MCP server)

## URL

https://github.com/Intellirim/inalign

## Text (if self-post, keep under ~300 words)

AI coding agents (Claude Code, Cursor, Copilot) can read, write, and execute anything on your machine. When an agent modifies a production config or runs a destructive command, you need to answer: what happened, who triggered it, and can you prove it?

InALign is an open-source MCP server that records every AI agent action into a SHA-256 hash chain. Each record is cryptographically linked to the previous one — modify any record and the chain breaks. Same principle as Git commits, applied to agent actions.

What it does:

- **Provenance chain**: Every action gets a SHA-256 hash linked to the previous record. Tamper with one → the chain breaks.
- **Risk analysis**: GraphRAG pattern detection for data exfiltration, privilege escalation, and suspicious tool chains.
- **Policy engine**: Three presets (Strict/Balanced/Sandbox). Simulate any policy against historical events before deploying.
- **16 MCP tools**: Works automatically once installed. No code changes needed.

Try it:

```
pip install inalign-mcp && inalign-install --local
```

No API key, no account, no cloud. Runs 100% locally in memory. Restart your editor and every agent action is recorded.

For persistent storage, self-host with Neo4j or use an API key for the managed service.

Tech: Python, MCP protocol, SHA-256 hash chains, Neo4j (optional), PROV-O ontology for provenance modeling.

I built this because I use Claude Code daily and wanted cryptographic proof of what my agents do — especially before handing off codebases to teammates or auditors. Happy to answer questions about the implementation.

GitHub: https://github.com/Intellirim/inalign

---

## Submission Notes

- **Best time**: Tuesday-Thursday, 9-11am ET (HN peak hours)
- **Do NOT**: Ask for upvotes, self-promote in comments
- **DO**: Answer every comment honestly, admit limitations
- **Key talking points if asked**:
  - "Why not just use Git history?" → Git shows file changes, not agent intent. InALign captures the user command → agent action → outcome chain.
  - "Is the hash chain actually useful?" → Same as Git's integrity model. Any tampering is immediately detectable via verify_provenance.
  - "Memory mode loses data on restart" → Yes, by design for quick tryouts. Use Neo4j or API for persistence.
  - "What about performance overhead?" → MCP calls are async, hash computation is ~microseconds. No measurable impact.
