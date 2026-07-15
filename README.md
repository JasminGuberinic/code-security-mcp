# kotlin-security-mcp

An [MCP](https://modelcontextprotocol.io) server that exposes a **216-rule,
framework-aware Kotlin/JVM security analyzer** to AI coding agents (Claude Code,
Cursor, …).

Generic assistants guess at JVM security. This server lets an agent **query real
security findings while it writes** — rule id, line, severity, and fix — backed
by the [`kotlin-security-scanner`](https://github.com/JasminGuberinic/kotlin-security-scanner)
detekt ruleset (Spring / WebFlux / Ktor / Quarkus / Micronaut / Vert.x).

> Not generic navigation (Serena), not generic SAST (Snyk): the JVM-framework
> **security specialist** for agents.

## Tools

| Tool | What it does |
|------|--------------|
| `security_scan(path)` | Scan a Kotlin file/directory and return every security finding. |

_(More tools — `secure_pattern`, `review_diff`, and tree-sitter navigation —
are on the roadmap.)_

## Architecture

Clean, hexagonal (ports & adapters). Dependencies point inward; the domain knows
nothing about detekt or MCP.

```
server.py            MCP surface + composition root   (knows MCP)
   │
application/         ScanCodeUseCase                  (knows only ports)
   │
domain/              Finding, ScanResult, ports        (pure vocabulary)
   ↑ implemented by
adapters/            DetektAnalyzer, SARIF parser      (knows detekt/JVM)
```

Swapping detekt for another engine, or adding Python/Java/C# analyzers, means
adding an adapter — nothing in the domain or use case changes.

## Requirements

- Python 3.11+
- A JDK (for the detekt runtime)
- The detekt CLI jar and the `scanner-all` ruleset jar

## Configuration

The server locates its tools through environment variables:

| Variable | Meaning |
|----------|---------|
| `KSM_JAVA` | Path to the `java` executable |
| `KSM_DETEKT_CLI_JAR` | Path to the detekt CLI jar |
| `KSM_PLUGIN_JARS` | Comma-separated ruleset jar(s) (`scanner-all`) |
| `KSM_DETEKT_CONFIG` | _(optional)_ path to a `detekt.yml` |

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

## License

MIT
