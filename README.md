# code-security-mcp

[![CI](https://github.com/JasminGuberinic/code-security-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/JasminGuberinic/code-security-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

**A framework-aware security [MCP](https://modelcontextprotocol.io) server for AI
coding agents.** It gives Claude Code, Cursor, and other agents real,
**framework-specific** security intelligence for **Kotlin / JVM** backends —
while they write, not after.

> **The security specialist for AI agents writing JVM/Kotlin backend code.**
> Not generic navigation (Serena), not generic SAST (Snyk/Semgrep): a
> *framework-aware* specialist that understands Spring, WebFlux, Ktor, Quarkus,
> Micronaut, and Vert.x idioms.

## Why

Generic assistants and multi-language scanners are shallow on framework idioms —
they don't know that a `@GetMapping` is missing `@PreAuthorize`, that a WebClient
trusts all certificates, or that a Vert.x cookie isn't `HttpOnly`. This server
wraps a **216-rule, framework-aware analyzer** (the
[`kotlin-security-scanner`](https://github.com/JasminGuberinic/kotlin-security-scanner)
detekt ruleset) and exposes it to agents through three tools.

**Design principle:** each language is handled by its **best native, framework-aware
analyzer** — detekt for Kotlin today, Roslyn for C# planned — never a single
lowest-common-denominator generic scanner.

## Tools

| Tool | What it does |
|------|--------------|
| `security_scan(path)` | Scan a Kotlin file/directory and return every security finding (rule, line, severity, CWE). |
| `review_diff(diff)` | Review a unified diff and flag only the issues the change *introduces* — a pre-commit self-check. |
| `secure_pattern(task, framework?)` | Get the vetted secure way to do a risky task — *before* writing it. |

`security_scan` returns **security** findings only — detekt's built-in
style/complexity rules are switched off, so the agent gets signal, not noise.

### Example

> _"What's the secure way to create a session cookie in Vert.x?"_

```kotlin
// secure_pattern(task = "create a session cookie", framework = "vertx")  →  CWE-614
val cookie = Cookie.cookie("session", token)
    .setSecure(true)      // only sent over HTTPS
    .setHttpOnly(true)    // hidden from JavaScript
    .setSameSite(CookieSameSite.STRICT)
response.addCookie(cookie)
```

## Architecture

Clean, hexagonal (ports & adapters). Dependencies point inward; the domain knows
nothing about detekt or MCP.

```
server.py            MCP surface + composition root   (knows MCP)
   │
application/         use cases: scan / review_diff / secure_pattern
   │
domain/              Finding, ScanResult, ports         (pure vocabulary)
   ↑ implemented by
adapters/            DetektAnalyzer, SARIF & diff parsers, pattern catalog
```

Adding a language = adding a native analyzer adapter that implements the same
`SecurityAnalyzer` port. The domain and use cases do not change.

## Requirements

- Python 3.11+
- A JDK (for the detekt runtime)
- The detekt CLI jar and the `scanner-all` ruleset jar(s)

## Configuration

The server locates its tools through environment variables:

| Variable | Meaning |
|----------|---------|
| `KSM_JAVA` | Path to the `java` executable |
| `KSM_DETEKT_CLI_JAR` | Path to the detekt CLI (`-all`) jar |
| `KSM_PLUGIN_JARS` | Comma-separated ruleset jar(s) |
| `KSM_DETEKT_CONFIG` | _(optional)_ path to a `detekt.yml` |

## Use with Claude Code

```bash
claude mcp add code-security -s user \
  -e KSM_JAVA=/path/to/java \
  -e KSM_DETEKT_CLI_JAR=/path/to/detekt-cli-<ver>-all.jar \
  -e KSM_PLUGIN_JARS=/path/to/scanner-core.jar,/path/to/scanner-spring-boot.jar,... \
  -- /path/to/.venv/bin/code-security-mcp
```

Then ask the agent, e.g. _"run security_scan on src/Main.kt"_ or
_"review_diff on my staged changes"_.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

The test suite is hermetic — it uses fake analyzers and hand-built SARIF/diff
fixtures, so it needs neither a JDK nor detekt.

## Roadmap

- Native C# support via **Roslyn** analyzers (same specialist approach).
- Framework-aware Python security.
- Zero-setup: auto-resolve the detekt runtime and ruleset.

## License

MIT — see [LICENSE](LICENSE).

---

<sub>Keywords: MCP server, Model Context Protocol, Kotlin security, JVM security,
SAST, static analysis, detekt, Spring Security, AI coding agent, Claude Code,
Cursor, secure coding.</sub>
