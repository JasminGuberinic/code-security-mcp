---
name: code-security-review
description: Finds real security vulnerabilities in Kotlin, Java, Python, C# and JavaScript/TypeScript by routing each file to its language's native analyzer, and supplies vetted secure patterns before risky code is written. Use when writing or changing code that touches authentication, cookies, sessions, secrets, keys, tokens, TLS, CORS, randomness, subprocesses, deserialization, SQL or file paths; when reviewing a diff before committing; or whenever asked to check code for security problems.
---

# Security review while the code is written

Most security tooling runs after the fact, in CI, on a whole repository, and
reports a generic pattern match. This runs *now*, on what is being written, and
each language is analyzed by the tool that language's own community trusts.

| Language | Analyzer |
|---|---|
| Kotlin | detekt, 216-rule ruleset aware of Spring, WebFlux, Ktor, Quarkus, Micronaut, Vert.x |
| Java | SpotBugs + FindSecBugs, filtered to security findings only |
| Python | Bandit |
| C# | Roslyn security analyzers |
| JavaScript / TypeScript | ESLint + eslint-plugin-security |

A directory containing several languages is routed per file.

## Requires the MCP server

This skill drives the `code-security-mcp` server. Without it the tools below do
not exist. Install it once, then restart the agent:

```bash
pipx install code-security-mcp
pipx inject code-security-mcp bandit      # Python analysis
code-security-mcp-setup                   # Kotlin + Java analyzers
```

Add `--with-dotnet` or `--with-eslint` for C# and JS/TS. Everything lands in an
isolated cache and the script prints the command that registers the server.
Nothing global is touched.

Source and full setup: https://github.com/JasminGuberinic/code-security-mcp

If a tool call fails with "No analyzer configured", the server is installed but
no analyzer is reachable — say so plainly and point at the setup script rather
than silently skipping the check.

## Which tool, and when

**Before writing** anything involving cookies, sessions, secrets, signing keys,
tokens, TLS, CORS or random values on the JVM, call `secure_pattern` first. It
returns an insecure/secure pair with the reason and CWE. Writing the safe
version immediately is cheaper than writing the unsafe one and fixing it.

Search with a **short noun phrase**, not a sentence: `session cookie` works
better than `how do I create a session cookie`. Naming a framework is safe — if
no pattern is written for it the search widens automatically and the response
carries a `note` saying the advice comes from another stack. Adapt the snippet
when you see that note; the principle holds, the API names will not.

**After editing, before committing**, call `review_diff` with `git diff`. It
reports only findings on lines the change adds, so pre-existing debt elsewhere
in the file stays out of the way and the review covers exactly what this change
introduced. This is the default self-check — prefer it to a full scan.

**When asked to audit**, or when touching unfamiliar code, call `security_scan`
on the file or directory. It reports everything the analyzer finds, including
issues that were already there.

## Reading the findings

Each finding carries `rule_id`, `message`, `file`, `line`, `severity`, and
`cwe` where the analyzer supplies one. Kotlin findings often embed the
remediation directly in the message, after `Fix:` — use it rather than inventing
a different repair.

Act on severity rather than reporting everything equally:

- **error** — fix before continuing; do not hand the code over in this state
- **warning** — fix unless there is a stated reason not to, and say what it is
- **info** — mention only if relevant to what is being built

When `truncated` is true the response hit the cap of 500 findings. Scan a
narrower path rather than reasoning about a partial list.

A finding is a claim, not a verdict. Read the flagged line before changing it:
analyzers report `subprocess` imports and `eval` in test fixtures the same way
they report them in production paths. Say when something is a false positive and
why, instead of contorting working code to satisfy a rule.

## How to report back

State the finding, the line, and the fix. Do not paste the raw JSON — it is long
and most of it is noise to a human.

> `examples/vulnerable_sample.py:13` — MD5 used for security (B324, CWE-327).
> Switched to `hashlib.sha256`; if the digest is non-security the call needs
> `usedforsecurity=False` instead.

If nothing is found, say so in one line. Silence reads as "not checked".
