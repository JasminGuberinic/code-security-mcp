"""The MCP server: the outermost, driving adapter.

This is where the Model Context Protocol meets our use case. It does three
things and nothing more:

  1. Composition root  — read configuration and wire the concrete objects
                         (DetektAnalyzer -> ScanCodeUseCase) together, once.
  2. Tool surface      — expose `security_scan` to the AI agent.
  3. Presentation      — turn domain Findings into a plain, JSON-friendly shape
                         the agent can read.

No security logic lives here. If we deleted MCP tomorrow and drove the use case
from a CLI instead, only this file would change.
"""

from __future__ import annotations

import os
from pathlib import Path

from kotlin_security_mcp.adapters.detekt_analyzer import DetektAnalyzer, DetektConfig
from kotlin_security_mcp.application.scan_code import ScanCodeUseCase
from kotlin_security_mcp.domain.models import Finding

# The SDK renamed FastMCP -> MCPServer. Import the current name, but fall back
# to the old one so the server keeps working on either SDK generation.
try:
    from mcp.server import MCPServer
except ImportError:  # pragma: no cover - depends on installed SDK version
    from mcp.server.fastmcp import FastMCP as MCPServer

# The server instance. The name is what shows up in the client's tool list.
mcp = MCPServer("kotlin-security-mcp")


@mcp.tool()
def security_scan(path: str) -> dict:
    """Scan Kotlin/JVM code for security issues using a 216-rule analyzer.

    Point this at a file or directory. It returns every security finding the
    analyzer reports — rule id, message, location, and severity — so the agent
    can fix issues *while writing*, not after.

    Args:
        path: File or directory to scan (absolute, or relative to the project).
    """
    use_case = _build_use_case()
    result = use_case.execute(Path(path))
    return {
        "target": path,
        "count": result.count,
        "findings": [_finding_to_dict(finding) for finding in result.findings],
    }


def _build_use_case() -> ScanCodeUseCase:
    """Composition root: assemble the concrete object graph from configuration.

    We read the "where is everything" paths from environment variables so the
    server runs on any machine without code changes. This is the single place
    allowed to name concrete classes; everything downstream sees only ports.
    """
    config = DetektConfig(
        java_executable=Path(_required_env("KSM_JAVA")),
        detekt_cli_jar=Path(_required_env("KSM_DETEKT_CLI_JAR")),
        plugin_jars=_paths_from_env("KSM_PLUGIN_JARS"),
        config_file=_optional_path_from_env("KSM_DETEKT_CONFIG"),
    )
    analyzer = DetektAnalyzer(config)
    return ScanCodeUseCase(analyzer)


def _finding_to_dict(finding: Finding) -> dict:
    """Flatten a domain Finding into a JSON-serializable dict for the agent.

    Presentation lives here, at the edge, so the domain never has to know how
    it will be displayed or transported.
    """
    return {
        "rule_id": finding.rule_id,
        "message": finding.message,
        "file": finding.file_path,
        "line": finding.line,
        "severity": finding.severity.value,
        "cwe": finding.cwe,
        "remediation": finding.remediation,
    }


def _required_env(name: str) -> str:
    """Read an environment variable, failing clearly if it is missing.

    A missing path is a setup mistake we want surfaced immediately, with the
    exact variable name, rather than a mysterious failure deep inside detekt.
    """
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _paths_from_env(name: str) -> tuple[Path, ...]:
    """Read a comma-separated list of paths (e.g. multiple plugin jars)."""
    raw = _required_env(name)
    return tuple(Path(part.strip()) for part in raw.split(",") if part.strip())


def _optional_path_from_env(name: str) -> Path | None:
    """Read an optional path; return None when the variable is unset."""
    value = os.environ.get(name)
    return Path(value) if value else None


def main() -> None:
    """Console entry point (see pyproject `[project.scripts]`).

    `mcp.run()` blocks for the whole server lifetime and speaks stdio by
    default — exactly what a local MCP client (Claude Code, Cursor) expects.
    """
    mcp.run()


if __name__ == "__main__":
    main()
