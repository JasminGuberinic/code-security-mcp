"""Translate a detekt SARIF report into our domain Findings.

SARIF (Static Analysis Results Interchange Format) is a JSON standard that many
analyzers, detekt included, can emit. Keeping this translation in its own module
means we can unit-test it with a hand-written JSON dict — no JVM, no detekt, no
files — which is exactly what makes the risky "parsing" logic cheap to verify.

We only read the handful of SARIF fields we actually rely on, and we guard every
access with `.get(...)` so a slightly unusual report degrades gracefully instead
of crashing the whole scan.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import unquote, urlparse

from code_security_mcp.domain.models import Finding, ScanResult, Severity

# How SARIF's `level` strings map onto our three-value Severity. Anything we do
# not recognize falls back to WARNING — a safe, attention-worthy default.
_SARIF_LEVEL_TO_SEVERITY: dict[str, Severity] = {
    "error": Severity.ERROR,
    "warning": Severity.WARNING,
    "note": Severity.INFO,
    "none": Severity.INFO,
}


def parse_sarif_report(report: dict[str, Any]) -> ScanResult:
    """Turn a parsed SARIF JSON document into a ScanResult.

    A SARIF document contains one or more `runs` (one per tool invocation), and
    each run contains `results` (the individual findings). We flatten every
    result from every run into a single list of domain Findings.
    """
    findings: list[Finding] = []
    for run in report.get("runs", []):
        for raw_result in run.get("results", []):
            findings.append(_finding_from_result(raw_result))
    return ScanResult(findings=tuple(findings))


def _finding_from_result(result: dict[str, Any]) -> Finding:
    """Build one Finding from one SARIF `result` object."""
    return Finding(
        rule_id=_rule_id_of(result),
        message=_message_of(result),
        file_path=_file_path_of(result),
        line=_line_of(result),
        severity=_severity_of(result),
    )


def _rule_id_of(result: dict[str, Any]) -> str:
    """The rule identifier, e.g. "WebClientInsecureSsl".

    detekt sometimes namespaces the id (e.g. "detekt.MyRuleSet.WebClient..."),
    so we take the last dotted segment to show the agent the clean rule name.
    """
    raw_id = result.get("ruleId", "unknown")
    return raw_id.rsplit(".", maxsplit=1)[-1]


def _message_of(result: dict[str, Any]) -> str:
    """The human-readable description of the issue."""
    return result.get("message", {}).get("text", "").strip()


def _severity_of(result: dict[str, Any]) -> Severity:
    """Map the SARIF `level` onto our Severity, defaulting to WARNING."""
    level = result.get("level", "warning").lower()
    return _SARIF_LEVEL_TO_SEVERITY.get(level, Severity.WARNING)


def _first_physical_location(result: dict[str, Any]) -> dict[str, Any]:
    """Return the first `physicalLocation` block, or an empty dict if absent.

    A result may carry several locations; for a line-level security finding the
    first one is the site we want to point the agent at.
    """
    locations = result.get("locations", [])
    if not locations:
        return {}
    return locations[0].get("physicalLocation", {})


def _file_path_of(result: dict[str, Any]) -> str:
    """Extract a clean filesystem path from the SARIF artifact URI.

    SARIF stores paths as URIs like "file:///Users/.../Foo.kt". We strip the
    "file://" scheme and percent-decode it (so "%20" becomes a real space).
    """
    physical = _first_physical_location(result)
    uri = physical.get("artifactLocation", {}).get("uri", "")
    if not uri:
        return ""
    if uri.startswith("file://"):
        return unquote(urlparse(uri).path)
    return unquote(uri)


def _line_of(result: dict[str, Any]) -> int:
    """The 1-based start line of the issue, defaulting to 1 if unspecified."""
    physical = _first_physical_location(result)
    return physical.get("region", {}).get("startLine", 1)
