"""Translate an ESLint JSON report into our domain Findings.

Like Bandit, ESLint has its own JSON shape rather than SARIF, so we map it here.
ESLint reports results per file, each with a list of messages; we keep only the
messages that came from a rule (dropping ESLint's own notices like parse errors
or "file ignored").
"""

from __future__ import annotations

from typing import Any

from code_security_mcp.domain.models import Finding, ScanResult, Severity

# ESLint grades severity numerically: 2 = error, 1 = warning.
_ESLINT_SEVERITY_TO_SEVERITY: dict[int, Severity] = {
    2: Severity.ERROR,
    1: Severity.WARNING,
}


def parse_eslint_report(report: list[dict[str, Any]]) -> ScanResult:
    """Turn ESLint's JSON array into a ScanResult.

    The top level is a list of per-file results; each result has a `messages`
    list. We flatten every rule-backed message into a Finding.
    """
    findings: list[Finding] = []
    for file_result in report:
        file_path = file_result.get("filePath", "")
        for message in file_result.get("messages", []):
            finding = _finding_from_message(message, file_path)
            if finding is not None:
                findings.append(finding)
    return ScanResult(findings=tuple(findings))


def _finding_from_message(message: dict[str, Any], file_path: str) -> Finding | None:
    """Build one Finding from one ESLint message, or None to skip it.

    Messages without a `ruleId` are ESLint notices (parse errors, ignored
    files), not security findings, so we drop them.
    """
    rule_id = message.get("ruleId")
    if not rule_id:
        return None
    return Finding(
        rule_id=rule_id,
        message=(message.get("message") or "").strip(),
        file_path=file_path,
        line=message.get("line", 1),
        severity=_severity_of(message),
    )


def _severity_of(message: dict[str, Any]) -> Severity:
    """Map ESLint's numeric severity onto our Severity, defaulting to WARNING."""
    return _ESLINT_SEVERITY_TO_SEVERITY.get(message.get("severity", 1), Severity.WARNING)
