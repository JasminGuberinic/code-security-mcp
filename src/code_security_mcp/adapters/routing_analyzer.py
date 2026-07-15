"""RoutingAnalyzer: send each target to the analyzers that understand it.

This is what turns a set of single-language specialists into one multi-language
tool without any of them knowing about the others. It holds a list of language
analyzers, asks each `supports(target)`, and merges the findings of those that
say yes. Kotlin goes to detekt; compiled Java goes to SpotBugs; a directory with
both gets scanned by both.

It implements the SecurityAnalyzer port (it has a `scan` method), so the use
cases treat it exactly like a single analyzer.
"""

from __future__ import annotations

from pathlib import Path

from code_security_mcp.domain.models import Finding, ScanResult
from code_security_mcp.domain.ports import LanguageAnalyzer


class RoutingAnalyzer:
    """Dispatch a scan to every registered analyzer that supports the target."""

    def __init__(self, analyzers: tuple[LanguageAnalyzer, ...]) -> None:
        # The specialists we route between, in priority order.
        self._analyzers = analyzers

    def scan(self, target: Path) -> ScanResult:
        """Scan `target` with each supporting analyzer and merge the results."""
        findings: list[Finding] = []
        for analyzer in self._analyzers:
            if analyzer.supports(target):
                findings.extend(analyzer.scan(target).findings)
        return ScanResult(findings=tuple(findings))
