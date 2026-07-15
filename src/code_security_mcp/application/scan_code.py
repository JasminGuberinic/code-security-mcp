"""The ScanCodeUseCase: the one action our MVP performs.

It ties together a target path and a SecurityAnalyzer, adds the small amount of
policy that does not belong in either (validating the path), and returns a
ScanResult. The MCP layer calls this; it never calls an analyzer directly.
"""

from __future__ import annotations

from pathlib import Path

from code_security_mcp.domain.models import ScanResult
from code_security_mcp.domain.ports import SecurityAnalyzer


class ScanCodeUseCase:
    """Scan a file or directory for security findings.

    The analyzer is injected through the constructor (dependency injection).
    The use case does not know or care whether it is detekt, Bandit, or a fake —
    it only knows it received *something that fulfills the SecurityAnalyzer port*.
    """

    def __init__(self, analyzer: SecurityAnalyzer) -> None:
        # Store the collaborator we were handed. This single line is the whole
        # "wiring" of the use case; everything else is behavior.
        self._analyzer = analyzer

    def execute(self, target: Path) -> ScanResult:
        """Validate the target, then delegate the actual scanning.

        We split this into tiny private steps below so each does exactly one
        thing and the method reads like a sentence: check it exists, then scan.
        """
        self._ensure_target_exists(target)
        return self._analyzer.scan(target)

    def _ensure_target_exists(self, target: Path) -> None:
        """Guard clause: refuse to scan a path that is not there.

        Failing loudly and early here gives the agent a clear error ("no such
        path") instead of a confusing empty result that looks like clean code.
        """
        if not target.exists():
            raise FileNotFoundError(f"Nothing to scan at: {target}")
