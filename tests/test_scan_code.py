"""Tests for ScanCodeUseCase.

We drive the use case with a hand-written fake analyzer. Because the use case
depends only on the SecurityAnalyzer *port*, the fake needs nothing more than a
matching `scan` method — no detekt, no JVM, no files to scan.
"""

import pytest

from kotlin_security_mcp.application.scan_code import ScanCodeUseCase
from kotlin_security_mcp.domain.models import Finding, ScanResult, Severity


class _FakeAnalyzer:
    """A stand-in analyzer that returns a canned result and records its input.

    This is the whole point of the port: production uses DetektAnalyzer, tests
    use this, and ScanCodeUseCase cannot tell the difference.
    """

    def __init__(self, result: ScanResult) -> None:
        self._result = result
        self.scanned_target = None  # remembers what it was asked to scan

    def scan(self, target):
        self.scanned_target = target
        return self._result


def test_execute_returns_the_analyzers_result(tmp_path):
    canned = ScanResult(
        findings=(Finding("R1", "msg", str(tmp_path), 1, Severity.WARNING),)
    )
    analyzer = _FakeAnalyzer(canned)

    result = ScanCodeUseCase(analyzer).execute(tmp_path)

    assert result is canned
    # It delegated with the exact target we passed in.
    assert analyzer.scanned_target == tmp_path


def test_execute_rejects_a_missing_path():
    analyzer = _FakeAnalyzer(ScanResult(findings=()))

    # A path that does not exist must fail loudly, before any scan happens.
    with pytest.raises(FileNotFoundError):
        ScanCodeUseCase(analyzer).execute(__import__("pathlib").Path("/no/such/path"))

    # And the analyzer must never have been called.
    assert analyzer.scanned_target is None
