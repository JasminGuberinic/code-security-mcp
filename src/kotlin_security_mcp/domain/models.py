"""The core value objects of the domain: Severity, Finding, ScanResult.

These are immutable data holders. We make them frozen dataclasses so that once
a finding is created it can never be mutated by accident — a scan result is a
*fact* about the code at a moment in time, and facts should not change under us.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    """How serious a finding is.

    We deliberately keep our own small vocabulary instead of leaking the
    analyzer's raw levels. Each external analyzer (detekt, Bandit, ...) has its
    own words for severity; adapters translate *their* words into *these* three.
    That keeps the domain stable no matter which analyzer we plug in.
    """

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True)
class Finding:
    """A single security issue discovered in one place in the code.

    This is the unit the AI agent ultimately receives. Every field is phrased
    in terms an agent (or a human) can act on, not in terms of how we found it.
    """

    # Stable identifier of the rule that fired, e.g. "WebClientInsecureSsl".
    rule_id: str

    # Human-readable explanation of what is wrong and why it matters.
    message: str

    # Absolute or project-relative path to the file containing the issue.
    file_path: str

    # 1-based line number the issue points at (editors count from 1).
    line: int

    # Our normalized severity (see Severity above).
    severity: Severity

    # Optional CWE identifier (e.g. "CWE-295") when the rule maps to one.
    # Optional because not every finding has a catalogued weakness class.
    cwe: str | None = None

    # Optional short hint on how to fix it, when the analyzer provides one.
    remediation: str | None = None


@dataclass(frozen=True)
class ScanResult:
    """The complete outcome of scanning a target: an ordered list of findings.

    We wrap the list in a small object (instead of returning a bare list) so we
    have a natural home for questions callers keep asking — "did anything come
    back?", "how many?" — without every caller re-implementing that logic.
    """

    # A tuple (not a list) so the result stays immutable, matching Finding.
    findings: tuple[Finding, ...]

    @property
    def has_findings(self) -> bool:
        """True when the scan reported at least one issue."""
        return len(self.findings) > 0

    @property
    def count(self) -> int:
        """How many findings the scan reported."""
        return len(self.findings)
