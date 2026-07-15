"""Ports: the contracts the domain defines and the outer world must fulfill.

A "port" is an interface owned by the domain. The domain says *what* it needs
("something that can scan a path and give me findings"); an adapter in an outer
layer decides *how* (by running detekt, Bandit, a fake, ...).

We express the port with typing.Protocol rather than an abstract base class.
A Protocol is structural: any object that has a matching `scan` method already
satisfies it — the adapter does not need to import or subclass anything from
the domain. That keeps the dependency arrow pointing strictly inward.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from kotlin_security_mcp.domain.models import ScanResult


@runtime_checkable
class SecurityAnalyzer(Protocol):
    """Anything that can inspect a path and report security findings.

    The whole application talks to *this*, never to detekt directly. Swapping
    detekt for another engine, or for a fake in tests, means providing another
    object with this same `scan` method — nothing else has to change.
    """

    def scan(self, target: Path) -> ScanResult:
        """Analyze the file or directory at `target` and return its findings.

        Implementations must return a ScanResult even when nothing is wrong
        (an empty result), and must not raise merely because the code is clean.
        """
        ...
