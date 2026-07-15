"""JavaAnalyzer: security-analyze compiled Java with SpotBugs + FindSecBugs.

This is the native, security-focused Java counterpart to detekt-for-Kotlin.
SpotBugs is the analysis engine; FindSecBugs is a plugin that adds ~135 security
detectors (crypto misuse, injection, insecure config, framework-specific issues).

Important difference from detekt: SpotBugs analyzes **compiled bytecode**, not
source. So this adapter is pointed at compiled output (a directory of `.class`
files, or a `.jar`) — the project must be built first. SpotBugs recurses into a
directory to find the class files itself.

As with detekt, SpotBugs emits SARIF, so we reuse the very same parser.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from code_security_mcp.adapters.language import target_has_extension
from code_security_mcp.adapters.sarif import parse_sarif_report
from code_security_mcp.domain.models import ScanResult

# What "Java to analyze" looks like on disk: compiled classes or a jar.
# (Not `.java` — SpotBugs needs bytecode, so source alone cannot be analyzed.)
_COMPILED_JAVA_EXTENSIONS: tuple[str, ...] = (".class", ".jar")


@dataclass(frozen=True)
class SpotBugsConfig:
    """Everything the analyzer needs to locate and launch SpotBugs."""

    # Path to the `java` executable (SpotBugs runs on the JVM, like detekt).
    java_executable: Path

    # Path to the SpotBugs engine jar (spotbugs.jar from the distribution).
    spotbugs_jar: Path

    # Security plugin jar(s) — the FindSecBugs plugin.
    plugin_jars: tuple[Path, ...]

    # Analysis effort. "max" finds the most issues at the cost of speed.
    effort: str = "max"


class JavaAnalyzer:
    """A LanguageAnalyzer that delegates to SpotBugs with FindSecBugs."""

    def __init__(self, config: SpotBugsConfig) -> None:
        # Hold the "where is everything" configuration for the whole object.
        self._config = config

    def supports(self, target: Path) -> bool:
        """True when SpotBugs is available AND the target has compiled Java.

        We require the engine jar to exist so the router transparently skips
        Java analysis on machines where SpotBugs is not installed.
        """
        if not self._config.spotbugs_jar.exists():
            return False
        return target_has_extension(target, _COMPILED_JAVA_EXTENSIONS)

    def scan(self, target: Path) -> ScanResult:
        """Run SpotBugs over compiled Java at `target` and return findings."""
        with tempfile.TemporaryDirectory() as work_dir:
            report_path = Path(work_dir) / "report.sarif"
            self._run_spotbugs(target, report_path)
            return self._read_report(report_path)

    def _run_spotbugs(self, target: Path, report_path: Path) -> None:
        """Launch the SpotBugs subprocess.

        SpotBugs' exit status reflects whether bugs were found, so — as with
        detekt — we ignore the return code and judge success by whether a report
        was written.
        """
        command = self._build_command(target, report_path)
        subprocess.run(command, capture_output=True, text=True, check=False)

    def _build_command(self, target: Path, report_path: Path) -> list[str]:
        """Assemble the `java -jar spotbugs.jar -textui ...` argument list."""
        return [
            str(self._config.java_executable),
            "-jar",
            str(self._config.spotbugs_jar),
            "-textui",
            f"-effort:{self._config.effort}",
            "-pluginList",
            self._joined_plugin_jars(),
            "-sarif",
            "-output",
            str(report_path),
            str(target),
        ]

    def _joined_plugin_jars(self) -> str:
        """SpotBugs expects multiple plugin jars separated by the path separator.

        We use ':' (the separator on macOS/Linux, which is our target here).
        """
        return ":".join(str(jar) for jar in self._config.plugin_jars)

    def _read_report(self, report_path: Path) -> ScanResult:
        """Load and parse the SARIF report, reusing the shared parser."""
        if not report_path.exists():
            raise RuntimeError(
                "SpotBugs did not produce a report; check the Java, SpotBugs jar, "
                "and plugin jar paths, and that the target contains compiled "
                "classes (build the project first)."
            )
        report = json.loads(report_path.read_text(encoding="utf-8"))
        return parse_sarif_report(report)
