"""Tests for the RoutingAnalyzer and the SpotBugs (Java) adapter wiring."""

from pathlib import Path

from code_security_mcp.adapters.routing_analyzer import RoutingAnalyzer
from code_security_mcp.adapters.spotbugs_analyzer import JavaAnalyzer, SpotBugsConfig
from code_security_mcp.domain.models import Finding, ScanResult, Severity


class _FakeLanguageAnalyzer:
    """A language analyzer that supports a fixed extension and returns one finding."""

    def __init__(self, extension: str, rule_id: str) -> None:
        self._extension = extension
        self._rule_id = rule_id

    def supports(self, target: Path) -> bool:
        return target.suffix == self._extension

    def scan(self, target: Path) -> ScanResult:
        return ScanResult(
            findings=(Finding(self._rule_id, "m", str(target), 1, Severity.WARNING),)
        )


def test_router_runs_only_supporting_analyzers():
    kotlin = _FakeLanguageAnalyzer(".kt", "KotlinRule")
    java = _FakeLanguageAnalyzer(".class", "JavaRule")
    router = RoutingAnalyzer((kotlin, java))

    result = router.scan(Path("App.kt"))

    # Only the Kotlin analyzer supports a .kt file.
    assert result.count == 1
    assert result.findings[0].rule_id == "KotlinRule"


def test_router_merges_findings_from_all_supporting_analyzers(tmp_path):
    # Two analyzers that both support directories (via the fake's suffix "").
    a = _FakeLanguageAnalyzer("", "RuleA")
    b = _FakeLanguageAnalyzer("", "RuleB")
    router = RoutingAnalyzer((a, b))

    result = router.scan(tmp_path)  # a directory has an empty suffix

    rule_ids = {finding.rule_id for finding in result.findings}
    assert rule_ids == {"RuleA", "RuleB"}


def test_java_analyzer_skips_itself_when_spotbugs_missing(tmp_path):
    # Point at a non-existent SpotBugs jar: supports() must return False so the
    # router transparently skips Java analysis instead of failing.
    config = SpotBugsConfig(
        java_executable=Path("/usr/bin/java"),
        spotbugs_jar=tmp_path / "does-not-exist.jar",
        plugin_jars=(tmp_path / "fsb.jar",),
    )
    analyzer = JavaAnalyzer(config)

    a_class = tmp_path / "Foo.class"
    a_class.write_bytes(b"\xca\xfe\xba\xbe")  # a fake .class file
    assert analyzer.supports(a_class) is False


def test_java_analyzer_command_is_well_formed(tmp_path):
    spotbugs = tmp_path / "spotbugs.jar"
    spotbugs.write_text("")  # exists, so supports() would pass availability
    plugin = tmp_path / "findsecbugs.jar"
    config = SpotBugsConfig(
        java_executable=Path("/opt/java/bin/java"),
        spotbugs_jar=spotbugs,
        plugin_jars=(plugin,),
    )
    analyzer = JavaAnalyzer(config)

    command = analyzer._build_command(tmp_path / "classes", tmp_path / "out.sarif")

    # The essentials must be present and in a sane shape.
    assert command[0] == "/opt/java/bin/java"
    assert "-textui" in command
    assert "-sarif" in command
    assert "-pluginList" in command
    assert str(plugin) in command
