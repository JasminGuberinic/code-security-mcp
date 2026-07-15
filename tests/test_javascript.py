"""Tests for the ESLint (JS/TS) report parser and analyzer wiring."""

from pathlib import Path

from code_security_mcp.adapters.eslint_analyzer import EslintConfig, JavaScriptAnalyzer
from code_security_mcp.adapters.eslint_report import parse_eslint_report
from code_security_mcp.domain.models import Severity


def _eslint_json_one_file() -> list:
    """A realistic ESLint JSON report for one file with two messages."""
    return [
        {
            "filePath": "/app/handler.js",
            "messages": [
                {
                    "ruleId": "security/detect-child-process",
                    "severity": 1,
                    "message": "Found child_process.exec() with non Literal argument.",
                    "line": 3,
                },
                # A non-rule notice (no ruleId) that must be dropped.
                {"ruleId": None, "severity": 1, "message": "File ignored.", "line": 0},
            ],
        }
    ]


def test_parses_rule_messages_and_drops_notices():
    result = parse_eslint_report(_eslint_json_one_file())

    assert result.count == 1  # the ruleId-less notice is dropped
    finding = result.findings[0]
    assert finding.rule_id == "security/detect-child-process"
    assert finding.file_path == "/app/handler.js"
    assert finding.line == 3
    assert finding.severity is Severity.WARNING  # ESLint severity 1


def test_error_severity_maps_to_error():
    report = _eslint_json_one_file()
    report[0]["messages"][0]["severity"] = 2
    result = parse_eslint_report(report)
    assert result.findings[0].severity is Severity.ERROR


def test_unsupported_when_eslint_missing(tmp_path):
    config = EslintConfig(
        eslint_executable=tmp_path / "no-eslint",
        config_file=tmp_path / "security.config.mjs",
    )
    (tmp_path / "app.js").write_text("eval(x)")
    assert JavaScriptAnalyzer(config).supports(tmp_path) is False


def test_working_dir_is_target_dir_for_directories(tmp_path):
    eslint = tmp_path / "eslint"
    eslint.write_text("")
    analyzer = JavaScriptAnalyzer(
        EslintConfig(eslint_executable=eslint, config_file=tmp_path / "c.mjs")
    )

    # A directory: run inside it and lint ".".
    assert analyzer._working_dir_and_path(tmp_path) == (tmp_path, ".")
    # A file: run inside its parent and lint it by name.
    a_file = tmp_path / "a.ts"
    a_file.write_text("")
    assert analyzer._working_dir_and_path(a_file) == (tmp_path, "a.ts")
