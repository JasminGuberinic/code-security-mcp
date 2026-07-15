"""Unit tests for the SARIF -> Finding translation.

These tests hand-build the exact JSON shape detekt emits, so we verify our
parsing logic without ever launching a JVM. Fast, deterministic, and they pin
down every field mapping we care about.
"""

from kotlin_security_mcp.adapters.sarif import parse_sarif_report
from kotlin_security_mcp.domain.models import Severity


def _sarif_with_one_result() -> dict:
    """A minimal but realistic SARIF document containing a single finding."""
    return {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "detekt.MyRuleSet.WebClientInsecureSsl",
                        "level": "error",
                        "message": {"text": "WebClient trusts all certificates."},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "file:///Users/me/app/Http%20Client.kt"
                                    },
                                    "region": {"startLine": 27},
                                }
                            }
                        ],
                    }
                ]
            }
        ]
    }


def test_parses_all_core_fields() -> None:
    result = parse_sarif_report(_sarif_with_one_result())

    assert result.count == 1
    finding = result.findings[0]
    # The namespaced id is trimmed down to the clean rule name.
    assert finding.rule_id == "WebClientInsecureSsl"
    assert finding.message == "WebClient trusts all certificates."
    assert finding.severity is Severity.ERROR
    assert finding.line == 27
    # The file:// scheme is stripped and %20 is decoded back to a space.
    assert finding.file_path == "/Users/me/app/Http Client.kt"


def test_empty_report_is_a_clean_result() -> None:
    # No runs at all must mean "nothing found", not an error.
    result = parse_sarif_report({})
    assert result.has_findings is False
    assert result.count == 0


def test_unknown_level_defaults_to_warning() -> None:
    report = _sarif_with_one_result()
    report["runs"][0]["results"][0]["level"] = "something-weird"
    result = parse_sarif_report(report)
    assert result.findings[0].severity is Severity.WARNING
