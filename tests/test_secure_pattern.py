"""Tests for the secure-pattern catalog and its use case."""

import pytest

from code_security_mcp.adapters.pattern_catalog import InMemorySecurePatternCatalog
from code_security_mcp.application.suggest_secure_pattern import (
    SuggestSecurePatternUseCase,
)


def test_finds_pattern_by_keyword():
    catalog = InMemorySecurePatternCatalog()

    results = catalog.find(framework=None, task="how do I create a session cookie")

    assert results, "expected at least one match for a cookie task"
    # The Vert.x cookie recipe should be the top hit.
    assert results[0].framework == "vertx"
    assert "setHttpOnly" in results[0].secure_example


def test_framework_narrows_but_keeps_agnostic_patterns():
    catalog = InMemorySecurePatternCatalog()

    # A secret-storage task in a Spring context: the "any" secret pattern applies.
    results = catalog.find(framework="spring-webflux", task="store a jwt secret")

    assert any(p.cwe == "CWE-798" for p in results)
    # A Ktor-only pattern must not leak into a Spring query.
    assert all(p.framework != "ktor" for p in results)


def test_no_match_returns_empty():
    catalog = InMemorySecurePatternCatalog()
    assert catalog.find(framework=None, task="completely unrelated request") == ()


def test_use_case_rejects_blank_task():
    use_case = SuggestSecurePatternUseCase(InMemorySecurePatternCatalog())
    with pytest.raises(ValueError):
        use_case.execute(framework=None, task="   ")


def test_use_case_widens_when_the_framework_filter_finds_nothing():
    """A framework with no cookie recipe must still get the cookie advice.

    Returning nothing here would tell the agent the task has no secure pattern,
    which is the one answer we must never give when the catalog does hold one.
    """
    use_case = SuggestSecurePatternUseCase(InMemorySecurePatternCatalog())

    suggestion = use_case.execute(framework="spring-webflux", task="session cookie")

    assert suggestion.widened is True
    assert [p.framework for p in suggestion.patterns] == ["vertx"]


def test_use_case_does_not_widen_when_the_framework_matches():
    use_case = SuggestSecurePatternUseCase(InMemorySecurePatternCatalog())

    suggestion = use_case.execute(framework="spring-webflux", task="current user")

    assert suggestion.widened is False
    assert all(p.framework in {"spring-webflux", "any"} for p in suggestion.patterns)


def test_use_case_reports_an_empty_result_as_not_widened():
    """Widening that also finds nothing is just an empty result."""
    use_case = SuggestSecurePatternUseCase(InMemorySecurePatternCatalog())

    suggestion = use_case.execute(framework="vertx", task="completely unrelated request")

    assert suggestion.patterns == ()
    assert suggestion.widened is False
