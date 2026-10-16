"""The SuggestSecurePatternUseCase: answer "how do I do X securely?".

Like ScanCodeUseCase, it depends only on a domain port (SecurePatternCatalog),
so the curated catalog we ship today can later become anything without touching
this layer or the MCP server.
"""

from __future__ import annotations

from dataclasses import dataclass

from code_security_mcp.domain.patterns import SecurePattern
from code_security_mcp.domain.ports import SecurePatternCatalog


@dataclass(frozen=True)
class SecurePatternSuggestion:
    """Patterns for a task, and whether the framework filter had to be dropped.

    `widened` is true when the caller named a framework, that search found
    nothing, and the answer therefore comes from other stacks. The advice is
    still worth having — Secure/HttpOnly/SameSite is the same idea everywhere —
    but the caller has to adapt the snippet, so we say so rather than pretending
    the match was exact.
    """

    patterns: tuple[SecurePattern, ...]
    widened: bool = False


class SuggestSecurePatternUseCase:
    """Recommend secure code patterns for a described task."""

    def __init__(self, catalog: SecurePatternCatalog) -> None:
        # The source of recipes, injected so tests can supply a tiny catalog.
        self._catalog = catalog

    def execute(self, framework: str | None, task: str) -> SecurePatternSuggestion:
        """Look up patterns for `task`, optionally narrowed to `framework`.

        We treat a blank task as a usage error: without something to search for
        there is no meaningful recommendation to give.

        A framework filter that matches nothing falls back to an unfiltered
        search. Returning an empty list there would read as "this task has no
        secure pattern", which is a dangerous thing to tell an agent when the
        catalog does hold advice for it under another framework.
        """
        if not task.strip():
            raise ValueError("A non-empty task description is required.")

        narrowed = self._catalog.find(framework, task)
        if narrowed or not self._is_narrowing(framework):
            return SecurePatternSuggestion(narrowed)

        # Only call it widened if dropping the filter actually found something;
        # an empty result is just an empty result, whichever way we searched.
        widened = self._catalog.find(None, task)
        return SecurePatternSuggestion(widened, widened=bool(widened))

    @staticmethod
    def _is_narrowing(framework: str | None) -> bool:
        """True when the caller actually asked to narrow by framework."""
        return bool(framework and framework.strip())
