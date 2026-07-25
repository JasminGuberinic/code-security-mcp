"""Make integration tests runnable in any runner (PyCharm, CLI) without manually
exporting KSM_* environment variables.

`scripts/setup.sh` installs every analyzer into ~/.cache/code-security-mcp. Here
we auto-discover those and populate the KSM_* variables the analyzers read — but
ONLY when a variable is not already set and the file actually exists. On a machine
without the cache (e.g. CI), nothing is set, so the analyzers stay unconfigured
and their tests self-skip. This is purely a developer convenience for debugging.
"""

from __future__ import annotations

import glob
import os
from pathlib import Path

_CACHE = Path.home() / ".cache" / "code-security-mcp"


def _set_if_unset(name: str, value: str | None) -> None:
    """Set an env var only when it is missing and we actually found a value."""
    if value and not os.environ.get(name):
        os.environ[name] = value


def _first_match(pattern: str) -> str | None:
    """Return the first path in the cache matching a glob, or None."""
    hits = sorted(glob.glob(str(_CACHE / pattern)))
    return hits[0] if hits else None


def _discover_java() -> str | None:
    """Find a `java` binary (Homebrew locations first, then JAVA_HOME)."""
    candidates = [
        "/opt/homebrew/opt/openjdk@21/bin/java",
        "/opt/homebrew/opt/openjdk/bin/java",
    ]
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidates.append(str(Path(java_home) / "bin" / "java"))
    return next((c for c in candidates if Path(c).exists()), None)


def pytest_configure(config) -> None:
    """Populate KSM_* from the setup.sh cache before any test runs."""
    if not _CACHE.is_dir():
        return

    java = os.environ.get("KSM_JAVA") or _discover_java()

    # Kotlin (detekt) and Java (SpotBugs + FindSecBugs) both run on the JVM.
    _set_if_unset("KSM_JAVA", java)
    _set_if_unset("KSM_DETEKT_CLI_JAR", _first_match("detekt-cli-*-all.jar"))
    scanner_jars = sorted(glob.glob(str(_CACHE / "scanner-*.jar")))
    if scanner_jars:
        _set_if_unset("KSM_PLUGIN_JARS", ",".join(scanner_jars))
    _set_if_unset("KSM_SPOTBUGS_JAR", _first_match("spotbugs-*/lib/spotbugs.jar"))
    _set_if_unset("KSM_FINDSECBUGS_JARS", _first_match("findsecbugs-plugin-*.jar"))

    # C# (Roslyn / isolated .NET SDK).
    if (_CACHE / "dotnet").is_dir():
        _set_if_unset("KSM_DOTNET_ROOT", str(_CACHE / "dotnet"))
        _set_if_unset("KSM_NUGET_PACKAGES", str(_CACHE / "nuget"))
        _set_if_unset("KSM_DOTNET_CLI_HOME", str(_CACHE / "dotnet-home"))

    # JS/TS (ESLint). Its shebang needs `node` on PATH — Homebrew's is common.
    _set_if_unset("KSM_ESLINT_BIN", _first_match("eslint/node_modules/.bin/eslint"))
    _set_if_unset("KSM_ESLINT_CONFIG", _first_match("eslint/security.config.mjs"))
    homebrew_bin = "/opt/homebrew/bin"
    if Path(homebrew_bin, "node").exists() and homebrew_bin not in os.environ.get("PATH", ""):
        os.environ["PATH"] = homebrew_bin + os.pathsep + os.environ.get("PATH", "")
