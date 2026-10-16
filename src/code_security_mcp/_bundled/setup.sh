#!/usr/bin/env bash
#
# One-command setup for code-security-mcp's analyzers.
#
# It downloads every analyzer into an isolated cache directory (nothing global is
# touched) and prints the exact `claude mcp add` command to register the server.
# Re-running is safe: anything already present is skipped.
#
# By default it sets up the JVM analyzers (Kotlin + Java), which are pure
# downloads. Pass flags to also set up the heavier, runtime-dependent ones:
#
#   ./scripts/setup.sh                 # Kotlin + Java
#   ./scripts/setup.sh --with-dotnet   # also C#  (installs an isolated .NET SDK)
#   ./scripts/setup.sh --with-eslint   # also JS/TS (needs node + npm on PATH)
#
set -euo pipefail

# ── Where everything lives. Override with KSM_CACHE if you like. ───────────────
CACHE="${KSM_CACHE:-$HOME/.cache/code-security-mcp}"
mkdir -p "$CACHE"

# ── Pinned versions (bump here when upgrading a tool). ────────────────────────
DETEKT_VERSION="1.23.7"
SCANNER_VERSION="0.3.0"
SPOTBUGS_VERSION="4.8.6"
FINDSECBUGS_VERSION="1.13.0"
DOTNET_CHANNEL="8.0"

MAVEN="https://repo1.maven.org/maven2"
SCANNER_MODULES=(core spring-boot quarkus ktor micronaut dropwizard vertx)

WITH_DOTNET=false
WITH_ESLINT=false
for arg in "$@"; do
  case "$arg" in
    --with-dotnet) WITH_DOTNET=true ;;
    --with-eslint) WITH_ESLINT=true ;;
    *) echo "Unknown flag: $arg" >&2; exit 1 ;;
  esac
done

# Download a URL to a path only if it is not already there.
fetch() {
  local url="$1" dest="$2"
  if [[ -f "$dest" ]]; then
    echo "  ✓ $(basename "$dest") (cached)"
    return
  fi
  echo "  ↓ $(basename "$dest")"
  curl -fSL --retry 3 -o "$dest" "$url"
}

# ── Kotlin: detekt CLI (fat jar) + the framework ruleset from Maven Central ───
setup_kotlin() {
  echo "Kotlin (detekt)…"
  local zip="$CACHE/detekt-cli-${DETEKT_VERSION}.zip"
  local cli="$CACHE/detekt-cli-${DETEKT_VERSION}-all.jar"
  if [[ ! -f "$cli" ]]; then
    fetch "https://github.com/detekt/detekt/releases/download/v${DETEKT_VERSION}/detekt-cli-${DETEKT_VERSION}.zip" "$zip"
    unzip -oq "$zip" -d "$CACHE/detekt-tmp"
    cp "$CACHE/detekt-tmp/detekt-cli-${DETEKT_VERSION}/lib/detekt-cli-${DETEKT_VERSION}-all.jar" "$cli"
    rm -rf "$CACHE/detekt-tmp" "$zip"
    echo "  ✓ detekt-cli-${DETEKT_VERSION}-all.jar"
  else
    echo "  ✓ detekt-cli (cached)"
  fi
  local jars=()
  for module in "${SCANNER_MODULES[@]}"; do
    local jar="$CACHE/scanner-${module}-${SCANNER_VERSION}.jar"
    fetch "${MAVEN}/io/github/jasminguberinic/scanner-${module}/${SCANNER_VERSION}/scanner-${module}-${SCANNER_VERSION}.jar" "$jar"
    jars+=("$jar")
  done
  # Remember the comma-separated plugin jar list for the final command.
  KSM_PLUGIN_JARS="$(IFS=,; echo "${jars[*]}")"
}

# ── Java: SpotBugs distribution + the FindSecBugs plugin ──────────────────────
setup_java() {
  echo "Java (SpotBugs + FindSecBugs)…"
  local zip="$CACHE/spotbugs-${SPOTBUGS_VERSION}.zip"
  if [[ ! -d "$CACHE/spotbugs-${SPOTBUGS_VERSION}" ]]; then
    fetch "https://github.com/spotbugs/spotbugs/releases/download/${SPOTBUGS_VERSION}/spotbugs-${SPOTBUGS_VERSION}.zip" "$zip"
    unzip -oq "$zip" -d "$CACHE"
    rm -f "$zip"
    echo "  ✓ spotbugs-${SPOTBUGS_VERSION}/"
  else
    echo "  ✓ spotbugs (cached)"
  fi
  fetch "${MAVEN}/com/h3xstream/findsecbugs/findsecbugs-plugin/${FINDSECBUGS_VERSION}/findsecbugs-plugin-${FINDSECBUGS_VERSION}.jar" \
        "$CACHE/findsecbugs-plugin-${FINDSECBUGS_VERSION}.jar"
}

# ── C#: an isolated .NET SDK (opt-in; ~200 MB). Nothing global is changed. ─────
setup_dotnet() {
  echo "C# (.NET SDK, isolated)…"
  if [[ -x "$CACHE/dotnet/dotnet" ]]; then
    echo "  ✓ .NET SDK (cached)"
    return
  fi
  curl -fSL --retry 3 -o "$CACHE/dotnet-install.sh" https://dot.net/v1/dotnet-install.sh
  chmod +x "$CACHE/dotnet-install.sh"
  "$CACHE/dotnet-install.sh" --channel "$DOTNET_CHANNEL" --install-dir "$CACHE/dotnet" --no-path
}

# ── JS/TS: an isolated ESLint + eslint-plugin-security install (needs node). ───
setup_eslint() {
  echo "JS/TS (ESLint + eslint-plugin-security)…"
  if ! command -v npm >/dev/null 2>&1; then
    echo "  ! npm not found on PATH — install Node.js, then re-run with --with-eslint" >&2
    return
  fi
  local dir="$CACHE/eslint"
  mkdir -p "$dir"
  if [[ ! -d "$dir/node_modules/eslint" ]]; then
    echo '{"name":"cs-mcp-eslint","private":true,"type":"module"}' > "$dir/package.json"
    (cd "$dir" && npm install --silent --no-fund --no-audit eslint eslint-plugin-security typescript-eslint)
  fi
  # Ship the flat config next to the node_modules so ESLint can resolve plugins.
  cp "$(dirname "$0")/../configs/eslint.security.config.mjs" "$dir/security.config.mjs"
  echo "  ✓ eslint + plugins"
}

echo "Setting up analyzers in: $CACHE"
echo
setup_kotlin
setup_java
$WITH_DOTNET && setup_dotnet
$WITH_ESLINT && setup_eslint

# ── Emit the registration command with everything we set up. ──────────────────
echo
echo "Done. Register the server with Claude Code:"
echo
echo "claude mcp add code-security -s user \\"
echo "  -e KSM_JAVA=\"\$(/usr/libexec/java_home 2>/dev/null || echo java)\"/bin/java \\"
echo "  -e KSM_DETEKT_CLI_JAR=\"$CACHE/detekt-cli-${DETEKT_VERSION}-all.jar\" \\"
echo "  -e KSM_PLUGIN_JARS=\"$KSM_PLUGIN_JARS\" \\"
echo "  -e KSM_SPOTBUGS_JAR=\"$CACHE/spotbugs-${SPOTBUGS_VERSION}/lib/spotbugs.jar\" \\"
echo "  -e KSM_FINDSECBUGS_JARS=\"$CACHE/findsecbugs-plugin-${FINDSECBUGS_VERSION}.jar\" \\"
$WITH_DOTNET && echo "  -e KSM_DOTNET_ROOT=\"$CACHE/dotnet\" -e KSM_NUGET_PACKAGES=\"$CACHE/nuget\" -e KSM_DOTNET_CLI_HOME=\"$CACHE/dotnet-home\" \\"
$WITH_ESLINT && echo "  -e KSM_ESLINT_BIN=\"$CACHE/eslint/node_modules/.bin/eslint\" -e KSM_ESLINT_CONFIG=\"$CACHE/eslint/security.config.mjs\" \\"
echo "  -- code-security-mcp"
echo
echo "(For Python, just: pip install bandit)"
