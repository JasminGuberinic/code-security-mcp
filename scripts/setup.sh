#!/usr/bin/env bash
#
# Thin wrapper kept for the documented `./scripts/setup.sh` path.
#
# The script itself lives inside the package, at
# src/code_security_mcp/_bundled/setup.sh, so that a `pipx install` user gets it
# too and can run `code-security-mcp-setup` without cloning the repository.
# One copy, one place to edit.

set -euo pipefail

exec "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/src/code_security_mcp/_bundled/setup.sh" "$@"
