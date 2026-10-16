"""Console entry point that runs the bundled analyzer setup script.

Installing the server with `pipx install code-security-mcp` gets you the server
but not the repository, and the analyzers for Kotlin, Java, C# and JS/TS are
external tools that still have to be fetched. Shipping the setup script inside
the package and exposing it as `code-security-mcp-setup` means those users do
not have to clone anything to finish the install.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

_SCRIPT = Path(__file__).parent / "_bundled" / "setup.sh"


def main() -> int:
    """Run the bundled setup script, forwarding any arguments to it."""
    if os.name == "nt":
        print(
            "code-security-mcp-setup needs a POSIX shell and does not run on "
            "native Windows. Use WSL, or follow the manual steps at "
            "https://github.com/JasminGuberinic/code-security-mcp",
            file=sys.stderr,
        )
        return 1

    bash = shutil.which("bash")
    if bash is None:
        print("bash is required to run the setup script.", file=sys.stderr)
        return 1

    if not _SCRIPT.is_file():
        print(f"Setup script missing from the installed package: {_SCRIPT}", file=sys.stderr)
        return 1

    # The script is read-only inside a pipx venv, so invoke bash on it rather
    # than relying on the executable bit surviving the install.
    return subprocess.call([bash, str(_SCRIPT), *sys.argv[1:]])


if __name__ == "__main__":
    raise SystemExit(main())
