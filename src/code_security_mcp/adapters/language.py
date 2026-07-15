"""A tiny helper shared by analyzers: does a target contain files I handle?

Each analyzer owns a set of file extensions. Whether it should run on a given
target is the same question every time — "is this a file with one of my
extensions, or a directory that contains at least one?" — so we answer it once,
here, instead of repeating it in every adapter.
"""

from __future__ import annotations

from pathlib import Path


def target_has_extension(target: Path, extensions: tuple[str, ...]) -> bool:
    """True if `target` is (or, for a directory, contains) a matching file.

    Directory checks stop at the first match (`next(..., None)`), so we never
    walk an entire tree just to answer yes.
    """
    if target.is_file():
        return target.suffix in extensions
    if target.is_dir():
        return any(
            next(target.rglob(f"*{extension}"), None) is not None
            for extension in extensions
        )
    return False
