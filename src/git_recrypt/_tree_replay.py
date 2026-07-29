"""Tree-based replay helpers: extract source trees into target with git-crypt."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

_GIT_CRYPT: str = "git-crypt"


def count_encrypted_files(repo: Path) -> int:
    """Count files marked encrypted by git-crypt status in the repo."""
    r = subprocess.run(  # noqa: S603
        [_GIT_CRYPT, "status"],
        cwd=repo,
        capture_output=True,
        check=False,
    )
    if r.returncode != 0:
        return 0
    return sum(
        1
        for line in r.stdout.decode(errors="replace").splitlines()
        if line.startswith("    encrypted:")
    )
