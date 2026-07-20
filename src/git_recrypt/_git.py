"""Low-level git plumbing helpers."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from pathlib import Path

_GIT: Final = "/usr/bin/git"


def get_commit_list(repo_path: Path) -> list[str]:
    """Return list of commit SHAs in rev-list order (newest first).

    Args:
        repo_path: Path to the git repository.

    Returns:
        List of full SHA strings.
    """
    result = subprocess.run(  # noqa: S603
        [_GIT, "rev-list", "--all"],
        cwd=repo_path,
        capture_output=True,
        check=True,
    )
    output: str = result.stdout.decode().strip()
    if not output:
        return []
    return output.splitlines()


def get_file_list(repo_path: Path, sha: str) -> list[str]:
    """Return list of file paths in a commit tree.

    Args:
        repo_path: Path to the git repository.
        sha: Commit SHA to inspect.

    Returns:
        List of file paths relative to repo root.
    """
    result = subprocess.run(  # noqa: S603
        [_GIT, "ls-tree", "-r", "--name-only", sha],
        cwd=repo_path,
        capture_output=True,
        check=True,
    )
    output: str = result.stdout.decode().strip()
    if not output:
        return []
    return output.splitlines()


def get_file_content(repo_path: Path, sha: str, filepath: str) -> bytes:
    """Return raw blob bytes for a file at a given commit.

    Args:
        repo_path: Path to the git repository.
        sha: Commit SHA.
        filepath: File path relative to repo root.

    Returns:
        Raw bytes of the file blob.
    """
    result = subprocess.run(  # noqa: S603
        [_GIT, "show", f"{sha}:{filepath}"],
        cwd=repo_path,
        capture_output=True,
        check=True,
    )
    return result.stdout
