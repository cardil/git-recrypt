"""Git plumbing helpers for the patch-replay architecture."""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from git_recrypt._shellout import GIT as _GIT
from git_recrypt._shellout import find_git_crypt
from git_recrypt.errors import RewriteError

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True, slots=True)
class CommitMeta:
    """Author or committer metadata for a commit."""

    name: str
    email: str
    date: str  # git internal format: "<unix-timestamp> <tz-offset>"


@dataclass(frozen=True, slots=True)
class CommitInfo:
    """Full metadata for a single commit."""

    author: CommitMeta
    committer: CommitMeta
    message: str
    parents: list[str]


def _exc_stderr(exc: subprocess.CalledProcessError) -> str:
    val: object = getattr(exc, "stderr", None)
    raw: bytes = val if isinstance(val, bytes) else b""
    return raw.decode(errors="replace") if raw else "unknown"


def git_init(path: Path, *, branch: str) -> None:
    try:
        _ = subprocess.run(  # noqa: S603
            [_GIT, "init", "-b", branch, str(path)],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as exc:
        raise RewriteError(
            phase="init",
            detail=f"git init failed: {_exc_stderr(exc)}",
        ) from exc


def read_commit_meta(repo: Path, sha: str) -> CommitInfo:
    fmt = "%P%n%an%n%ae%n%aI%n%cn%n%ce%n%cI%n%B"
    try:
        result = subprocess.run(  # noqa: S603
            [_GIT, "show", "-s", f"--format={fmt}", sha],
            capture_output=True,
            check=True,
            cwd=repo,
        )
    except subprocess.CalledProcessError as exc:
        raise RewriteError(
            phase="read-commit",
            detail=f"git show failed for {sha}: {_exc_stderr(exc)}",
        ) from exc

    lines = result.stdout.decode(errors="replace").split("\n", 7)
    parents_raw = lines[0].strip()
    parents = parents_raw.split() if parents_raw else []
    author = CommitMeta(name=lines[1], email=lines[2], date=lines[3])
    committer = CommitMeta(name=lines[4], email=lines[5], date=lines[6])
    message = lines[7].rstrip("\n") if len(lines) > 7 else ""  # noqa: PLR2004
    return CommitInfo(
        author=author, committer=committer, message=message, parents=parents
    )


def list_commits_topo(repo: Path, branch: str = "HEAD") -> list[str]:
    """Return all commits oldest-first in topological order for the given branch."""
    try:
        result = subprocess.run(  # noqa: S603
            [_GIT, "rev-list", "--reverse", "--topo-order", branch],
            capture_output=True,
            check=True,
            cwd=repo,
        )
    except subprocess.CalledProcessError as exc:
        raise RewriteError(
            phase="rev-list",
            detail=f"git rev-list failed: {_exc_stderr(exc)}",
        ) from exc
    output = result.stdout.decode().strip()
    return output.splitlines() if output else []


def run_git_crypt(repo: Path, args: list[str]) -> None:
    try:
        git_crypt = find_git_crypt()
    except RuntimeError:
        raise RewriteError(
            phase="git-crypt",
            detail="git-crypt not found in PATH. Install it first.",
        ) from None
    try:
        _ = subprocess.run(  # noqa: S603
            [git_crypt, *args],
            cwd=repo,
            capture_output=True,
            check=True,
        )
    except FileNotFoundError:
        raise RewriteError(
            phase="git-crypt",
            detail="git-crypt not found in PATH. Install it first.",
        ) from None
    except subprocess.CalledProcessError as exc:
        raise RewriteError(
            phase="git-crypt",
            detail=f"git-crypt {' '.join(args)} failed: {_exc_stderr(exc)}",
        ) from exc


def now_git_date() -> str:
    return f"{int(time.time())} +0000"
