"""Tree-based replay helpers: extract source trees into target with git-crypt."""

from __future__ import annotations

import os
import subprocess
from typing import TYPE_CHECKING, Final

from git_recrypt.errors import RewriteError

if TYPE_CHECKING:
    from pathlib import Path

    from git_recrypt._replay import CommitInfo

_GIT: Final = "/usr/bin/git"
_GIT_CRYPT: Final = "git-crypt"
_TAR: Final = "/usr/bin/tar"


def apply_tree(src: Path, tgt: Path, sha: str) -> None:
    """Sync target working tree to match source commit tree.

    Reads raw blobs via git cat-file (no filters), writes them into the target
    working directory, removes files absent from the source tree (excluding
    .gitattributes), then stages all changes with git add -A so git-crypt's
    clean filter encrypts matching files automatically.
    """
    _extract_tree(src, tgt, sha)
    _remove_deleted_files(src, tgt, sha)
    _ = _git(["add", "-A"], tgt)


def commit_with_meta(tgt: Path, meta: CommitInfo) -> str:
    """Create a commit in tgt preserving original author/committer/message."""
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": meta.author.name,
        "GIT_AUTHOR_EMAIL": meta.author.email,
        "GIT_AUTHOR_DATE": meta.author.date,
        "GIT_COMMITTER_NAME": meta.committer.name,
        "GIT_COMMITTER_EMAIL": meta.committer.email,
        "GIT_COMMITTER_DATE": meta.committer.date,
    }
    cmd = [
        _GIT, "-c", "commit.gpgsign=false",
        "commit", "--allow-empty", "-m", meta.message,
    ]
    r = subprocess.run(  # noqa: S603
        cmd,
        cwd=tgt,
        capture_output=True,
        check=False,
        env=env,
    )
    if r.returncode != 0:
        raw: bytes = r.stderr or b""
        raise RewriteError(
            phase="commit",
            detail=f"git commit failed: {raw.decode(errors='replace')}",
        )
    return rev_parse_head(tgt)


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


def rev_parse_head(repo: Path) -> str:
    """Return the SHA of HEAD in repo."""
    return _git(["rev-parse", "HEAD"], repo).decode().strip()


def _git(args: list[str], cwd: Path) -> bytes:
    r = subprocess.run(  # noqa: S603
        [_GIT, *args], cwd=cwd, capture_output=True, check=False
    )
    if r.returncode != 0:
        raw: bytes = r.stderr or b""
        raise RewriteError(
            phase=args[0],
            detail=f"git {args[0]} failed: {raw.decode(errors='replace')}",
        )
    return r.stdout or b""


def _extract_tree(src: Path, tgt: Path, sha: str) -> None:
    """Extract source commit's tree into target working dir via git archive.

    Single subprocess pipe per commit instead of per-file.
    """
    archive = subprocess.Popen(  # noqa: S603
        [_GIT, "archive", "--format=tar", sha],
        cwd=src,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    untar = subprocess.Popen(  # noqa: S603
        [_TAR, "xf", "-", "--exclude=.gitattributes"],
        cwd=tgt,
        stdin=archive.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if archive.stdout is not None:
        archive.stdout.close()
    _, tar_err = untar.communicate()
    arc_ret = archive.wait()
    if arc_ret != 0:
        raw: bytes = archive.stderr.read() if archive.stderr else b""
        raise RewriteError(
            phase="archive",
            detail=f"git archive failed: {raw.decode(errors='replace')}",
        )
    if untar.returncode != 0:
        raise RewriteError(
            phase="archive",
            detail=f"tar extract failed: {tar_err.decode(errors='replace')}",
        )


def _remove_deleted_files(src: Path, tgt: Path, sha: str) -> None:
    src_files = set(
        _git(["ls-tree", "-r", "--name-only", sha], src).decode().splitlines()
    )
    tgt_files = _git(["ls-files"], tgt).decode().splitlines()
    for fp in tgt_files:
        if fp == ".gitattributes" or fp in src_files:
            continue
        full = tgt / fp
        if full.exists():
            full.unlink()
        _remove_empty_parents(full.parent, tgt)


def _remove_empty_parents(parent: Path, stop: Path) -> None:
    while parent != stop:
        try:
            parent.rmdir()
        except OSError:
            break
        parent = parent.parent
