"""Shared executable discovery for git, gpg, diff, and git-crypt."""

from __future__ import annotations

import shutil
from typing import Final


def find_git() -> str:
    """Find git binary in PATH or raise RuntimeError."""
    path = shutil.which("git")
    if path is None:
        msg = "git not found in PATH"
        raise RuntimeError(msg)
    return path


def find_gpg() -> str:
    """Find gpg binary in PATH or raise RuntimeError."""
    path = shutil.which("gpg") or shutil.which("gpg2")
    if path is None:
        msg = "gpg not found in PATH; required for GPG mode"
        raise RuntimeError(msg)
    return path


def find_diff() -> str | None:
    """Find diff binary in PATH, or return None."""
    return shutil.which("diff")


def find_git_crypt() -> str:
    """Find git-crypt binary in PATH or raise RuntimeError."""
    path = shutil.which("git-crypt")
    if path is None:
        msg = "git-crypt not found in PATH; required for rewriting"
        raise RuntimeError(msg)
    return path


GIT: Final[str] = find_git()
# GIT_CRYPT is NOT validated at import time so that non-rewrite commands
# (detect, init, verify) work without git-crypt installed.  Runtime callers
# use find_git_crypt() which raises RuntimeError if missing.
GIT_CRYPT: Final[str] = "git-crypt"


def get_git_crypt() -> str:
    """Return validated git-crypt path. Cached after first call."""
    return find_git_crypt()
