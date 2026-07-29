"""Shared pytest fixtures for git-recrypt tests."""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path


def _find_bin(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        msg = f"{name} not found in PATH"
        raise RuntimeError(msg)
    return path


_GIT = _find_bin("git")
_GIT_CRYPT = _find_bin("git-crypt")

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.com",
}


def _run_git(args: list[str], cwd: Path) -> None:
    """Run a git subcommand in cwd with a deterministic author/committer env."""
    _ = subprocess.run(  # noqa: S603
        [_GIT, *args],
        check=True,
        capture_output=True,
        cwd=cwd,
        env={**os.environ, **_GIT_ENV},
    )


def _run_git_crypt(args: list[str], cwd: Path) -> None:
    """Run a git-crypt subcommand in cwd."""
    _ = subprocess.run(  # noqa: S603
        [_GIT_CRYPT, *args],
        check=True,
        capture_output=True,
        cwd=cwd,
    )


@pytest.fixture
def tmp_git_repo(tmp_path: Path) -> Path:
    """Create a temporary git repo with some commits.

    Returns the repo path.
    Creates:
    - Initial commit with README.md
    - Second commit adding secrets/api.key and .env
    - Third commit modifying .env
    """
    repo = tmp_path / "repo"
    repo.mkdir()

    _run_git(["init"], cwd=repo)
    _run_git(["config", "user.email", "test@example.com"], cwd=repo)
    _run_git(["config", "user.name", "Test"], cwd=repo)

    # Initial commit with README.md
    _ = (repo / "README.md").write_text("# Test Repo\n")
    _run_git(["add", "README.md"], cwd=repo)
    _run_git(["commit", "-m", "Initial commit"], cwd=repo)

    # Second commit: add secrets/api.key and .env
    secrets_dir = repo / "secrets"
    secrets_dir.mkdir()
    _ = (secrets_dir / "api.key").write_text("API_KEY=super-secret-value\n")
    _ = (repo / ".env").write_text("DATABASE_URL=postgres://user:pass@localhost/db\n")
    _run_git(["add", "."], cwd=repo)
    _run_git(["commit", "-m", "Add secrets"], cwd=repo)

    # Third commit: modify .env
    _ = (repo / ".env").write_text(
        "DATABASE_URL=postgres://user:pass@localhost/db\nSECRET_KEY=another-secret\n"
    )
    _run_git(["add", ".env"], cwd=repo)
    _run_git(["commit", "-m", "Update .env"], cwd=repo)

    return repo


@pytest.fixture
def sample_key_file(tmp_path: Path) -> Path:
    """Create a git-crypt key file via git-crypt init + export-key in a temp repo.

    Returns the path to the exported key file.
    """
    repo = tmp_path / "key-repo"
    repo.mkdir()

    _run_git(["init"], cwd=repo)
    _run_git(["config", "user.email", "test@example.com"], cwd=repo)
    _run_git(["config", "user.name", "Test"], cwd=repo)

    # git-crypt requires at least one commit
    _ = (repo / "README.md").write_text("# Key Repo\n")
    _run_git(["add", "README.md"], cwd=repo)
    _run_git(["commit", "-m", "init"], cwd=repo)

    _run_git_crypt(["init"], cwd=repo)

    key_file = tmp_path / "test.key"
    _run_git_crypt(["export-key", str(key_file)], cwd=repo)

    return key_file
