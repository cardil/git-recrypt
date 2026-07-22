"""Tests for git_recrypt.rewriter -- TDD, Given/When/Then."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest

from git_recrypt.errors import RewriteError
from git_recrypt.manifest import KeyConfig, Manifest, SymmetricKeyConfig
from git_recrypt.rewriter import HistoryRewriter, RewriteConfig

if TYPE_CHECKING:
    from pathlib import Path

_GIT = "/usr/bin/git"
_GITCRYPT_HEADER = b"\x00GITCRYPT\x00"


def _make_manifest(
    patterns: list[str],
    exclude: list[str] | None = None,
    introduce_at: str = "root",
    key_file_path: str = "dummy",
) -> Manifest:
    return Manifest(
        version=1,
        key=KeyConfig(symmetric=SymmetricKeyConfig(key_file=key_file_path)),
        patterns=patterns,
        exclude=exclude or [],
        introduce_at=introduce_at,
    )


def _git_show(path: str, cwd: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603
        [_GIT, "show", f"HEAD:{path}"],
        cwd=cwd,
        capture_output=True,
        check=False,
    )


@dataclass
class _RW:
    repo: Path
    key_file: Path
    work_parent: Path
    patterns: list[str]
    exclude: list[str] | None = None
    introduce_at: str = "root"


def _run_rewrite(rw: _RW) -> Path:
    manifest = _make_manifest(
        patterns=rw.patterns,
        exclude=rw.exclude,
        introduce_at=rw.introduce_at,
        key_file_path=str(rw.key_file),
    )
    config = RewriteConfig(
        manifest=manifest,
        key_file=rw.key_file,
        repo_path=rw.repo,
        work_dir=rw.work_parent / "work",
    )
    result = HistoryRewriter(config).run()
    return result.work_dir


def test_clone_creates_work_dir(
    tmp_git_repo: Path, sample_key_file: Path, tmp_path: Path
) -> None:
    manifest = _make_manifest(patterns=["*.env"])
    config = RewriteConfig(
        manifest=manifest,
        key_file=sample_key_file,
        repo_path=tmp_git_repo,
        work_dir=tmp_path / "work",
    )
    result = HistoryRewriter(config).run()

    assert result.work_dir.exists()
    assert (result.work_dir / ".git").is_dir()


def test_simple_rewrite_from_root(
    tmp_git_repo: Path, sample_key_file: Path, tmp_path: Path
) -> None:
    work_dir = _run_rewrite(
        _RW(
            repo=tmp_git_repo,
            key_file=sample_key_file,
            work_parent=tmp_path,
            patterns=[".env", "secrets/**"],
            introduce_at="root",
        )
    )

    ga = _git_show(".gitattributes", work_dir)
    assert ga.returncode == 0

    env_result = _git_show(".env", work_dir)
    assert env_result.returncode == 0
    assert env_result.stdout.startswith(_GITCRYPT_HEADER)

    key_result = _git_show("secrets/api.key", work_dir)
    assert key_result.returncode == 0
    assert key_result.stdout.startswith(_GITCRYPT_HEADER)


def test_non_matching_files_unchanged(
    tmp_git_repo: Path, sample_key_file: Path, tmp_path: Path
) -> None:
    work_dir = _run_rewrite(
        _RW(
            repo=tmp_git_repo,
            key_file=sample_key_file,
            work_parent=tmp_path,
            patterns=[".env", "secrets/**"],
        )
    )

    readme = _git_show("README.md", work_dir)
    assert readme.returncode == 0
    assert readme.stdout == b"# Test Repo\n"


def test_encrypt_idempotent(
    tmp_git_repo: Path, sample_key_file: Path, tmp_path: Path
) -> None:
    work_dir = _run_rewrite(
        _RW(
            repo=tmp_git_repo,
            key_file=sample_key_file,
            work_parent=tmp_path,
            patterns=[".env"],
        )
    )

    first_env = _git_show(".env", work_dir)
    assert first_env.stdout.startswith(_GITCRYPT_HEADER)

    manifest = _make_manifest(patterns=[".env"])
    config = RewriteConfig(
        manifest=manifest,
        key_file=sample_key_file,
        repo_path=work_dir,
        work_dir=tmp_path / "work2",
    )
    with pytest.raises(RewriteError, match="encrypted files"):
        HistoryRewriter(config).run()


def test_rewrite_result_has_counts(
    tmp_git_repo: Path, sample_key_file: Path, tmp_path: Path
) -> None:
    manifest = _make_manifest(patterns=[".env", "secrets/**"])
    config = RewriteConfig(
        manifest=manifest,
        key_file=sample_key_file,
        repo_path=tmp_git_repo,
        work_dir=tmp_path / "work",
    )
    result = HistoryRewriter(config).run()

    assert result.commits_rewritten > 0
    assert result.files_encrypted > 0
    assert result.elapsed_seconds > 0


def test_invalid_repo_path_raises(sample_key_file: Path, tmp_path: Path) -> None:
    manifest = _make_manifest(patterns=[".env"])
    config = RewriteConfig(
        manifest=manifest,
        key_file=sample_key_file,
        repo_path=tmp_path / "nonexistent",
        work_dir=tmp_path / "work",
    )
    with pytest.raises(RewriteError, match="Source repo not found"):
        _ = HistoryRewriter(config).run()


def test_patterns_that_match_nothing_still_injects_gitattributes(
    tmp_git_repo: Path, sample_key_file: Path, tmp_path: Path
) -> None:
    work_dir = _run_rewrite(
        _RW(
            repo=tmp_git_repo,
            key_file=sample_key_file,
            work_parent=tmp_path,
            patterns=["*.nonexistent_extension_xyz"],
        )
    )

    ga = _git_show(".gitattributes", work_dir)
    assert ga.returncode == 0


def test_git_init_creates_master_branch(tmp_path: Path) -> None:
    # Given: a fresh directory
    from git_recrypt._replay import git_init  # noqa: PLC0415

    repo = tmp_path / "init-test"

    # When: git_init creates the repo
    git_init(repo)

    # Then: HEAD points to refs/heads/master
    head_ref = subprocess.run(  # noqa: S603
        [_GIT, "symbolic-ref", "HEAD"],
        cwd=repo, capture_output=True, check=True,
    ).stdout.decode().strip()
    assert head_ref == "refs/heads/master"
