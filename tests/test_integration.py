"""End-to-end integration tests: create repo -> rewrite -> verify."""

from __future__ import annotations

import os
import subprocess
from typing import TYPE_CHECKING, Final

from git_recrypt.crypto import GITCRYPT_HEADER, is_encrypted
from git_recrypt.manifest import KeyConfig, Manifest, SymmetricKeyConfig
from git_recrypt.patterns import PatternMatcher
from git_recrypt.rewriter import HistoryRewriter, RewriteConfig, RewriteResult
from git_recrypt.verifier import RewriteVerifier, VerifyMode, VerifyResult

if TYPE_CHECKING:
    from pathlib import Path

_GIT: Final = "/usr/bin/git"
_GIT_ENV: Final[dict[str, str]] = {
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.com",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_git(args: list[str], cwd: Path) -> None:
    _ = subprocess.run(  # noqa: S603
        [_GIT, *args],
        check=True,
        capture_output=True,
        cwd=cwd,
        env={**os.environ, **_GIT_ENV},
    )


def _git_show(repo_path: Path, ref: str, filepath: str) -> bytes:
    result = subprocess.run(  # noqa: S603
        [_GIT, "show", f"{ref}:{filepath}"],
        cwd=repo_path,
        capture_output=True,
        check=False,
    )
    return result.stdout


def _create_manifest(
    key_file: Path,
    patterns: list[str],
    exclude: list[str] | None = None,
    introduce_at: str = "root",
) -> Manifest:
    return Manifest(
        version=1,
        key=KeyConfig(symmetric=SymmetricKeyConfig(key_file=str(key_file))),
        patterns=patterns,
        exclude=exclude or [],
        introduce_at=introduce_at,
    )


def _run_rewrite(
    repo_path: Path,
    key_file: Path,
    work_dir: Path,
    manifest: Manifest,
) -> RewriteResult:
    config = RewriteConfig(
        manifest=manifest,
        key_file=key_file,
        repo_path=repo_path,
        work_dir=work_dir,
    )
    rewriter = HistoryRewriter(config)
    return rewriter.run()


def _verify_rewrite(
    original: Path,
    rewritten: Path,
    key_file: Path,
    patterns: list[str],
    exclude: list[str] | None = None,
) -> VerifyResult:
    matcher = PatternMatcher(
        include_patterns=tuple(patterns),
        exclude_patterns=tuple(exclude or []),
    )
    verifier = RewriteVerifier(
        original_path=original,
        rewritten_path=rewritten,
        key_file=key_file,
        matcher=matcher,
        mode=VerifyMode.FULL,
    )
    return verifier.verify()


# ---------------------------------------------------------------------------
# Test 1: simple rewrite from root
# ---------------------------------------------------------------------------


def test_simple_rewrite_from_root(
    tmp_git_repo: Path, sample_key_file: Path, tmp_path: Path
) -> None:
    # Given: tmp_git_repo with 3 commits (README.md, secrets/api.key, .env)
    manifest = _create_manifest(
        key_file=sample_key_file,
        patterns=[".env", "secrets/**"],
        introduce_at="root",
    )

    # When: rewrite with patterns [".env", "secrets/**"], introduce_at="root"
    result = _run_rewrite(
        repo_path=tmp_git_repo,
        key_file=sample_key_file,
        work_dir=tmp_path / "work",
        manifest=manifest,
    )
    rewritten = result.work_dir

    # Then: .gitattributes present in HEAD
    ga_content = _git_show(rewritten, "HEAD", ".gitattributes")
    assert ga_content != b""

    # .env is encrypted in HEAD
    env_content = _git_show(rewritten, "HEAD", ".env")
    assert env_content.startswith(GITCRYPT_HEADER)

    # secrets/api.key is encrypted in HEAD
    key_content = _git_show(rewritten, "HEAD", "secrets/api.key")
    assert key_content.startswith(GITCRYPT_HEADER)

    # README.md is NOT encrypted (byte-identical to original)
    readme_original = _git_show(tmp_git_repo, "HEAD", "README.md")
    readme_rewritten = _git_show(rewritten, "HEAD", "README.md")
    assert not is_encrypted(readme_rewritten)
    assert readme_rewritten == readme_original

    # Verification passes
    verify_result = _verify_rewrite(
        original=tmp_git_repo,
        rewritten=rewritten,
        key_file=sample_key_file,
        patterns=[".env", "secrets/**"],
    )
    assert verify_result.passed is True
    assert verify_result.errors == ()


# ---------------------------------------------------------------------------
# Test 2: exclude patterns
# ---------------------------------------------------------------------------


def test_exclude_patterns(sample_key_file: Path, tmp_path: Path) -> None:
    # Given: a repo with foo.key and foo.pub files
    repo = tmp_path / "exclude-repo"
    repo.mkdir()
    _run_git(["init"], cwd=repo)
    _run_git(["config", "user.email", "test@example.com"], cwd=repo)
    _run_git(["config", "user.name", "Test"], cwd=repo)

    _ = (repo / "foo.key").write_text("private-key-data\n")
    _ = (repo / "foo.pub").write_text("public-key-data\n")
    _run_git(["add", "."], cwd=repo)
    _run_git(["commit", "-m", "Add key files"], cwd=repo)

    manifest = _create_manifest(
        key_file=sample_key_file,
        patterns=["*.key"],
        exclude=["*.pub"],
    )

    # When: rewrite with patterns ["*.key"], exclude=["*.pub"]
    result = _run_rewrite(
        repo_path=repo,
        key_file=sample_key_file,
        work_dir=tmp_path / "work",
        manifest=manifest,
    )
    rewritten = result.work_dir

    key_content = _git_show(rewritten, "HEAD", "foo.key")
    assert key_content.startswith(GITCRYPT_HEADER)

    # foo.pub is NOT encrypted (excluded)
    pub_content = _git_show(rewritten, "HEAD", "foo.pub")
    assert not is_encrypted(pub_content)
    assert pub_content == b"public-key-data\n"


# ---------------------------------------------------------------------------
# Test 3: empty file encryption
# ---------------------------------------------------------------------------


def test_empty_file_encryption(sample_key_file: Path, tmp_path: Path) -> None:
    # Given: a repo with an empty secret file
    repo = tmp_path / "empty-repo"
    repo.mkdir()
    _run_git(["init"], cwd=repo)
    _run_git(["config", "user.email", "test@example.com"], cwd=repo)
    _run_git(["config", "user.name", "Test"], cwd=repo)

    _ = (repo / "empty.key").write_bytes(b"")
    _run_git(["add", "."], cwd=repo)
    _run_git(["commit", "-m", "Add empty secret"], cwd=repo)

    manifest = _create_manifest(
        key_file=sample_key_file,
        patterns=["*.key"],
    )

    # When: rewrite with patterns matching the empty file
    result = _run_rewrite(
        repo_path=repo,
        key_file=sample_key_file,
        work_dir=tmp_path / "work",
        manifest=manifest,
    )
    rewritten = result.work_dir

    # Then: empty file is encrypted (git-crypt handles empty files)
    content = _git_show(rewritten, "HEAD", "empty.key")
    assert content.startswith(GITCRYPT_HEADER)

    # Verification passes
    verify_result = _verify_rewrite(
        original=repo,
        rewritten=rewritten,
        key_file=sample_key_file,
        patterns=["*.key"],
    )
    assert verify_result.passed is True


# ---------------------------------------------------------------------------
# Test 4: already-encrypted idempotent
# ---------------------------------------------------------------------------


def test_already_encrypted_idempotent(
    tmp_git_repo: Path, sample_key_file: Path, tmp_path: Path
) -> None:
    # Given: a rewritten repo (first pass)
    manifest = _create_manifest(
        key_file=sample_key_file,
        patterns=[".env", "secrets/**"],
    )
    first_result = _run_rewrite(
        repo_path=tmp_git_repo,
        key_file=sample_key_file,
        work_dir=tmp_path / "work1",
        manifest=manifest,
    )
    first_rewritten = first_result.work_dir

    # When: run rewrite AGAIN on the already-rewritten repo
    second_result = _run_rewrite(
        repo_path=first_rewritten,
        key_file=sample_key_file,
        work_dir=tmp_path / "work2",
        manifest=manifest,
    )
    second_rewritten = second_result.work_dir

    # Then: files are not double-encrypted
    env_content = _git_show(second_rewritten, "HEAD", ".env")
    assert env_content.startswith(GITCRYPT_HEADER)
    # Content after header does NOT start with another GITCRYPT header
    assert not env_content[len(GITCRYPT_HEADER) :].startswith(GITCRYPT_HEADER)

    key_content = _git_show(second_rewritten, "HEAD", "secrets/api.key")
    assert key_content.startswith(GITCRYPT_HEADER)
    assert not key_content[len(GITCRYPT_HEADER) :].startswith(GITCRYPT_HEADER)


# ---------------------------------------------------------------------------
# Test 5: rewrite result counts
# ---------------------------------------------------------------------------


def test_rewrite_result_counts(
    tmp_git_repo: Path, sample_key_file: Path, tmp_path: Path
) -> None:
    manifest = _create_manifest(
        key_file=sample_key_file,
        patterns=[".env", "secrets/**"],
    )

    # When: rewrite with patterns [".env", "secrets/**"]
    result = _run_rewrite(
        repo_path=tmp_git_repo,
        key_file=sample_key_file,
        work_dir=tmp_path / "work",
        manifest=manifest,
    )

    # Then: result counts are positive
    assert result.commits_rewritten > 0
    assert result.files_encrypted > 0
    assert result.elapsed_seconds > 0


# ---------------------------------------------------------------------------
# Test 6: verification detects missing encryption
# ---------------------------------------------------------------------------


def test_verification_detects_missing_encryption(
    tmp_git_repo: Path, sample_key_file: Path
) -> None:
    # Given: tmp_git_repo (original, no rewrite) -- comparing original to itself
    # When: verify original vs itself (files that should be encrypted aren't)
    verify_result = _verify_rewrite(
        original=tmp_git_repo,
        rewritten=tmp_git_repo,
        key_file=sample_key_file,
        patterns=[".env", "secrets/**"],
    )

    # Then: verification FAILS (files that should be encrypted aren't)
    assert verify_result.passed is False
    assert len(verify_result.errors) > 0
