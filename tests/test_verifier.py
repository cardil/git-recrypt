"""Tests for git_recrypt.verifier -- TDD, Given/When/Then."""

from __future__ import annotations

import os
import subprocess
from typing import TYPE_CHECKING, Final

from git_recrypt.crypto import CryptoEngine
from git_recrypt.patterns import PatternMatcher
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


def _run(args: list[str], cwd: Path) -> None:
    subprocess.run(  # noqa: S603
        args,
        check=True,
        capture_output=True,
        cwd=cwd,
        env={**os.environ, **_GIT_ENV},
    )


def _make_single_commit_repo(tmp_path: Path, name: str) -> Path:
    """Create a minimal git repo with one commit: README.md and secrets/api.key."""
    repo = tmp_path / name
    repo.mkdir()
    _run([_GIT, "init"], cwd=repo)
    _run([_GIT, "config", "user.email", "test@example.com"], cwd=repo)
    _run([_GIT, "config", "user.name", "Test"], cwd=repo)

    (repo / "README.md").write_text("# Test\n")
    secrets = repo / "secrets"
    secrets.mkdir()
    (secrets / "api.key").write_text("API_KEY=super-secret\n")
    _run([_GIT, "add", "."], cwd=repo)
    _run([_GIT, "commit", "-m", "Initial commit"], cwd=repo)
    return repo


def _make_rewritten_repo(
    original: Path,
    dest: Path,
    key_file: Path,
    files_to_encrypt: list[str],
) -> None:
    """Clone original and manually encrypt the specified files in the clone.

    Adds .gitattributes and amends the HEAD commit.
    Since original has a single commit, amending HEAD rewrites the full history.
    """
    _run(
        [_GIT, "clone", "--no-local", str(original), str(dest)],
        cwd=original.parent,
    )
    _run([_GIT, "config", "user.email", "test@example.com"], cwd=dest)
    _run([_GIT, "config", "user.name", "Test"], cwd=dest)

    crypto = CryptoEngine(key_file=key_file)

    for filepath in files_to_encrypt:
        full = dest / filepath
        if not full.exists():
            continue
        content = full.read_bytes()
        encrypted = crypto.encrypt(content)
        full.write_bytes(encrypted)
        _run([_GIT, "add", filepath], cwd=dest)

    gitattributes_lines = [
        f"{fp} filter=git-crypt diff=git-crypt" for fp in files_to_encrypt
    ]
    gitattributes_lines.append(".gitattributes !filter !diff")
    (dest / ".gitattributes").write_text("\n".join(gitattributes_lines) + "\n")
    _run([_GIT, "add", ".gitattributes"], cwd=dest)
    _run([_GIT, "commit", "--amend", "--no-edit"], cwd=dest)


# ---------------------------------------------------------------------------
# test_correctly_rewritten_passes
# ---------------------------------------------------------------------------


def test_correctly_rewritten_passes(sample_key_file: Path, tmp_path: Path) -> None:
    """Given correctly rewritten repo, when verify called, passes with no errors."""
    # Given
    original = _make_single_commit_repo(tmp_path, "original")
    rewritten = tmp_path / "rewritten"
    _make_rewritten_repo(original, rewritten, sample_key_file, ["secrets/api.key"])

    matcher = PatternMatcher(
        include_patterns=("secrets/api.key",),
        exclude_patterns=(),
    )
    verifier = RewriteVerifier(
        original_path=original,
        rewritten_path=rewritten,
        key_file=sample_key_file,
        matcher=matcher,
        mode=VerifyMode.FAST,
    )
    # When
    result = verifier.verify()
    # Then
    assert result.passed is True
    assert result.errors == ()


# ---------------------------------------------------------------------------
# test_missing_encryption_detected
# ---------------------------------------------------------------------------


def test_missing_encryption_detected(sample_key_file: Path, tmp_path: Path) -> None:
    """Given file that should be encrypted but isn't, errors reported."""
    # Given: single-commit original, clone without encrypting
    original = _make_single_commit_repo(tmp_path, "original")
    rewritten = tmp_path / "rewritten"
    _run(
        [_GIT, "clone", "--no-local", str(original), str(rewritten)],
        cwd=original.parent,
    )
    _run([_GIT, "config", "user.email", "test@example.com"], cwd=rewritten)
    _run([_GIT, "config", "user.name", "Test"], cwd=rewritten)
    # Add .gitattributes but do NOT encrypt the file
    (rewritten / ".gitattributes").write_text(
        "secrets/api.key filter=git-crypt diff=git-crypt\n"
        ".gitattributes !filter !diff\n"
    )
    _run([_GIT, "add", ".gitattributes"], cwd=rewritten)
    _run([_GIT, "commit", "--amend", "--no-edit"], cwd=rewritten)

    matcher = PatternMatcher(
        include_patterns=("secrets/api.key",),
        exclude_patterns=(),
    )
    verifier = RewriteVerifier(
        original_path=original,
        rewritten_path=rewritten,
        key_file=sample_key_file,
        matcher=matcher,
        mode=VerifyMode.FAST,
    )
    # When
    result = verifier.verify()
    # Then
    assert result.passed is False
    assert any("expected encrypted" in e for e in result.errors)


# ---------------------------------------------------------------------------
# test_non_encrypted_unchanged_passes
# ---------------------------------------------------------------------------


def test_non_encrypted_unchanged_passes(sample_key_file: Path, tmp_path: Path) -> None:
    """Given non-matching files identical in both repos, when verify called, passes."""
    # Given: single-commit original, clone with .gitattributes, no encryption patterns
    original = _make_single_commit_repo(tmp_path, "original")
    rewritten = tmp_path / "rewritten"
    _run(
        [_GIT, "clone", "--no-local", str(original), str(rewritten)],
        cwd=original.parent,
    )
    _run([_GIT, "config", "user.email", "test@example.com"], cwd=rewritten)
    _run([_GIT, "config", "user.name", "Test"], cwd=rewritten)
    (rewritten / ".gitattributes").write_text(".gitattributes !filter !diff\n")
    _run([_GIT, "add", ".gitattributes"], cwd=rewritten)
    _run([_GIT, "commit", "--amend", "--no-edit"], cwd=rewritten)

    # Matcher matches nothing -- all files are non-encrypted
    matcher = PatternMatcher(include_patterns=(), exclude_patterns=())
    verifier = RewriteVerifier(
        original_path=original,
        rewritten_path=rewritten,
        key_file=sample_key_file,
        matcher=matcher,
        mode=VerifyMode.FAST,
    )
    # When
    result = verifier.verify()
    # Then
    assert result.passed is True


# ---------------------------------------------------------------------------
# test_missing_gitattributes_detected
# ---------------------------------------------------------------------------


def test_missing_gitattributes_detected(sample_key_file: Path, tmp_path: Path) -> None:
    """Given rewritten repo without .gitattributes, error reported."""
    # Given: single-commit original, plain clone with no .gitattributes
    original = _make_single_commit_repo(tmp_path, "original")
    rewritten = tmp_path / "rewritten"
    _run(
        [_GIT, "clone", "--no-local", str(original), str(rewritten)],
        cwd=original.parent,
    )
    _run([_GIT, "config", "user.email", "test@example.com"], cwd=rewritten)
    _run([_GIT, "config", "user.name", "Test"], cwd=rewritten)

    matcher = PatternMatcher(include_patterns=(), exclude_patterns=())
    verifier = RewriteVerifier(
        original_path=original,
        rewritten_path=rewritten,
        key_file=sample_key_file,
        matcher=matcher,
        mode=VerifyMode.FAST,
    )
    # When
    result = verifier.verify()
    # Then
    assert result.passed is False
    assert any(".gitattributes missing" in e for e in result.errors)


# ---------------------------------------------------------------------------
# test_verify_result_passed_true_when_clean
# ---------------------------------------------------------------------------


def test_verify_result_passed_true_when_clean(
    sample_key_file: Path, tmp_path: Path
) -> None:
    """Given clean rewritten repo, VerifyResult.passed is True."""
    # Given
    original = _make_single_commit_repo(tmp_path, "original")
    rewritten = tmp_path / "rewritten"
    _make_rewritten_repo(original, rewritten, sample_key_file, ["secrets/api.key"])

    matcher = PatternMatcher(
        include_patterns=("secrets/api.key",),
        exclude_patterns=(),
    )
    verifier = RewriteVerifier(
        original_path=original,
        rewritten_path=rewritten,
        key_file=sample_key_file,
        matcher=matcher,
        mode=VerifyMode.FAST,
    )
    # When
    result = verifier.verify()
    # Then
    assert isinstance(result, VerifyResult)
    assert result.passed is True


# ---------------------------------------------------------------------------
# test_verify_result_passed_false_on_errors
# ---------------------------------------------------------------------------


def test_verify_result_passed_false_on_errors(
    sample_key_file: Path, tmp_path: Path
) -> None:
    """Given rewritten repo with errors, VerifyResult.passed is False."""
    # Given: single-commit original, clone with no .gitattributes and no encryption
    original = _make_single_commit_repo(tmp_path, "original")
    rewritten = tmp_path / "rewritten"
    _run(
        [_GIT, "clone", "--no-local", str(original), str(rewritten)],
        cwd=original.parent,
    )
    _run([_GIT, "config", "user.email", "test@example.com"], cwd=rewritten)
    _run([_GIT, "config", "user.name", "Test"], cwd=rewritten)

    matcher = PatternMatcher(
        include_patterns=("secrets/api.key",),
        exclude_patterns=(),
    )
    verifier = RewriteVerifier(
        original_path=original,
        rewritten_path=rewritten,
        key_file=sample_key_file,
        matcher=matcher,
        mode=VerifyMode.FAST,
    )
    # When
    result = verifier.verify()
    # Then
    assert isinstance(result, VerifyResult)
    assert result.passed is False
    assert len(result.errors) > 0


# ---------------------------------------------------------------------------
# test_fast_mode_samples_commits
# ---------------------------------------------------------------------------


def test_fast_mode_samples_commits(sample_key_file: Path, tmp_path: Path) -> None:
    """Given FAST mode with multi-commit repo, commits_verified <= commits_total."""
    # Given: build a 3-commit original repo, rewrite only HEAD
    original = tmp_path / "original"
    original.mkdir()
    _run([_GIT, "init"], cwd=original)
    _run([_GIT, "config", "user.email", "test@example.com"], cwd=original)
    _run([_GIT, "config", "user.name", "Test"], cwd=original)

    (original / "README.md").write_text("# Test\n")
    _run([_GIT, "add", "."], cwd=original)
    _run([_GIT, "commit", "-m", "commit 1"], cwd=original)

    secrets = original / "secrets"
    secrets.mkdir()
    (secrets / "api.key").write_text("API_KEY=secret\n")
    _run([_GIT, "add", "."], cwd=original)
    _run([_GIT, "commit", "-m", "commit 2"], cwd=original)

    (original / "README.md").write_text("# Updated\n")
    _run([_GIT, "add", "."], cwd=original)
    _run([_GIT, "commit", "-m", "commit 3"], cwd=original)

    # Rewritten: clone and encrypt only HEAD (amend)
    rewritten = tmp_path / "rewritten"
    _make_rewritten_repo(original, rewritten, sample_key_file, ["secrets/api.key"])

    matcher = PatternMatcher(
        include_patterns=("secrets/api.key",),
        exclude_patterns=(),
    )
    verifier = RewriteVerifier(
        original_path=original,
        rewritten_path=rewritten,
        key_file=sample_key_file,
        matcher=matcher,
        mode=VerifyMode.FAST,
    )
    # When
    result = verifier.verify()
    # Then
    assert result.commits_total == 3
    assert result.commits_verified <= result.commits_total
    assert result.commits_verified >= 1
