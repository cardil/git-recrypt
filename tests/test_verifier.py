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
_GIT_CRYPT: Final = "git-crypt"
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


def _run_git_crypt(args: list[str], cwd: Path) -> None:
    subprocess.run(  # noqa: S603
        [_GIT_CRYPT, *args],
        check=True,
        capture_output=True,
        cwd=cwd,
    )


def _make_single_commit_repo(tmp_path: Path, name: str) -> Path:
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


def _clone_and_setup(original: Path, dest: Path) -> None:
    _run(
        [_GIT, "clone", "--no-local", str(original), str(dest)],
        cwd=original.parent,
    )
    _run([_GIT, "config", "user.email", "test@example.com"], cwd=dest)
    _run([_GIT, "config", "user.name", "Test"], cwd=dest)


def _get_head_sha(repo: Path) -> str:
    """Return the HEAD commit SHA of a repo."""
    result = subprocess.run(  # noqa: S603
        [_GIT, "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        cwd=repo,
    )
    return result.stdout.decode().strip()


def _write_commit_map(original: Path, rewritten: Path) -> None:
    """Write a commit-map mapping orig->rewritten SHA."""
    orig_sha = _get_head_sha(original)
    rew_sha = _get_head_sha(rewritten)
    map_dir = rewritten / ".git" / "filter-repo"
    map_dir.mkdir(parents=True, exist_ok=True)
    (map_dir / "commit-map").write_text(
        f"old                                      new\n{orig_sha} {rew_sha}\n",
        encoding="utf-8",
    )


def _make_rewritten_repo(
    original: Path,
    dest: Path,
    key_file: Path,
    files_to_encrypt: list[str],
) -> None:
    """Clone original, encrypt files, add .gitattributes, commit, then unlock+lock.

    Correct order: encrypt files first, then add .gitattributes, then commit,
    then unlock (working tree is clean at that point), then lock.
    Also writes a commit-map so the verifier can find commit pairs.
    """
    _clone_and_setup(original, dest)

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

    _run_git_crypt(["unlock", str(key_file)], cwd=dest)
    _run_git_crypt(["lock", "--force"], cwd=dest)

    _write_commit_map(original, dest)


def _make_gcrypt_repo_no_encrypted_files(
    original: Path,
    dest: Path,
    key_file: Path,
) -> None:
    """Clone original, add .gitattributes (no encrypt), unlock, lock.

    Files are NOT encrypted -- used to test that missing encryption is detected.
    """
    _clone_and_setup(original, dest)

    (dest / ".gitattributes").write_text(
        "secrets/api.key filter=git-crypt diff=git-crypt\n"
        ".gitattributes !filter !diff\n"
    )
    _run([_GIT, "add", ".gitattributes"], cwd=dest)
    _run([_GIT, "commit", "--amend", "--no-edit"], cwd=dest)

    _run_git_crypt(["unlock", str(key_file)], cwd=dest)
    _run_git_crypt(["lock", "--force"], cwd=dest)


def _make_gcrypt_repo_no_gitattributes(
    original: Path,
    dest: Path,
    key_file: Path,
) -> None:
    """Clone original, unlock (no .gitattributes), lock. Writes commit map."""
    _clone_and_setup(original, dest)
    _run_git_crypt(["unlock", str(key_file)], cwd=dest)
    _run_git_crypt(["lock", "--force"], cwd=dest)
    _write_commit_map(original, dest)


def _make_gcrypt_repo_no_patterns(
    original: Path,
    dest: Path,
    key_file: Path,
) -> None:
    """Clone original, add .gitattributes with no encrypt patterns, unlock, lock."""
    _clone_and_setup(original, dest)
    (dest / ".gitattributes").write_text(".gitattributes !filter !diff\n")
    _run([_GIT, "add", ".gitattributes"], cwd=dest)
    _run([_GIT, "commit", "--amend", "--no-edit"], cwd=dest)
    _run_git_crypt(["unlock", str(key_file)], cwd=dest)
    _run_git_crypt(["lock", "--force"], cwd=dest)
    _write_commit_map(original, dest)


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
    # Given: single-commit original, clone with .gitattributes but file not encrypted
    original = _make_single_commit_repo(tmp_path, "original")
    rewritten = tmp_path / "rewritten"
    _make_gcrypt_repo_no_encrypted_files(original, rewritten, sample_key_file)

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
    assert len(result.errors) > 0


# ---------------------------------------------------------------------------
# test_non_encrypted_unchanged_passes
# ---------------------------------------------------------------------------


def test_non_encrypted_unchanged_passes(sample_key_file: Path, tmp_path: Path) -> None:
    """Given non-matching files identical in both repos, when verify called, passes."""
    # Given: single-commit original, clone with .gitattributes, no encrypt patterns
    original = _make_single_commit_repo(tmp_path, "original")
    rewritten = tmp_path / "rewritten"
    _make_gcrypt_repo_no_patterns(original, rewritten, sample_key_file)

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
    # Given: two-commit original so oldest commit goes through blobwise verification
    original = tmp_path / "original"
    original.mkdir()
    _run([_GIT, "init"], cwd=original)
    _run([_GIT, "config", "user.email", "test@example.com"], cwd=original)
    _run([_GIT, "config", "user.name", "Test"], cwd=original)
    (original / "README.md").write_text("# Test\n")
    _run([_GIT, "add", "."], cwd=original)
    _run([_GIT, "commit", "-m", "commit 1"], cwd=original)
    (original / "README.md").write_text("# Updated\n")
    _run([_GIT, "add", "."], cwd=original)
    _run([_GIT, "commit", "-m", "commit 2"], cwd=original)

    rewritten = tmp_path / "rewritten"
    _make_gcrypt_repo_no_gitattributes(original, rewritten, sample_key_file)
    # Write commit map for both commits
    result_orig = subprocess.run(  # noqa: S603
        [_GIT, "rev-list", "--all"],
        cwd=original,
        capture_output=True,
        check=True,
    )
    result_rew = subprocess.run(  # noqa: S603
        [_GIT, "rev-list", "--all"],
        cwd=rewritten,
        capture_output=True,
        check=True,
    )
    orig_shas = result_orig.stdout.decode().strip().splitlines()
    rew_shas = result_rew.stdout.decode().strip().splitlines()
    map_dir = rewritten / ".git" / "filter-repo"
    map_dir.mkdir(parents=True, exist_ok=True)
    lines = ["old                                      new\n"]
    for o, r in zip(orig_shas, rew_shas, strict=False):
        lines.append(f"{o} {r}\n")
    (map_dir / "commit-map").write_text("".join(lines), encoding="utf-8")

    matcher = PatternMatcher(include_patterns=(), exclude_patterns=())
    verifier = RewriteVerifier(
        original_path=original,
        rewritten_path=rewritten,
        key_file=sample_key_file,
        matcher=matcher,
        mode=VerifyMode.FULL,
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
    # Given: single-commit original, clone with .gitattributes but no encryption
    original = _make_single_commit_repo(tmp_path, "original")
    rewritten = tmp_path / "rewritten"
    _make_gcrypt_repo_no_encrypted_files(original, rewritten, sample_key_file)

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


# ---------------------------------------------------------------------------
# test_verify_result_has_new_fields
# ---------------------------------------------------------------------------


def test_verify_result_has_new_fields(sample_key_file: Path, tmp_path: Path) -> None:
    """Given clean rewritten repo, VerifyResult has encrypted_files_count and identities_verified."""  # noqa: E501
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
    assert result.encrypted_files_count >= 1
    assert result.identities_verified >= 1


# ---------------------------------------------------------------------------
# test_set_gpg_user_ids_accepted
# ---------------------------------------------------------------------------


def test_set_gpg_user_ids_accepted(sample_key_file: Path, tmp_path: Path) -> None:
    """Given set_gpg_user_ids called, verifier stores the IDs without error."""
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
    verifier.set_gpg_user_ids(["alice@example.com"])
    # Then -- no exception raised; GPG mode would be used in verify()
    assert True
