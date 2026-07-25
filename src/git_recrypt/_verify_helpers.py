"""Preflight verification helpers for git-recrypt verifier."""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from git_recrypt._git import (
    load_commit_map,
    run_git_crypt_lock,
    run_git_crypt_status,
    run_git_crypt_unlock,
)
from git_recrypt.crypto import GITCRYPT_HEADER
from git_recrypt.errors import CryptoError

if TYPE_CHECKING:
    from pathlib import Path

    from git_recrypt.patterns import PatternMatcher


@dataclass(frozen=True, slots=True)
class PreflightResult:
    """Result of all preflight phases."""

    passed: bool
    encrypted_files_count: int
    identities_verified: int
    errors: tuple[str, ...]


def run_preflight(
    rewritten_path: Path,
    matcher: PatternMatcher,
    key_file: Path | None,
    gpg_user_ids: list[str],  # noqa: ARG001  # pyright: ignore[reportUnusedParameter]
    lock_unlock_shas: list[str] | None = None,
) -> PreflightResult:
    """Run preflight phases: git-crypt status + lock/unlock roundtrips.

    lock_unlock_shas: rewritten commit SHAs to test lock/unlock at (tip + middle).
    """
    status_result = _phase_git_crypt_status(rewritten_path, matcher)
    if not status_result.passed:
        return status_result

    shas = lock_unlock_shas or []
    if status_result.encrypted_files_count == 0:
        shas = []
    for sha in shas:
        from git_recrypt._git import git_checkout  # noqa: PLC0415

        try:
            git_checkout(rewritten_path, sha)
        except CryptoError as exc:
            return PreflightResult(
                passed=False,
                encrypted_files_count=status_result.encrypted_files_count,
                identities_verified=0,
                errors=(f"Phase 2 checkout {sha[:8]} failed: {exc}",),
            )
        error = _test_lock_unlock_roundtrip(rewritten_path, key_file)
        if error is not None:
            return PreflightResult(
                passed=False,
                encrypted_files_count=status_result.encrypted_files_count,
                identities_verified=0,
                errors=(f"Phase 2 at {sha[:8]}: {error}",),
            )

    # The lock/unlock roundtrip verifies that at least one identity works,
    # but does not test each identity individually. Report 1 (roundtrip passed)
    # rather than len(gpg_user_ids) to avoid overclaiming per-identity coverage.
    identities_verified = 1 if shas else 0

    return PreflightResult(
        passed=True,
        encrypted_files_count=status_result.encrypted_files_count,
        identities_verified=identities_verified,
        errors=(),
    )


def _phase_git_crypt_status(
    rewritten_path: Path,
    matcher: PatternMatcher,
) -> PreflightResult:
    """Phase 1: verify git-crypt status shows encrypted files matching patterns."""
    try:
        entries = run_git_crypt_status(rewritten_path)
    except CryptoError as exc:
        return PreflightResult(
            passed=False,
            encrypted_files_count=0,
            identities_verified=0,
            errors=(f"Phase 1 git-crypt status failed: {exc}",),
        )

    encrypted_matching = [
        fp for fp, is_enc in entries if is_enc and matcher.matches(fp)
    ]
    count = len(encrypted_matching)

    unencrypted_matching = [
        fp for fp, is_enc in entries if not is_enc and matcher.matches(fp)
    ]
    if unencrypted_matching:
        msgs = [f"  {fp}" for fp in unencrypted_matching[:10]]
        detail = "\n".join(msgs)
        return PreflightResult(
            passed=False,
            encrypted_files_count=count,
            identities_verified=0,
            errors=(
                f"Phase 1: {len(unencrypted_matching)} matched file(s) are NOT"
                f" encrypted:\n{detail}",
            ),
        )

    has_patterns = bool(matcher.include_patterns)
    if has_patterns and count == 0:
        return PreflightResult(
            passed=False,
            encrypted_files_count=0,
            identities_verified=0,
            errors=("Phase 1: no encrypted files matching manifest patterns found",),
        )

    return PreflightResult(
        passed=True,
        encrypted_files_count=count,
        identities_verified=0,
        errors=(),
    )


def _collect_encrypted_disk_files_raw(rewritten_path: Path, limit: int) -> list[Path]:
    collected: list[Path] = []
    for fp in rewritten_path.rglob("*"):
        if not fp.is_file():
            continue
        try:
            _ = fp.relative_to(rewritten_path / ".git")
            continue
        except ValueError:
            pass
        try:
            header = fp.read_bytes()[:10]
        except OSError:
            continue
        if header == GITCRYPT_HEADER:
            collected.append(fp)
            if len(collected) >= limit:
                break
    return collected


def _test_lock_unlock_roundtrip(
    rewritten_path: Path,
    key_file: Path | None,
) -> str | None:
    """Lock, verify encrypted on disk, unlock, verify plaintext."""
    with contextlib.suppress(CryptoError):
        run_git_crypt_lock(rewritten_path)

    encrypted_files = _collect_encrypted_disk_files_raw(rewritten_path, limit=5)
    if not encrypted_files:
        with contextlib.suppress(CryptoError):
            run_git_crypt_unlock(rewritten_path, key_file)
        return "no encrypted files found after lock"

    try:
        run_git_crypt_unlock(rewritten_path, key_file)
    except CryptoError as exc:
        return f"unlock failed: {exc}"

    for fp in encrypted_files:
        content = fp.read_bytes()
        if content[:10] == GITCRYPT_HEADER:
            return f"after unlock, {fp.name} still encrypted"

    return None


def build_commit_pairs(
    original_commits: list[str],
    rewritten_path: Path,
) -> list[tuple[str, str]]:
    """Build (original, rewritten) SHA pairs using git-filter-repo commit map.

    Raises ValueError if commit map is missing or empty.
    """
    commit_map = load_commit_map(rewritten_path)
    if not commit_map:
        msg = "No commit map found"
        raise ValueError(msg)
    pairs: list[tuple[str, str]] = []
    for orig_sha in original_commits:
        rew_sha = commit_map.get(orig_sha)
        if rew_sha is not None:
            pairs.append((orig_sha, rew_sha))
    return pairs
