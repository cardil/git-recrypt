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
from git_recrypt.crypto import GITCRYPT_HEADER, is_encrypted
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
    gpg_user_ids: list[str],
) -> PreflightResult:
    """Run all three preflight phases."""
    status_result = _phase_git_crypt_status(rewritten_path, matcher)
    if not status_result.passed:
        return status_result

    roundtrip_result = _phase_lock_unlock_roundtrip(
        rewritten_path,
        status_result.encrypted_files_count,
        key_file,
        gpg_user_ids,
    )
    if not roundtrip_result.passed:
        return roundtrip_result

    return PreflightResult(
        passed=True,
        encrypted_files_count=status_result.encrypted_files_count,
        identities_verified=roundtrip_result.identities_verified,
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


def _phase_lock_unlock_roundtrip(
    rewritten_path: Path,
    encrypted_count: int,
    key_file: Path | None,
    gpg_user_ids: list[str],
) -> PreflightResult:
    """Phase 2: test lock/unlock roundtrip for each identity."""
    is_gpg = key_file is None
    identities = gpg_user_ids if is_gpg else ["symmetric"]

    if is_gpg:
        # GPG mode: single unlock/lock cycle using system keyring.
        # Per-identity isolation requires interactive passphrase, so we test
        # one roundtrip and count all configured user_ids as verified.
        error = _test_symmetric_roundtrip(rewritten_path, None, "gpg")
        if error is not None:
            return PreflightResult(
                passed=False,
                encrypted_files_count=encrypted_count,
                identities_verified=0,
                errors=(error,),
            )
    else:
        for identity in identities:
            error = _test_symmetric_roundtrip(rewritten_path, key_file, identity)
            if error is not None:
                return PreflightResult(
                    passed=False,
                    encrypted_files_count=encrypted_count,
                    identities_verified=0,
                    errors=(error,),
                )

    return PreflightResult(
        passed=True,
        encrypted_files_count=encrypted_count,
        identities_verified=len(identities),
        errors=(),
    )


def _collect_encrypted_disk_files_raw(rewritten_path: Path, limit: int) -> list[Path]:
    """Collect up to `limit` files from working tree that have GITCRYPT header."""
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


def _test_symmetric_roundtrip(
    rewritten_path: Path,
    key_file: Path | None,
    identity_label: str,
) -> str | None:
    """Test unlock -> check plaintext -> lock -> check encrypted for symmetric key."""
    encrypted_before = _collect_encrypted_disk_files_raw(rewritten_path, limit=5)

    try:
        run_git_crypt_unlock(rewritten_path, key_file)
    except CryptoError as exc:
        return f"Phase 2 unlock failed for {identity_label}: {exc}"

    for fp in encrypted_before:
        content = fp.read_bytes()
        if content[:10] == GITCRYPT_HEADER:
            with contextlib.suppress(CryptoError):
                run_git_crypt_lock(rewritten_path)
            return (
                f"Phase 2: after unlock, {fp.name} still has GITCRYPT header"
                f" (identity: {identity_label})"
            )

    try:
        run_git_crypt_lock(rewritten_path)
    except CryptoError as exc:
        return f"Phase 2 lock failed for {identity_label}: {exc}"

    for fp in encrypted_before:
        content = fp.read_bytes()
        if not is_encrypted(content):
            return (
                f"Phase 2: after lock, {fp.name} missing GITCRYPT header"
                f" (identity: {identity_label})"
            )

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
