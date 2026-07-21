"""Verify that a rewritten repo matches the original."""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from git_recrypt._git import (
    get_commit_list,
    run_git_crypt_status,
)
from git_recrypt._verify_commits import (
    FileVerification,
    verify_commit_blobwise,
    verify_commit_checkout,
    verify_head_encryption,
)
from git_recrypt._verify_helpers import (
    build_commit_pairs,
    run_preflight,
)
from git_recrypt.crypto import CryptoEngine, is_encrypted
from git_recrypt.errors import CryptoError

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from git_recrypt.patterns import PatternMatcher


class VerifyMode(StrEnum):
    """Verification thoroughness."""

    FULL = "full"
    FAST = "fast"


@dataclass(frozen=True, slots=True)
class VerifyResult:
    """Overall verification result."""

    passed: bool
    commits_verified: int
    commits_total: int
    files_verified: int
    encrypted_files: tuple[FileVerification, ...]
    errors: tuple[str, ...]
    encrypted_files_count: int = field(default=0)
    identities_verified: int = field(default=0)


class RewriteVerifier:
    """Verifies a rewritten repo matches the original."""

    _original_path: Path
    _rewritten_path: Path
    _crypto: CryptoEngine
    _matcher: PatternMatcher
    _mode: VerifyMode
    _progress_cb: Callable[[int, int], None] | None
    _gpg_user_ids: list[str]
    _rewrite_commits: int
    _rewrite_files_encrypted: int

    def __init__(  # noqa: PLR0913
        self,
        original_path: Path,
        rewritten_path: Path,
        key_file: Path,
        matcher: PatternMatcher,
        mode: VerifyMode = VerifyMode.FAST,
        rewrite_commits: int = 0,
        rewrite_files_encrypted: int = 0,
    ) -> None:
        """Initialize the verifier."""
        self._original_path = original_path
        self._rewritten_path = rewritten_path
        self._crypto = CryptoEngine(key_file=key_file)
        self._matcher = matcher
        self._mode = mode
        self._progress_cb = None
        self._gpg_user_ids = []
        self._rewrite_commits = rewrite_commits
        self._rewrite_files_encrypted = rewrite_files_encrypted

    def set_progress_callback(self, cb: Callable[[int, int], None]) -> None:
        """Set an optional (current, total) progress callback."""
        self._progress_cb = cb

    def set_gpg_user_ids(self, user_ids: list[str]) -> None:
        """Set GPG user IDs for identity verification in Phase 2/3."""
        self._gpg_user_ids = list(user_ids)

    def verify(self) -> VerifyResult:
        """Run preflight phases then commit-level verification."""
        rewrite_errors = self._check_rewrite_report()
        if rewrite_errors:
            return VerifyResult(
                passed=False,
                commits_verified=0,
                commits_total=0,
                files_verified=0,
                encrypted_files=(),
                errors=tuple(rewrite_errors),
            )

        key_file = self._crypto.key_file
        is_gpg = bool(self._gpg_user_ids)
        preflight_key = None if is_gpg else key_file

        preflight = run_preflight(
            rewritten_path=self._rewritten_path,
            matcher=self._matcher,
            key_file=preflight_key,
            gpg_user_ids=self._gpg_user_ids,
        )

        if not preflight.passed:
            return VerifyResult(
                passed=False,
                commits_verified=0,
                commits_total=0,
                files_verified=0,
                encrypted_files=(),
                errors=preflight.errors,
                encrypted_files_count=preflight.encrypted_files_count,
                identities_verified=preflight.identities_verified,
            )

        original_commits = get_commit_list(self._original_path)
        commits_total = len(original_commits)

        try:
            pairs = build_commit_pairs(original_commits, self._rewritten_path)
        except ValueError as exc:
            return VerifyResult(
                passed=False,
                commits_verified=0,
                commits_total=commits_total,
                files_verified=0,
                encrypted_files=(),
                errors=(str(exc),),
                encrypted_files_count=preflight.encrypted_files_count,
                identities_verified=preflight.identities_verified,
            )

        pairs_to_check = (
            self._select_fast_sample(pairs) if self._mode == VerifyMode.FAST else pairs
        )

        all_errors, total_files, commits_checked = self._run_commit_verification(
            pairs_to_check
        )

        if not all_errors:
            lock_errors = self._verify_final_locked_state()
            all_errors.extend(lock_errors)

        all_encrypted = verify_head_encryption(
            self._original_path,
            self._rewritten_path,
            pairs_to_check,
            self._matcher,
            self._crypto,
        )

        return VerifyResult(
            passed=len(all_errors) == 0,
            commits_verified=commits_checked,
            commits_total=commits_total,
            files_verified=total_files,
            encrypted_files=tuple(all_encrypted),
            errors=tuple(all_errors),
            encrypted_files_count=preflight.encrypted_files_count,
            identities_verified=preflight.identities_verified,
        )

    def _check_rewrite_report(self) -> list[str]:
        """Fail fast if rewrite_commits or rewrite_files_encrypted is 0 (when set)."""
        errors: list[str] = []
        if not (self._rewrite_commits > 0 or self._rewrite_files_encrypted > 0):
            return errors
        if self._rewrite_commits == 0:
            errors.append(
                "Rewrite report: commits_rewritten is 0 -- no commits were rewritten"
            )
        if self._rewrite_files_encrypted == 0:
            errors.append(
                "Rewrite report: files_encrypted is 0 -- no files were encrypted"
            )
        return errors

    def _run_commit_verification(
        self,
        pairs_to_check: list[tuple[str, str]],
    ) -> tuple[list[str], int, int]:
        """Run commit-level verification. Returns (errors, files, commits)."""
        all_errors: list[str] = []
        total_files = 0
        commits_checked = 0
        checkout_indices = self._select_checkout_indices(pairs_to_check)
        key_file = self._crypto.key_file

        for idx, (orig_sha, rew_sha) in enumerate(pairs_to_check):
            if self._progress_cb is not None:
                self._progress_cb(idx, len(pairs_to_check))
            if idx in checkout_indices:
                errs = verify_commit_checkout(
                    self._rewritten_path,
                    self._original_path,
                    orig_sha,
                    rew_sha,
                    key_file,
                )
            else:
                errs = verify_commit_blobwise(
                    self._original_path,
                    self._rewritten_path,
                    orig_sha,
                    rew_sha,
                    self._matcher,
                    self._crypto,
                )
            all_errors.extend(errs)
            commits_checked += 1
            if all_errors:
                break

        return all_errors, total_files, commits_checked

    def _select_checkout_indices(self, pairs: list[tuple[str, str]]) -> set[int]:
        """Select indices for checkout-based verification: tip (0) + 1 random middle."""
        if not pairs:
            return set()
        indices: set[int] = {0}
        middle = list(range(1, len(pairs) - 1)) if len(pairs) > 2 else []  # noqa: PLR2004
        if middle:
            indices.add(random.choice(middle))  # noqa: S311
        return indices

    def _verify_final_locked_state(self) -> list[str]:
        """Verify repo is in locked state after all commits verified."""
        errors: list[str] = []
        try:
            entries = run_git_crypt_status(self._rewritten_path)
        except CryptoError:
            return errors
        encrypted_paths = [
            self._rewritten_path / fp
            for fp, is_enc in entries
            if is_enc and self._matcher.matches(fp)
        ][:5]
        for fp in encrypted_paths:
            if not fp.exists():
                continue
            try:
                content = fp.read_bytes()
            except OSError:
                continue
            if not is_encrypted(content):
                errors.append(
                    f"Post-verify: {fp.name} is not locked (missing GITCRYPT header)"
                )
        return errors

    def _select_fast_sample(
        self, pairs: list[tuple[str, str]]
    ) -> list[tuple[str, str]]:
        if not pairs:
            return []
        selected: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()

        def add(pair: tuple[str, str]) -> None:
            if pair not in seen:
                seen.add(pair)
                selected.append(pair)

        add(pairs[0])
        add(pairs[-1])
        sample_count = max(5, min(30, len(pairs) // 10))
        for pair in random.sample(pairs, min(sample_count, len(pairs))):
            add(pair)
        return selected
