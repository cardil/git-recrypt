"""Verify that a rewritten repo matches the original."""

from __future__ import annotations

import contextlib
import random
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING

from git_recrypt._git import (
    get_commit_list,
    get_file_list,
    run_git_crypt_status,
)
from git_recrypt._shellout import GIT
from git_recrypt._verify_commits import (
    verify_commit_checkout,
)
from git_recrypt._verify_helpers import (
    build_commit_pairs,
    run_preflight,
)
from git_recrypt.crypto import is_encrypted
from git_recrypt.errors import CryptoError

if TYPE_CHECKING:
    from collections.abc import Callable

    from git_recrypt.patterns import PatternMatcher


def _has_gitattributes(rewritten_path: Path, sha: str) -> bool:
    """Return True if .gitattributes exists in the tree at the given SHA."""
    result = subprocess.run(  # noqa: S603
        [GIT, "ls-tree", "--name-only", sha, ".gitattributes"],
        cwd=rewritten_path,
        capture_output=True,
        check=False,
    )
    return result.returncode == 0 and bool(result.stdout.strip())


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
    encrypted_files: tuple[str, ...]
    errors: tuple[str, ...]
    encrypted_files_count: int = field(default=0)
    identities_verified: int = field(default=0)


class RewriteVerifier:
    """Verifies a rewritten repo matches the original."""

    _original_path: Path
    _rewritten_path: Path
    _key_file: Path
    _matcher: PatternMatcher
    _mode: VerifyMode
    _progress_cb: Callable[[int, int], None] | None
    _gpg_user_ids: list[str]  # pyright: ignore[reportRedeclaration]
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
        self._key_file = key_file
        self._matcher = matcher
        self._mode = mode
        self._progress_cb = None
        self._gpg_user_ids: list[str] = []
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

        is_gpg = bool(self._gpg_user_ids)
        preflight_key: Path | None = None if is_gpg else self._key_file

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
            )

        if len(pairs) != len(original_commits):
            missing = len(original_commits) - len(pairs)
            return VerifyResult(
                passed=False,
                commits_verified=0,
                commits_total=commits_total,
                files_verified=0,
                encrypted_files=(),
                errors=(
                    f"Incomplete commit map: {missing} of {len(original_commits)}"
                    " original commits have no mapping in the rewritten repo",
                ),
            )

        lock_unlock_shas = self._select_lock_unlock_shas(pairs, self._rewritten_path)

        orig_ref: str | None = None
        try:
            r = subprocess.run(  # noqa: S603
                [GIT, "symbolic-ref", "--short", "HEAD"],
                cwd=self._rewritten_path,
                capture_output=True,
                check=False,
            )
            if r.returncode == 0:
                orig_ref = r.stdout.decode().strip()
            else:
                r = subprocess.run(  # noqa: S603
                    [GIT, "rev-parse", "HEAD"],
                    cwd=self._rewritten_path,
                    capture_output=True,
                    check=False,
                )
                if r.returncode == 0:
                    orig_ref = r.stdout.decode().strip()
        except OSError:
            pass

        try:
            preflight = run_preflight(
                rewritten_path=self._rewritten_path,
                matcher=self._matcher,
                key_file=preflight_key,
                gpg_user_ids=self._gpg_user_ids,
                lock_unlock_shas=lock_unlock_shas,
            )

            if not preflight.passed:
                return VerifyResult(
                    passed=False,
                    commits_verified=0,
                    commits_total=commits_total,
                    files_verified=0,
                    encrypted_files=(),
                    errors=preflight.errors,
                    encrypted_files_count=preflight.encrypted_files_count,
                    identities_verified=preflight.identities_verified,
                )

            pairs_to_check = (
                self._select_fast_sample(pairs)
                if self._mode == VerifyMode.FAST
                else pairs
            )

            all_errors, total_files, commits_checked = self._run_commit_verification(
                pairs_to_check
            )
        finally:
            if orig_ref:
                _ = subprocess.run(  # noqa: S603
                    [GIT, "checkout", orig_ref],
                    cwd=self._rewritten_path,
                    capture_output=True,
                    check=False,
                )
            from git_recrypt._git import run_git_crypt_lock  # noqa: PLC0415

            with contextlib.suppress(CryptoError):
                run_git_crypt_lock(self._rewritten_path)

        return VerifyResult(
            passed=len(all_errors) == 0,
            commits_verified=commits_checked,
            commits_total=commits_total,
            files_verified=total_files,
            encrypted_files=(),
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

        source_tmpdir = tempfile.mkdtemp(prefix="gcri-src-")
        source_copy = Path(source_tmpdir)
        _ = shutil.copytree(self._original_path, source_copy, dirs_exist_ok=True)
        try:
            for idx, (orig_sha, rew_sha) in enumerate(pairs_to_check):
                if self._progress_cb is not None:
                    self._progress_cb(idx, len(pairs_to_check))
                errs = verify_commit_checkout(
                    self._rewritten_path,
                    self._original_path,
                    orig_sha,
                    rew_sha,
                    source_copy,
                )
                all_errors.extend(errs)
                total_files += len(get_file_list(self._original_path, orig_sha))
                commits_checked += 1
                if all_errors:
                    break
        finally:
            shutil.rmtree(source_tmpdir, ignore_errors=True)

        return all_errors, total_files, commits_checked

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

    @staticmethod
    def _select_lock_unlock_shas(
        pairs: list[tuple[str, str]], rewritten_path: Path | None = None
    ) -> list[str]:
        if not pairs:
            return []
        eligible = pairs
        if rewritten_path is not None:
            eligible = [
                p for p in pairs
                if _has_gitattributes(rewritten_path, p[1])
            ]
        if not eligible:
            return []
        shas = [eligible[0][1]]
        if len(eligible) > 2:  # noqa: PLR2004
            shas.append(eligible[len(eligible) // 2][1])
        return shas

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
        remaining = [p for p in pairs if p not in seen]
        sample_count = min(23, len(remaining))
        if sample_count > 0:
            for pair in random.sample(remaining, sample_count):
                add(pair)
        return selected
