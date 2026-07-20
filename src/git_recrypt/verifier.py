"""Verify that a rewritten repo matches the original."""

from __future__ import annotations

import random
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from git_recrypt._git import get_commit_list, get_file_content, get_file_list
from git_recrypt.crypto import CryptoEngine, is_encrypted

if TYPE_CHECKING:
    from pathlib import Path

    from git_recrypt.patterns import PatternMatcher


class VerifyMode(StrEnum):
    """Verification thoroughness."""

    FULL = "full"
    FAST = "fast"


@dataclass(frozen=True, slots=True)
class FileVerification:
    """Result of verifying a single file."""

    filepath: str
    expected_encrypted: bool
    actual_encrypted: bool
    content_matches: bool


@dataclass(frozen=True, slots=True)
class CommitVerification:
    """Result of verifying a single commit."""

    original_sha: str
    rewritten_sha: str
    files_verified: int
    gitattributes_present: bool
    errors: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class VerifyResult:
    """Overall verification result."""

    passed: bool
    commits_verified: int
    commits_total: int
    files_verified: int
    encrypted_files: tuple[FileVerification, ...]
    errors: tuple[str, ...]


class RewriteVerifier:
    """Verifies a rewritten repo matches the original."""

    _original_path: Path
    _rewritten_path: Path
    _crypto: CryptoEngine
    _matcher: PatternMatcher
    _mode: VerifyMode

    def __init__(
        self,
        original_path: Path,
        rewritten_path: Path,
        key_file: Path,
        matcher: PatternMatcher,
        mode: VerifyMode = VerifyMode.FAST,
    ) -> None:
        """Initialize the verifier.

        Args:
            original_path: Path to the original (plaintext) repo.
            rewritten_path: Path to the rewritten (encrypted) repo.
            key_file: Path to the git-crypt key file.
            matcher: PatternMatcher for determining which files should be encrypted.
            mode: Verification thoroughness (FULL or FAST).
        """
        self._original_path = original_path
        self._rewritten_path = rewritten_path
        self._crypto = CryptoEngine(key_file=key_file)
        self._matcher = matcher
        self._mode = mode

    def verify(self) -> VerifyResult:
        """Run verification and return aggregated result.

        Returns:
            VerifyResult with pass/fail status and collected errors.
        """
        original_commits = get_commit_list(self._original_path)
        rewritten_commits = get_commit_list(self._rewritten_path)

        commits_total = len(original_commits)
        pairs = list(zip(original_commits, rewritten_commits, strict=False))

        if self._mode == VerifyMode.FAST:
            pairs_to_check = self._select_fast_sample(pairs)
        else:
            pairs_to_check = pairs

        all_errors: list[str] = []
        all_encrypted: list[FileVerification] = []
        total_files = 0

        for orig_sha, rew_sha in pairs_to_check:
            cv = self._verify_commit(orig_sha, rew_sha)
            all_errors.extend(cv.errors)
            total_files += cv.files_verified

        # Collect encrypted file verifications from HEAD
        if pairs_to_check:
            orig_head, rew_head = pairs_to_check[0]
            orig_files = get_file_list(self._original_path, orig_head)
            rew_files = set(get_file_list(self._rewritten_path, rew_head))
            for fp in orig_files:
                if not self._matcher.matches(fp):
                    continue
                if fp not in rew_files:
                    continue
                orig_content = get_file_content(self._original_path, orig_head, fp)
                rew_content = get_file_content(self._rewritten_path, rew_head, fp)
                actual_enc = is_encrypted(rew_content)
                content_ok = False
                if actual_enc:
                    try:
                        decrypted = self._crypto.decrypt(rew_content)
                        content_ok = decrypted == orig_content
                    except Exception:  # noqa: BLE001
                        content_ok = False
                all_encrypted.append(
                    FileVerification(
                        filepath=fp,
                        expected_encrypted=True,
                        actual_encrypted=actual_enc,
                        content_matches=content_ok,
                    )
                )

        return VerifyResult(
            passed=len(all_errors) == 0,
            commits_verified=len(pairs_to_check),
            commits_total=commits_total,
            files_verified=total_files,
            encrypted_files=tuple(all_encrypted),
            errors=tuple(all_errors),
        )

    def _select_fast_sample(
        self, pairs: list[tuple[str, str]]
    ) -> list[tuple[str, str]]:
        """Select HEAD, root commit, and a random 10% sample (min 5, max 50).

        Args:
            pairs: All (original_sha, rewritten_sha) pairs in rev-list order.

        Returns:
            Deduplicated subset of pairs to verify.
        """
        if not pairs:
            return []

        selected: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()

        def add(pair: tuple[str, str]) -> None:
            if pair not in seen:
                seen.add(pair)
                selected.append(pair)

        # HEAD is first in rev-list output, root is last
        add(pairs[0])
        add(pairs[-1])

        sample_count = max(5, min(50, len(pairs) // 10))
        for pair in random.sample(pairs, min(sample_count, len(pairs))):
            add(pair)

        return selected

    def _verify_commit(
        self, original_sha: str, rewritten_sha: str
    ) -> CommitVerification:
        """Verify a single commit pair.

        Args:
            original_sha: SHA in the original repo.
            rewritten_sha: SHA in the rewritten repo.

        Returns:
            CommitVerification with per-file results and errors.
        """
        errors: list[str] = []
        files_verified = 0

        orig_files = get_file_list(self._original_path, original_sha)
        rew_files = set(get_file_list(self._rewritten_path, rewritten_sha))

        gitattributes_present = ".gitattributes" in rew_files
        if not gitattributes_present:
            errors.append(
                f"commit {rewritten_sha[:8]}: .gitattributes missing in rewritten repo"
            )

        for fp in orig_files:
            if fp not in rew_files:
                errors.append(
                    f"commit {rewritten_sha[:8]}: file missing in rewritten repo: {fp}"
                )
                continue

            orig_content = get_file_content(self._original_path, original_sha, fp)
            rew_content = get_file_content(self._rewritten_path, rewritten_sha, fp)
            files_verified += 1

            if self._matcher.matches(fp):
                if not is_encrypted(rew_content):
                    errors.append(
                        f"commit {rewritten_sha[:8]}: {fp}: expected encrypted, got plaintext"  # noqa: E501
                    )
                    continue
                try:
                    decrypted = self._crypto.decrypt(rew_content)
                except Exception as exc:  # noqa: BLE001
                    errors.append(
                        f"commit {rewritten_sha[:8]}: {fp}: decryption failed: {exc}"
                    )
                    continue
                if decrypted != orig_content:
                    errors.append(
                        f"commit {rewritten_sha[:8]}: {fp}: decrypted content differs from original"  # noqa: E501
                    )
            elif rew_content != orig_content:
                errors.append(
                    f"commit {rewritten_sha[:8]}: {fp}: non-encrypted file content differs"  # noqa: E501
                )

        return CommitVerification(
            original_sha=original_sha,
            rewritten_sha=rewritten_sha,
            files_verified=files_verified,
            gitattributes_present=gitattributes_present,
            errors=tuple(errors),
        )
