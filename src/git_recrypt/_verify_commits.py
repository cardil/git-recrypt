"""Commit-level verification helpers (checkout-based and blob-wise)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from git_recrypt._git import (
    get_file_content,
    get_file_list,
    git_checkout,
)
from git_recrypt.crypto import GITCRYPT_HEADER, CryptoEngine, is_encrypted
from git_recrypt.errors import CryptoError

if TYPE_CHECKING:
    from pathlib import Path

    from git_recrypt.patterns import PatternMatcher


@dataclass(frozen=True, slots=True)
class FileCheckContext:
    """Context for checking a single encrypted file in a commit."""

    rewritten_sha: str
    fp: str
    orig_content: bytes
    rew_content: bytes
    crypto: CryptoEngine


def check_encrypted_file(errors: list[str], ctx: FileCheckContext) -> None:
    """Append errors for a file that should be encrypted."""
    orig_already_enc = ctx.orig_content[:10] == GITCRYPT_HEADER
    rew_enc = is_encrypted(ctx.rew_content)

    if orig_already_enc and rew_enc:
        if ctx.orig_content != ctx.rew_content:
            sha = ctx.rewritten_sha[:8]
            errors.append(f"commit {sha}: {ctx.fp}: already-encrypted blob differs")
        return

    if not rew_enc:
        sha = ctx.rewritten_sha[:8]
        errors.append(f"commit {sha}: {ctx.fp}: expected encrypted, got plaintext")
        return

    try:
        decrypted = ctx.crypto.decrypt(ctx.rew_content)
    except Exception as exc:  # noqa: BLE001
        sha = ctx.rewritten_sha[:8]
        errors.append(f"commit {sha}: {ctx.fp}: decryption failed: {exc}")
        return

    if decrypted != ctx.orig_content:
        sha = ctx.rewritten_sha[:8]
        errors.append(
            f"commit {sha}: {ctx.fp}: decrypted content differs from original"
        )


def verify_commit_checkout(
    rewritten_path: Path,
    orig_path: Path,
    orig_sha: str,
    rew_sha: str,
) -> list[str]:
    """Verify a commit by checking out and comparing disk files.

    Repo must already be unlocked. Skips .gitattributes and .git-crypt/.
    Returns list of error strings.
    """
    errors: list[str] = []
    try:
        git_checkout(rewritten_path, rew_sha)
    except CryptoError as exc:
        return [f"commit {rew_sha[:8]}: checkout failed: {exc}"]

    rew_files = set(get_file_list(rewritten_path, rew_sha))
    if ".gitattributes" not in rew_files:
        errors.append(f"commit {rew_sha[:8]}: .gitattributes missing")

    orig_files = get_file_list(orig_path, orig_sha)
    for fp in orig_files:
        if fp == ".gitattributes" or fp.startswith(".git-crypt/"):
            continue
        disk_path = rewritten_path / fp
        if not disk_path.exists():
            errors.append(f"commit {rew_sha[:8]}: file missing on disk: {fp}")
            continue
        disk_content = disk_path.read_bytes()
        orig_content = get_file_content(orig_path, orig_sha, fp)
        if disk_content != orig_content:
            errors.append(
                f"commit {rew_sha[:8]}: {fp}: disk content differs from original"
            )

    orig_file_set = set(orig_files)
    for fp in rew_files:
        if fp == ".gitattributes" or fp.startswith(".git-crypt/"):
            continue
        if fp not in orig_file_set:
            errors.append(
                f"commit {rew_sha[:8]}: unexpected extra file in rewritten tree: {fp}"
            )

    return errors


def verify_commit_blobwise(  # noqa: PLR0913
    orig_path: Path,
    rewritten_path: Path,
    orig_sha: str,
    rew_sha: str,
    matcher: PatternMatcher,
    crypto: CryptoEngine,
) -> list[str]:
    """Verify a commit via git show blob comparison (no checkout).

    For encrypted files: compare raw bytes if both encrypted, else decrypt+compare.
    For non-encrypted files (excluding .gitattributes): compare raw bytes.
    Checks .gitattributes exists in rewritten commit.
    Returns list of error strings.
    """
    errors: list[str] = []
    orig_files = get_file_list(orig_path, orig_sha)
    rew_files = set(get_file_list(rewritten_path, rew_sha))

    if ".gitattributes" not in rew_files:
        errors.append(f"commit {rew_sha[:8]}: .gitattributes missing in rewritten repo")

    for fp in orig_files:
        if fp not in rew_files:
            errors.append(f"commit {rew_sha[:8]}: file missing in rewritten repo: {fp}")
            continue

        orig_content = get_file_content(orig_path, orig_sha, fp)
        rew_content = get_file_content(rewritten_path, rew_sha, fp)

        if matcher.matches(fp):
            check_encrypted_file(
                errors,
                FileCheckContext(
                    rewritten_sha=rew_sha,
                    fp=fp,
                    orig_content=orig_content,
                    rew_content=rew_content,
                    crypto=crypto,
                ),
            )
        elif fp == ".gitattributes":
            pass
        elif rew_content != orig_content:
            errors.append(
                f"commit {rew_sha[:8]}: {fp}: non-encrypted file content differs"
            )

    return errors


@dataclass(frozen=True, slots=True)
class FileVerification:
    """Result of verifying a single file."""

    filepath: str
    expected_encrypted: bool
    actual_encrypted: bool
    content_matches: bool


def verify_head_encryption(
    orig_path: Path,
    rewritten_path: Path,
    pairs: list[tuple[str, str]],
    matcher: PatternMatcher,
    crypto: CryptoEngine,
) -> list[FileVerification]:
    """Verify encryption state of files at HEAD (tip commit)."""
    if not pairs:
        return []
    orig_head, rew_head = pairs[0]
    orig_files = get_file_list(orig_path, orig_head)
    rew_files = set(get_file_list(rewritten_path, rew_head))
    results: list[FileVerification] = []
    for fp in orig_files:
        if not matcher.matches(fp) or fp not in rew_files:
            continue
        orig_content = get_file_content(orig_path, orig_head, fp)
        rew_content = get_file_content(rewritten_path, rew_head, fp)
        actual_enc = is_encrypted(rew_content)
        content_ok = False
        if actual_enc:
            try:
                decrypted = crypto.decrypt(rew_content)
                content_ok = decrypted == orig_content
            except Exception:  # noqa: BLE001
                content_ok = False
        results.append(
            FileVerification(
                filepath=fp,
                expected_encrypted=True,
                actual_encrypted=actual_enc,
                content_matches=content_ok,
            )
        )
    return results
