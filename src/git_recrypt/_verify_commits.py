"""Commit-level verification helpers (checkout-based and blob-wise)."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

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

_DIFF: Final[str | None] = shutil.which("diff")
_GIT_BIN: Final[str] = shutil.which("git") or "git"
_RelFn = Callable[[str], str]


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


def _parse_diff_stdout(
    lines: list[str],
    sha: str,
    tmpdir_prefix: str,
    tmpdir: str,
    rel: _RelFn,
) -> list[str]:
    errors: list[str] = []
    for line in lines:
        line = line.strip()  # noqa: PLW2901
        if not line:
            continue
        if line.startswith("Files ") and " differ" in line:
            # diff -rq format: "Files /a/foo and /b/foo differ"
            path_a = line.split(" and ", 1)[0].removeprefix("Files ").strip()
            errors.append(f"commit {sha}: content mismatch: {rel(path_a)}")
        elif line.startswith("Only in ") and ": " in line:
            # diff -rq format: "Only in /dir: filename"
            rest = line.removeprefix("Only in ").strip()
            dir_part, name = rest.split(": ", 1)
            full = dir_part.rstrip("/") + "/" + name
            rel_path = rel(full)
            in_orig = (
                dir_part.startswith(tmpdir_prefix.rstrip("/"))
                or dir_part == tmpdir.rstrip("/")
            )
            if in_orig:
                errors.append(
                    f"commit {sha}: file missing from rewritten tree: {rel_path}"
                )
            else:
                errors.append(
                    f"commit {sha}: unexpected extra file in rewritten tree: {rel_path}"
                )
    return errors


def _parse_diff_stderr(lines: list[str], sha: str, rel: _RelFn) -> list[str]:
    errors: list[str] = []
    for line in lines:
        line = line.strip()  # noqa: PLW2901
        if not line:
            continue
        # diff stderr format: "diff: /path: No such file or directory" (broken symlink)
        if line.startswith("diff:") and "No such file or directory" in line:
            path_part = line.removeprefix("diff:").split(":")[0].strip()
            errors.append(f"commit {sha}: inaccessible path: {rel(path_part)}")
    return errors


def _parse_diff_output(
    stdout: str,
    stderr: str,
    tmpdir: str,
    rewritten_path: Path,
    rew_sha: str,
) -> list[str]:
    sha = rew_sha[:8]
    tmpdir_prefix = tmpdir.rstrip("/") + "/"
    rew_prefix = str(rewritten_path).rstrip("/") + "/"

    def rel(raw: str) -> str:
        if raw.startswith(tmpdir_prefix):
            return raw[len(tmpdir_prefix):]
        if raw.startswith(rew_prefix):
            return raw[len(rew_prefix):]
        return raw

    return [
        *_parse_diff_stdout(stdout.splitlines(), sha, tmpdir_prefix, tmpdir, rel),
        *_parse_diff_stderr(stderr.splitlines(), sha, rel),
    ]


def verify_commit_checkout(
    rewritten_path: Path,
    orig_path: Path,
    orig_sha: str,
    rew_sha: str,
) -> list[str]:
    if _DIFF is None:
        return [f"commit {rew_sha[:8]}: diff not found in PATH"]

    errors: list[str] = []

    try:
        git_checkout(rewritten_path, rew_sha)
    except CryptoError as exc:
        return [f"commit {rew_sha[:8]}: checkout failed: {exc}"]

    rew_files = set(get_file_list(rewritten_path, rew_sha))
    if ".gitattributes" not in rew_files:
        errors.append(f"commit {rew_sha[:8]}: .gitattributes missing")

    with tempfile.TemporaryDirectory() as tmpdir:
        wt_cmd = [
            _GIT_BIN, "-C", str(orig_path),
            "worktree", "add", "--detach", tmpdir, orig_sha,
        ]
        wt_result = subprocess.run(wt_cmd, capture_output=True, check=False)  # noqa: S603
        if wt_result.returncode != 0:
            stderr_str = wt_result.stderr.decode(errors="replace")
            return [f"commit {rew_sha[:8]}: worktree add failed: {stderr_str.strip()}"]

        try:
            diff_result = subprocess.run(  # noqa: S603
                [
                    _DIFF,
                    "-rq",
                    "--no-dereference",
                    "--exclude=.git",
                    "--exclude=.gitattributes",
                    "--exclude=.git-crypt",
                    tmpdir,
                    str(rewritten_path),
                ],
                capture_output=True,
                check=False,
            )
            # diff exit codes: 0=identical, 1=differences found, 2=trouble
            if diff_result.returncode == 2:  # noqa: PLR2004
                stderr_str = diff_result.stderr.decode(errors="replace")
                errors.append(f"commit {rew_sha[:8]}: diff error: {stderr_str.strip()}")
            else:
                stdout = diff_result.stdout.decode(errors="replace")
                stderr = diff_result.stderr.decode(errors="replace")
                errors.extend(
                    _parse_diff_output(stdout, stderr, tmpdir, rewritten_path, rew_sha)
                )
        finally:
            subprocess.run(  # noqa: S603
                [_GIT_BIN, "-C", str(orig_path), "worktree", "remove", "--force", tmpdir],  # noqa: E501
                capture_output=True,
                check=False,
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
