"""Commit-level verification helpers (checkout-based)."""

from __future__ import annotations

import subprocess
import tempfile
from collections.abc import Callable
from typing import TYPE_CHECKING, Final

from git_recrypt._git import (
    get_file_list,
    git_checkout,
)
from git_recrypt._shellout import GIT, find_diff
from git_recrypt.errors import CryptoError

if TYPE_CHECKING:
    from pathlib import Path

_DIFF: Final[str | None] = find_diff()
_RelFn = Callable[[str], str]


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
            path_a = line.split(" and ", 1)[0].removeprefix("Files ").strip()
            errors.append(f"commit {sha}: content mismatch: {rel(path_a)}")
        elif line.startswith("Only in ") and ": " in line:
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
        elif "Symbolic links" in line and "differ" in line:
            path_a = line.split(" and ", 1)[0].removeprefix("Symbolic links ").strip()
            errors.append(f"commit {sha}: symlink target mismatch: {rel(path_a)}")
        elif "is a symbolic link while" in line or "is a regular file while" in line:
            path_part = line.split(" is a ")[0].removeprefix("File ").strip()
            errors.append(f"commit {sha}: file type mismatch: {rel(path_part)}")
        else:
            errors.append(f"commit {sha}: unexpected diff output: {line}")
    return errors


def _parse_diff_stderr(lines: list[str], sha: str, rel: _RelFn) -> list[str]:
    errors: list[str] = []
    for line in lines:
        line = line.strip()  # noqa: PLW2901
        if not line:
            continue
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
            GIT, "-C", str(orig_path),
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
            _ = subprocess.run(  # noqa: S603
                [GIT, "-C", str(orig_path), "worktree", "remove", "--force", tmpdir],
                capture_output=True,
                check=False,
            )

    return errors
