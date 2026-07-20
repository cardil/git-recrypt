"""History rewriter: retroactively inject git-crypt encryption via git-filter-repo."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final

import git_filter_repo  # type: ignore[import-untyped]

from git_recrypt.crypto import CryptoEngine, is_encrypted
from git_recrypt.errors import RewriteError
from git_recrypt.patterns import PatternMatcher, generate_gitattributes

if TYPE_CHECKING:
    from collections.abc import Callable

    from git_recrypt.manifest import Manifest

_GIT: Final = "/usr/bin/git"
_GITATTRIBUTES: Final = b".gitattributes"
_MODE_REGULAR: Final = b"100644"


@dataclass(frozen=True, slots=True)
class RewriteConfig:
    """Configuration for a history rewrite operation."""

    manifest: Manifest
    key_file: Path
    repo_path: Path
    work_dir: Path


@dataclass(frozen=True, slots=True)
class RewriteProgress:
    """Progress update during rewrite."""

    phase: str
    commits_processed: int
    commits_total: int
    files_encrypted: int


@dataclass(frozen=True, slots=True)
class RewriteResult:
    """Result of a completed rewrite."""

    work_dir: Path
    commits_rewritten: int
    files_encrypted: int
    elapsed_seconds: float


class HistoryRewriter:
    """Rewrites git history to retroactively add git-crypt encryption.

    Uses git-filter-repo in two passes:
    1. Inject .gitattributes at the target commit.
    2. Encrypt all matching files across all commits.
    """

    _config: RewriteConfig
    _progress_cb: Callable[[RewriteProgress], None] | None
    _files_encrypted: int
    _commits_processed: int

    def __init__(
        self,
        config: RewriteConfig,
        progress_callback: Callable[[RewriteProgress], None] | None = None,
    ) -> None:
        """Initialize the rewriter with config and optional progress callback."""
        self._config = config
        self._progress_cb = progress_callback
        self._files_encrypted = 0
        self._commits_processed = 0

    def run(self) -> RewriteResult:
        """Execute the full rewrite pipeline."""
        start = time.monotonic()
        clone_path = self._clone_repo()
        self._setup_git_crypt(clone_path)
        self._rewrite_history(clone_path)
        elapsed = time.monotonic() - start
        return RewriteResult(
            work_dir=clone_path,
            commits_rewritten=self._commits_processed,
            files_encrypted=self._files_encrypted,
            elapsed_seconds=elapsed,
        )

    def _clone_repo(self) -> Path:
        """Clone the source repo to work_dir."""
        work = self._config.work_dir
        if work.exists():
            shutil.rmtree(work)
        try:
            _ = subprocess.run(  # noqa: S603
                [_GIT, "clone", "--no-local", str(self._config.repo_path), str(work)],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as exc:
            raise RewriteError(
                phase="clone",
                detail=f"git clone failed: {_exc_stderr(exc)}",
            ) from exc
        return work

    def _setup_git_crypt(self, clone_path: Path) -> None:
        """Copy key file into the clone's git-crypt keys directory."""
        keys_dir = clone_path / ".git" / "git-crypt" / "keys"
        keys_dir.mkdir(parents=True, exist_ok=True)
        _ = shutil.copy2(self._config.key_file, keys_dir / "default")

    def _rewrite_history(self, clone_path: Path) -> None:
        """Two-pass rewrite: inject .gitattributes, then encrypt matching files."""
        manifest = self._config.manifest
        gitattributes_content = generate_gitattributes(manifest.patterns).encode()
        matcher = PatternMatcher(
            include_patterns=tuple(manifest.patterns),
            exclude_patterns=tuple(manifest.exclude),
        )
        crypto = CryptoEngine(key_file=self._config.key_file)
        self._pass1_inject_gitattributes(clone_path, manifest, gitattributes_content)
        self._pass2_encrypt_files(clone_path, matcher, crypto)

    def _pass1_inject_gitattributes(
        self,
        clone_path: Path,
        manifest: Manifest,
        gitattributes_content: bytes,
    ) -> None:
        """Pass 1: inject .gitattributes blob at the target commit."""
        blob_hash = _create_blob(clone_path, gitattributes_content)
        introduce_at = manifest.introduce_at
        injected: list[bool] = [False]

        def commit_callback(commit: git_filter_repo.Commit, _metadata: object) -> None:
            self._commits_processed += 1
            if injected[0]:
                return
            if not _should_inject(commit, introduce_at):
                return
            change = git_filter_repo.FileChange(
                b"M", _GITATTRIBUTES, blob_hash, _MODE_REGULAR
            )
            commit.file_changes.append(change)
            injected[0] = True

        orig = Path.cwd()
        os.chdir(clone_path)
        try:
            args = git_filter_repo.FilteringOptions.default_options()
            args.force = True
            git_filter_repo.RepoFilter(args, commit_callback=commit_callback).run()
        finally:
            os.chdir(orig)

    def _pass2_encrypt_files(
        self,
        clone_path: Path,
        matcher: PatternMatcher,
        crypto: CryptoEngine,
    ) -> None:
        """Pass 2: encrypt matching files via file_info_callback."""

        def file_info_callback(
            filename: bytes,
            mode: bytes,
            blob_id: bytes | int,
            value: git_filter_repo.FileInfoValueHelper,
        ) -> tuple[bytes, bytes, bytes | int]:
            if not matcher.matches_bytes(filename):
                return (filename, mode, blob_id)
            contents = value.get_contents_by_identifier(blob_id)
            if contents is None or is_encrypted(contents):
                return (filename, mode, blob_id)
            encrypted = crypto.encrypt(contents)
            new_id = value.insert_file_with_contents(encrypted)
            self._files_encrypted += 1
            return (filename, mode, new_id)

        orig = Path.cwd()
        os.chdir(clone_path)
        try:
            args = git_filter_repo.FilteringOptions.default_options()
            args.force = True
            git_filter_repo.RepoFilter(
                args, file_info_callback=file_info_callback
            ).run()
        finally:
            os.chdir(orig)


def _exc_stderr(exc: subprocess.CalledProcessError) -> str:
    """Extract stderr from a CalledProcessError as a decoded string."""
    val: object = getattr(exc, "stderr", None)
    raw: bytes = val if isinstance(val, bytes) else b""
    return raw.decode(errors="replace") if raw else "unknown"


def _create_blob(repo_path: Path, content: bytes) -> bytes:
    """Write content to git object store, return the blob hash as bytes."""
    try:
        result = subprocess.run(  # noqa: S603
            [_GIT, "hash-object", "-w", "--stdin"],
            input=content,
            capture_output=True,
            check=True,
            cwd=repo_path,
        )
    except subprocess.CalledProcessError as exc:
        raise RewriteError(
            phase="blob-create",
            detail=f"git hash-object failed: {_exc_stderr(exc)}",
        ) from exc
    return result.stdout.strip()


def _should_inject(commit: git_filter_repo.Commit, introduce_at: str) -> bool:
    """Return True if .gitattributes should be injected at this commit."""
    if introduce_at == "root":
        return len(commit.parents) == 0
    if introduce_at == "first-match":
        return bool(commit.file_changes)
    # SHA match
    orig_id = commit.original_id
    if orig_id is None:
        return False
    return orig_id.decode("ascii", errors="replace") == introduce_at
