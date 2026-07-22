"""History rewriter: retroactively inject git-crypt encryption via tree-replay."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final

from git_recrypt._replay import (
    CommitInfo,
    CommitMeta,
    TreeEntry,
    git_commit_tree,
    git_hash_object,
    git_init,
    git_mktree,
    git_update_ref,
    list_commits_topo,
    make_empty_tree,
    now_git_date,
    read_commit_meta,
    run_git_crypt,
)
from git_recrypt._state import (
    StateConfig,
    save_commit_map,
    save_config,
    save_setup_commits,
    state_dir_for_repo,
)
from git_recrypt._tree_replay import count_encrypted_files
from git_recrypt.crypto import is_encrypted
from git_recrypt.errors import RewriteError
from git_recrypt.patterns import PatternMatcher, generate_gitattributes

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from git_recrypt.manifest import Manifest

_GIT: Final = "/usr/bin/git"


def _run(args: list[str], cwd: Path, *, inp: bytes | None = None) -> bytes:
    """Run git command, return stdout. Raises RewriteError on failure."""
    r = subprocess.run(  # noqa: S603
        [_GIT, *args], cwd=cwd, capture_output=True, check=False, input=inp
    )
    if r.returncode != 0:
        val: object = getattr(r, "stderr", None)
        raw: bytes = val if isinstance(val, bytes) else b""
        stderr = raw.decode(errors="replace") if raw else "unknown"
        raise RewriteError(phase=args[0], detail=f"git {args[0]} failed: {stderr}")
    val2: object = getattr(r, "stdout", None)
    return val2 if isinstance(val2, bytes) else b""


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
    setup_commits: tuple[str, ...]


class HistoryRewriter:
    """Rewrites git history to retroactively add git-crypt encryption."""

    def __init__(
        self,
        config: RewriteConfig,
        progress_callback: Callable[[RewriteProgress], None] | None = None,
    ) -> None:
        """Initialize the rewriter with config and optional progress callback."""
        self._config: RewriteConfig = config
        self._progress_cb: Callable[[RewriteProgress], None] | None = progress_callback
        self._commits_processed: int = 0
        self._sha_map: dict[str, str] = {}
        self._setup_commits: list[str] = []

    def run(self) -> RewriteResult:
        """Execute the full rewrite pipeline."""
        _assert_not_encrypted(self._config.repo_path, self._config.manifest)
        start = time.monotonic()
        try:
            self._create_target()
            last_sha = self._replay_commits()
        except RewriteError as exc:
            _enrich_error_with_debug_hint(exc, self._config.repo_path)
            raise
        from git_recrypt._git import git_checkout  # noqa: PLC0415

        git_checkout(self._config.work_dir, "master")
        files_encrypted = count_encrypted_files(self._config.work_dir)
        self._save_state(last_sha)
        elapsed = time.monotonic() - start
        return RewriteResult(
            work_dir=self._config.work_dir,
            commits_rewritten=self._commits_processed,
            files_encrypted=files_encrypted,
            elapsed_seconds=elapsed,
            setup_commits=tuple(self._setup_commits),
        )

    def _create_target(self) -> None:
        """Phase 1: create target repo with git-crypt setup, then unlock."""
        t = self._config.work_dir
        if t.exists():
            shutil.rmtree(t)
        git_init(t)
        bot = CommitMeta("git-recrypt", "git-recrypt@localhost", now_git_date())
        init_sha = git_commit_tree(
            t, make_empty_tree(t), [], "git-recrypt: initial setup", bot, bot
        )
        self._setup_commits.append(init_sha)
        git_update_ref(t, "refs/heads/master", init_sha)
        m = self._config.manifest
        gpg_cfg = m.key.gpg
        if gpg_cfg is not None and gpg_cfg.user_ids is not None:
            from git_recrypt.crypto import init_gpg_repo  # noqa: PLC0415

            init_gpg_repo(t, gpg_cfg.user_ids)
        else:
            run_git_crypt(t, ["init"])
        keys_dir = t / ".git" / "git-crypt" / "keys"
        keys_dir.mkdir(parents=True, exist_ok=True)
        _ = shutil.copy2(self._config.key_file, keys_dir / "default")
        ga_sha = git_hash_object(t, generate_gitattributes(m.patterns).encode())
        tree_sha = git_mktree(
            t, [TreeEntry("100644", "blob", ga_sha, ".gitattributes")]
        )
        ga_commit = git_commit_tree(
            t, tree_sha, [init_sha], "git-recrypt: add .gitattributes", bot, bot
        )
        self._setup_commits.append(ga_commit)
        git_update_ref(t, "refs/heads/master", ga_commit)
        _ = _run(["reset", "--hard", "HEAD"], t)
        # Unlock so smudge/clean filters work transparently during replay.
        run_git_crypt(t, ["unlock", str(self._config.key_file)])

    def _replay_commits(self) -> str:
        """Phase 2: apply patches. git-crypt clean filter encrypts on add."""
        src = self._config.repo_path
        if not src.exists():
            msg = f"Source repo not found: {src}"
            raise RewriteError(phase="replay", detail=msg)
        tgt = self._config.work_dir
        commits = list_commits_topo(src)
        total = len(commits)
        for i, old_sha in enumerate(commits):
            meta = read_commit_meta(src, old_sha)
            self._apply_and_commit(old_sha, src, tgt, meta, is_root=(i == 0))
            self._sha_map[old_sha] = _rev_parse(tgt)
            self._commits_processed += 1
            if self._progress_cb is not None:
                self._progress_cb(
                    RewriteProgress(
                        phase="replay",
                        commits_processed=self._commits_processed,
                        commits_total=total,
                        files_encrypted=0,
                    )
                )
        return _rev_parse(tgt)

    def _apply_and_commit(
        self,
        sha: str,
        src: Path,
        tgt: Path,
        meta: CommitInfo,
        *,
        is_root: bool,
    ) -> None:
        if len(meta.parents) > 1:
            self._replay_merge_commit(tgt, meta)
            return
        fmt = ["format-patch", "--stdout", "--binary", "--no-stat"]
        if is_root:
            fmt += ["--root", sha]
        else:
            fmt += ["-1", sha]
        fmt += ["--", ":!.git-crypt"]
        patch = _run(fmt, src)
        if not patch.strip():
            return
        _dump_debug_patch(src, sha, patch)
        _git_apply(tgt, patch)
        _ = _run(["add", "-A"], tgt)
        _commit_with_meta(tgt, meta)

    def _replay_merge_commit(self, tgt: Path, meta: CommitInfo) -> None:
        mapped_parents = [self._sha_map[p] for p in meta.parents]
        _ = _run(["checkout", mapped_parents[0]], tgt)
        merge_cmd = ["merge", "--no-commit", "--no-ff", mapped_parents[1]]
        r = subprocess.run(  # noqa: S603
            [_GIT, *merge_cmd], cwd=tgt, capture_output=True, check=False
        )
        if r.returncode not in {0, 1}:
            raw: bytes = r.stderr or b""
            raise RewriteError(
                phase="merge",
                detail=f"git merge failed: {raw.decode(errors='replace')}",
            )
        _ = _run(["add", "-A"], tgt)
        _commit_with_meta(tgt, meta)
        _ = _run(["checkout", "master"], tgt)
        _ = _run(["merge", "--ff-only", "HEAD@{1}"], tgt)

    def _save_state(self, _last_sha: str) -> None:
        """Phase 3: persist commit map, setup commits, and config."""
        src = self._config.repo_path
        sd = state_dir_for_repo(src)
        save_commit_map(sd, self._sha_map)
        save_setup_commits(sd, self._setup_commits)
        mhash = hashlib.sha256(
            str(self._config.manifest.model_dump()).encode()
        ).hexdigest()
        save_config(
            sd,
            StateConfig(
                source_repo=str(src.resolve()),
                target_repo=str(self._config.work_dir.resolve()),
                manifest_hash=mhash,
                status="complete",
                timestamp=datetime.now(tz=UTC).isoformat(),
            ),
        )


def _dump_debug_patch(src: Path, sha: str, patch: bytes) -> None:
    from git_recrypt._state import debug_dir_for_repo, is_debug  # noqa: PLC0415

    if not is_debug():
        return
    dbg = debug_dir_for_repo(src)
    dbg.mkdir(parents=True, exist_ok=True)
    _ = (dbg / f"{sha}.patch").write_bytes(patch)


def _enrich_error_with_debug_hint(exc: RewriteError, src: Path) -> None:
    from git_recrypt._state import (  # noqa: PLC0415
        DEBUG_ENV,
        debug_dir_for_repo,
        is_debug,
    )

    if is_debug():
        return
    exc.detail += (
        f"\nRe-run with {DEBUG_ENV}=1 to dump debug data to {debug_dir_for_repo(src)}"
    )


def _git_apply(tgt: Path, patch: bytes) -> None:
    ga = tgt / ".gitattributes"
    ga_hidden = tgt / ".gitattributes.gcri-hidden"
    _ = ga.rename(ga_hidden)
    try:
        r = subprocess.run(  # noqa: S603
            [_GIT, "apply", "--whitespace=nowarn"],
            cwd=tgt, input=patch, capture_output=True, check=False,
        )
    finally:
        _ = ga_hidden.rename(ga)
    if r.returncode != 0:
        raw: bytes = r.stderr or r.stdout or b""
        raise RewriteError(
            phase="apply",
            detail=f"git apply failed: {raw.decode(errors='replace')}",
        )


def _rev_parse(repo: Path) -> str:
    return _run(["rev-parse", "HEAD"], repo).decode().strip()


def _commit_with_meta(tgt: Path, meta: CommitInfo) -> None:
    import os  # noqa: PLC0415

    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": meta.author.name,
        "GIT_AUTHOR_EMAIL": meta.author.email,
        "GIT_AUTHOR_DATE": meta.author.date,
        "GIT_COMMITTER_NAME": meta.committer.name,
        "GIT_COMMITTER_EMAIL": meta.committer.email,
        "GIT_COMMITTER_DATE": meta.committer.date,
    }
    cmd = [
        _GIT, "-c", "commit.gpgsign=false",
        "commit", "--allow-empty", "-m", meta.message,
    ]
    r = subprocess.run(  # noqa: S603
        cmd, cwd=tgt, capture_output=True, check=False, env=env,
    )
    if r.returncode != 0:
        raw: bytes = r.stderr or b""
        stderr = raw.decode(errors="replace")
        raise RewriteError(phase="commit", detail=f"git commit failed: {stderr}")


def _assert_not_encrypted(repo: Path, manifest: Manifest) -> None:
    """Module-level pre-check: raise RewriteError if source has encrypted files."""
    from git_recrypt._git import get_file_content, get_file_list  # noqa: PLC0415

    if not repo.exists():
        return
    try:
        head = _run(["rev-parse", "HEAD"], repo).decode().strip()
    except RewriteError:
        return
    matcher = PatternMatcher(
        include_patterns=tuple(manifest.patterns),
        exclude_patterns=tuple(manifest.exclude),
    )
    for fp in get_file_list(repo, head):
        if not matcher.matches(fp):
            continue
        if is_encrypted(get_file_content(repo, head, fp)):
            raise RewriteError(
                phase="pre-check",
                detail=f"Source repo has encrypted files (e.g. {fp}). Decrypt first.",
            )
