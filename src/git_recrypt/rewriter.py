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
        self._create_target()
        last_sha = self._replay_commits()
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
        fmt = ["format-patch", "--stdout", "--binary"]
        if is_root:
            fmt += ["--root", sha]
        else:
            fmt += ["-1", sha]
        fmt += ["--", ":!.git-crypt"]
        patch = _run(fmt, src)
        if not patch.strip():
            return
        _apply_patch_and_binaries(src, tgt, sha, patch)
        _ = _run(["add", "-A"], tgt)
        _commit_with_meta(tgt, meta)

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


@dataclass(frozen=True, slots=True)
class _SymlinkChange:
    path: str
    target: str | None
    is_deletion: bool


def _is_symlink_mode_line(line: str) -> bool:
    return line.startswith(("new file mode 120000", "deleted file mode 120000")) or (
        line.startswith("index ") and "120000" in line
    )


def _flush_symlink(
    current_path: str,
    is_symlink: bool,
    is_deletion: bool,
    hunk_lines: list[str],
    changes: list[_SymlinkChange],
) -> None:
    if not (current_path and is_symlink):
        return
    if is_deletion:
        changes.append(_SymlinkChange(path=current_path, target=None, is_deletion=True))
        return
    target: str | None = None
    for hl in hunk_lines:
        if hl.startswith("+") and not hl.startswith("+++"):
            target = hl[1:].rstrip("\r\n")
            break
    if target is not None:
        changes.append(
            _SymlinkChange(path=current_path, target=target, is_deletion=False)
        )


def _find_symlink_changes(patch: bytes) -> list[_SymlinkChange]:
    changes: list[_SymlinkChange] = []
    current_path: str = ""
    is_symlink: bool = False
    is_deletion: bool = False
    hunk_lines: list[str] = []
    in_hunk: bool = False

    for raw_line in patch.split(b"\n"):
        line = raw_line.decode(errors="replace")
        if line.startswith("diff --git a/"):
            _flush_symlink(current_path, is_symlink, is_deletion, hunk_lines, changes)
            current_path = line.split(" b/", 1)[-1].rstrip("\r\n")
            is_symlink = False
            is_deletion = False
            hunk_lines = []
            in_hunk = False
        elif _is_symlink_mode_line(line):
            is_symlink = True
            is_deletion = line.startswith("deleted file mode 120000")
        elif line.startswith("@@"):
            in_hunk = True
        elif in_hunk:
            hunk_lines.append(line)

    _flush_symlink(current_path, is_symlink, is_deletion, hunk_lines, changes)
    return changes


def _strip_symlink_diffs(patch: bytes) -> bytes:
    lines = patch.split(b"\n")
    result: list[bytes] = []
    skip = False
    for line in lines:
        if line.startswith(b"diff --git a/"):
            skip = False
        if skip:
            continue
        decoded = line.decode(errors="replace")
        if decoded.startswith(("new file mode 120000", "deleted file mode 120000")) or (
            "120000" in decoded and decoded.startswith("index ")
        ):
            skip = True
            while result and not result[-1].startswith(b"diff --git"):
                _ = result.pop()
            _ = result.pop()
            continue
        result.append(line)
    return b"\n".join(result)


def _apply_symlink_changes(tgt: Path, changes: list[_SymlinkChange]) -> None:
    for change in changes:
        dest = tgt / change.path
        if change.is_deletion:
            if dest.is_symlink():
                dest.unlink()
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.is_symlink() or dest.exists():
                dest.unlink()
            if change.target is not None:
                dest.symlink_to(change.target)


def _apply_patch_and_binaries(
    src: Path, tgt: Path, sha: str, patch: bytes,
) -> None:
    added, deleted = _find_binary_files(patch)
    symlink_changes = _find_symlink_changes(patch)
    has_specials = bool(added or deleted or symlink_changes)
    text_patch = patch
    if has_specials:
        text_patch = _strip_binary_diffs(patch)
        if symlink_changes:
            text_patch = _strip_symlink_diffs(text_patch)
    if _has_patchable_diffs(text_patch):
        r = subprocess.run(
            ["/usr/bin/patch", "-p1", "--no-backup-if-mismatch", "-s"],
            cwd=tgt, input=text_patch, capture_output=True, check=False,
        )
        if r.returncode != 0:
            raw: bytes = r.stderr or r.stdout or b""
            raise RewriteError(
                phase="patch",
                detail=f"patch -p1 failed: {raw.decode(errors='replace')}",
            )
    for fp in added:
        dest = tgt / fp
        dest.parent.mkdir(parents=True, exist_ok=True)
        blob = _run(["show", f"{sha}:{fp}"], src)
        _ = dest.write_bytes(blob)
    for fp in deleted:
        dest = tgt / fp
        if dest.exists():
            dest.unlink()
    _apply_symlink_changes(tgt, symlink_changes)


def _has_patchable_diffs(patch: bytes) -> bool:
    """Return True if patch has at least one diff block that patch(1) can apply.

    A diff block is patchable when it contains more than just a bare
    'diff --git' header -- i.e. it has index/mode lines, hunk markers, or
    empty-file markers.  Stripped binary-only patches leave bare 'diff --git'
    lines with nothing after them; those must not be passed to patch(1).
    """
    lines = patch.split(b"\n")
    in_diff = False
    for line in lines:
        if line.startswith(b"diff --git a/"):
            in_diff = True
            continue
        if in_diff:
            if line.startswith(b"diff --git a/"):
                continue
            if line.strip():
                return True
    return False


def _find_binary_files(patch: bytes) -> tuple[list[str], list[str]]:
    added: list[str] = []
    deleted: list[str] = []
    current: str = ""
    is_deletion: bool = False
    for line in patch.split(b"\n"):
        if line.startswith(b"diff --git a/"):
            current = line.decode(errors="replace").split(" b/", 1)[-1]
            is_deletion = False
        elif line.startswith(b"deleted file mode"):
            is_deletion = True
        elif line.startswith(b"GIT binary patch") and current:
            if is_deletion:
                deleted.append(current)
            else:
                added.append(current)
            current = ""
            is_deletion = False
    return added, deleted


def _strip_binary_diffs(patch: bytes) -> bytes:
    lines = patch.split(b"\n")
    result: list[bytes] = []
    skip = False
    for line in lines:
        if line.startswith(b"diff --git a/"):
            skip = False
        if line.startswith(b"GIT binary patch"):
            skip = True
            while result and not result[-1].startswith(b"diff --git"):
                _ = result.pop()
            continue
        if not skip:
            result.append(line)
    return b"\n".join(result)


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
