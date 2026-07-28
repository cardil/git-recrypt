"""History rewriter: retroactively inject git-crypt encryption via tree-replay."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from git_recrypt._replay import (
    CommitInfo,
    git_init,
    list_commits_topo,
    read_commit_meta,
    run_git_crypt,
)
from git_recrypt._shellout import GIT as _GIT
from git_recrypt._shellout import find_gpg
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


def _git_config(repo: Path, key: str, value: str) -> None:
    _ = _run(["config", key, value], repo)


def _run(args: list[str], cwd: Path, *, inp: bytes | None = None) -> bytes:
    """Run git command, return stdout. Raises RewriteError on failure."""
    try:
        r = subprocess.run(  # noqa: S603
            [_GIT, *args], cwd=cwd, capture_output=True, check=False, input=inp
        )
    except OSError as exc:
        raise RewriteError(
            phase=args[0], detail=f"git {args[0]} failed: {exc}"
        ) from exc
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
    message: str | None = None


@dataclass(frozen=True, slots=True)
class RewriteResult:
    """Result of a completed rewrite."""

    work_dir: Path
    commits_rewritten: int
    files_encrypted: int
    elapsed_seconds: float
    setup_commits: tuple[str, ...]
    branch: str = ""


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
        self._branch: str = ""

    def _resolve_branch(self) -> str:
        m = self._config.manifest
        branch = m.branches[0] if m.branches else "HEAD"
        if branch != "HEAD":
            return branch
        src = self._config.repo_path
        if not src.exists():
            raise RewriteError(
                phase="pre-check",
                detail=f"Source repo not found: {src}",
            )
        raw = _run(["symbolic-ref", "--short", "HEAD"], src)
        resolved = raw.decode().strip()
        if not resolved:
            raise RewriteError(
                phase="pre-check",
                detail=f"Cannot resolve HEAD branch in {src}",
            )
        return resolved

    def run(self) -> RewriteResult:
        """Execute the full rewrite pipeline."""
        _assert_work_dir_safe(self._config.repo_path, self._config.work_dir)
        _assert_not_encrypted(self._config.repo_path, self._config.manifest)
        _assert_gpg_keys_available(self._config.manifest)
        self._branch = self._resolve_branch()
        start = time.monotonic()
        try:
            self._create_target()
            last_sha = self._replay_commits()
        except RewriteError as exc:
            _enrich_error_with_debug_hint(exc, self._config.repo_path)
            raise
        from git_recrypt._git import git_checkout  # noqa: PLC0415

        git_checkout(self._config.work_dir, self._branch)
        files_encrypted = count_encrypted_files(self._config.work_dir)
        self._save_state(last_sha)
        elapsed = time.monotonic() - start
        return RewriteResult(
            work_dir=self._config.work_dir,
            commits_rewritten=self._commits_processed,
            files_encrypted=files_encrypted,
            elapsed_seconds=elapsed,
            setup_commits=tuple(self._setup_commits),
            branch=self._branch,
        )

    def _emit(self, msg: str) -> None:
        if self._progress_cb is not None:
            self._progress_cb(RewriteProgress(
                phase="init", commits_processed=0, commits_total=0,
                files_encrypted=0, message=msg,
            ))

    def _create_target(self) -> None:
        """Phase 1: create target repo with git-crypt setup, then unlock."""
        t = self._config.work_dir
        if t.exists():
            shutil.rmtree(t)
        self._emit(f"Initializing target repo: {t} (branch: {self._branch})")
        git_init(t, branch=self._branch)
        _git_config(t, "user.name", "git-recrypt")
        _git_config(t, "user.email", "git-recrypt@localhost")
        _git_config(t, "commit.gpgsign", "false")
        _ = _run(["commit", "--allow-empty", "-m", "git-recrypt: initial setup"], t)
        self._setup_commits.append(_rev_parse(t))
        m = self._config.manifest
        gpg_cfg = m.key.gpg
        if gpg_cfg is not None and gpg_cfg.user_ids is not None:
            from git_recrypt.crypto import init_gpg_repo  # noqa: PLC0415

            self._emit("Initializing git-crypt (GPG mode)")
            init_gpg_repo(t, gpg_cfg.user_ids)
            for uid in gpg_cfg.user_ids:
                self._emit(f"  Added GPG collaborator: {uid}")
        else:
            self._emit("Initializing git-crypt (symmetric mode)")
            run_git_crypt(t, ["init"])
            keys_dir = t / ".git" / "git-crypt" / "keys"
            keys_dir.mkdir(parents=True, exist_ok=True)
            _ = shutil.copy2(self._config.key_file, keys_dir / "default")
        is_gpg = gpg_cfg is not None and gpg_cfg.user_ids is not None
        self._emit(f"Committing .gitattributes ({len(m.patterns)} patterns)")
        ga_content = generate_gitattributes(m.patterns, exclude=m.exclude)
        _ = (t / ".gitattributes").write_text(ga_content, encoding="utf-8")
        _ = _run(["add", ".gitattributes"], t)
        _ = _run(["commit", "-m", "git-recrypt: add .gitattributes"], t)
        self._setup_commits.append(_rev_parse(t))
        if is_gpg:
            self._emit("Unlocking target repo (GPG)")
            run_git_crypt(t, ["unlock"])
        else:
            self._emit("Unlocking target repo (symmetric key)")
            run_git_crypt(t, ["unlock", str(self._config.key_file)])
        self._emit("Copying remotes from source repo")
        _copy_remotes(self._config.repo_path, t)
        self._emit("Pre-flight: testing lock/unlock roundtrip")
        _preflight_lock_unlock(t, self._config.key_file, is_gpg)
        self._emit("Target repo ready")

    def _replay_commits(self) -> str:
        """Phase 2: apply patches. git-crypt clean filter encrypts on add."""
        src = self._config.repo_path
        if not src.exists():
            msg = f"Source repo not found: {src}"
            raise RewriteError(phase="replay", detail=msg)
        tgt = self._config.work_dir
        commits = list_commits_topo(src, branch=self._branch)
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
            self._replay_merge_commit(sha, src, tgt, meta)
            return
        if not is_root and meta.parents:
            mapped_parent = self._sha_map[meta.parents[0]]
            current_head = _rev_parse(tgt)
            if current_head != mapped_parent:
                _ = _run(["checkout", mapped_parent], tgt)
        fmt = ["format-patch", "--stdout", "--binary", "--no-stat"]
        if is_root:
            fmt += ["--root", sha]
        else:
            fmt += ["-1", sha]
        fmt += ["--", ":!.git-crypt", ":!.gitattributes"]
        patch = _run(fmt, src)
        if not patch.strip():
            _merge_source_gitattributes(src, tgt, sha)
            _ = _run(["add", "-A"], tgt)
            _commit_with_meta(tgt, meta)
            return
        _dump_debug_patch(src, sha, patch)
        _git_apply(tgt, patch)
        _merge_source_gitattributes(src, tgt, sha)
        _ = _run(["add", "-A"], tgt)
        _commit_with_meta(tgt, meta)

    def _replay_merge_commit(
        self, sha: str, src: Path, tgt: Path, meta: CommitInfo,
    ) -> None:
        if len(meta.parents) > 2:  # noqa: PLR2004
            raise RewriteError(
                phase="merge",
                detail=(
                    f"Octopus merges ({len(meta.parents)} parents) are a planned"
                    " feature, not yet implemented."
                ),
            )
        mapped_parents = [self._sha_map[p] for p in meta.parents]
        _ = _run(["checkout", mapped_parents[0]], tgt)
        # Use git diff between first parent and merge commit to reproduce the
        # original author's resolved tree exactly. format-patch fails on merges
        # because files already exist after checking out the first parent.
        diff_cmd = [
            "diff", "-p", "--binary",
            meta.parents[0], sha, "--", ":!.git-crypt", ":!.gitattributes",
        ]
        patch = _run(diff_cmd, src)
        if patch.strip():
            _dump_debug_patch(src, sha, patch)
            _git_apply(tgt, patch)
        _merge_source_gitattributes(src, tgt, sha)
        _ = _run(["add", "-A"], tgt)
        _commit_merge_with_meta(tgt, meta, mapped_parents)
        _ = _run(["checkout", self._branch], tgt)
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


def _merge_source_gitattributes(src: Path, tgt: Path, sha: str) -> None:
    """Merge non-git-crypt lines from source .gitattributes at sha into target."""
    try:
        raw = _run(["show", f"{sha}:.gitattributes"], src)
        src_lines = raw.decode(errors="replace").splitlines()
    except RewriteError:
        # .gitattributes may not exist at this SHA -- that's fine
        return
    ga = tgt / ".gitattributes"
    existing = ga.read_text(encoding="utf-8").splitlines() if ga.exists() else []
    existing_set = set(existing)
    added = False
    for line in src_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "filter=git-crypt" in stripped or "diff=git-crypt" in stripped:
            continue
        if stripped not in existing_set:
            existing.append(line)
            existing_set.add(stripped)
            added = True
    if added:
        _ = ga.write_text("\n".join(existing) + "\n", encoding="utf-8")


def _dump_debug_patch(src: Path, sha: str, patch: bytes) -> None:
    from git_recrypt._state import debug_dir_for_repo, is_debug  # noqa: PLC0415

    if not is_debug():
        return
    dbg = debug_dir_for_repo(src)
    dbg.mkdir(parents=True, exist_ok=True)
    dbg.chmod(0o700)
    p = dbg / f"{sha}.patch"
    _ = p.write_bytes(patch)
    p.chmod(0o600)


def _preflight_lock_unlock(tgt: Path, key_file: Path, is_gpg: bool) -> None:
    run_git_crypt(tgt, ["lock"])
    try:
        if is_gpg:
            run_git_crypt(tgt, ["unlock"])
        else:
            run_git_crypt(tgt, ["unlock", str(key_file)])
    except RewriteError as exc:
        raise RewriteError(
            phase="pre-flight",
            detail=f"lock/unlock roundtrip failed: {exc.detail}",
        ) from exc


def _copy_remotes(src: Path, tgt: Path) -> None:
    """Copy remote definitions from source to target repo."""
    try:
        raw = _run(["remote", "-v"], src)
    except RewriteError:
        return
    remotes: dict[str, dict[str, list[str]]] = {}
    for line in raw.decode(errors="replace").splitlines():
        parts = line.split()
        if len(parts) < 3:  # noqa: PLR2004
            continue
        name, url = parts[0], parts[1]
        kind = parts[2].strip("()")  # "fetch" or "push"
        if name not in remotes:
            remotes[name] = {"fetch": [], "push": []}
        remotes[name][kind].append(url)
    for name, urls in remotes.items():
        fetch_urls = urls.get("fetch", [])
        push_urls = urls.get("push", [])
        if not fetch_urls and not push_urls:
            continue
        primary = fetch_urls[0] if fetch_urls else push_urls[0]
        _ = _run(["remote", "add", name, primary], tgt)
        for extra_fetch in fetch_urls[1:]:
            _ = _run(["remote", "set-url", "--add", name, extra_fetch], tgt)
        if push_urls and push_urls != fetch_urls:
            # Clear default push URL (which equals fetch) and set explicit push URLs
            _ = _run(["remote", "set-url", "--push", name, push_urls[0]], tgt)
            for extra_push in push_urls[1:]:
                _ = _run(
                    ["remote", "set-url", "--add", "--push", name, extra_push], tgt
                )


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


def _commit_merge_with_meta(
    tgt: Path, meta: CommitInfo, parents: list[str],
) -> None:
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
    tree_sha = _run(["write-tree"], tgt).decode().strip()
    parent_args: list[str] = []
    for p in parents:
        parent_args += ["-p", p]
    cmd = [_GIT, "commit-tree", tree_sha, *parent_args, "-m", meta.message]
    new_sha = subprocess.run(  # noqa: S603
        cmd, cwd=tgt, capture_output=True, check=False, env=env,
    )
    if new_sha.returncode != 0:
        raw: bytes = new_sha.stderr or b""
        stderr = raw.decode(errors="replace")
        raise RewriteError(phase="commit", detail=f"git commit-tree failed: {stderr}")
    sha = new_sha.stdout.decode().strip()
    _ = _run(["update-ref", "HEAD", sha], tgt)


def _assert_gpg_keys_available(manifest: Manifest) -> None:
    gpg_cfg = manifest.key.gpg
    if gpg_cfg is None or gpg_cfg.user_ids is None:
        return
    try:
        _gpg: str | None = find_gpg()
    except RuntimeError:
        _gpg = None
    if _gpg is None:
        msg = "gpg not found in PATH"
        raise RewriteError(phase="pre-check", detail=msg)
    # GPG preflight needs at least ONE secret key for verification (git-crypt unlock).
    # Other user_ids are public-key recipients -- they only need public keys available,
    # which git-crypt add-gpg-user validates at setup time.
    for uid in gpg_cfg.user_ids:
        r = subprocess.run(  # noqa: S603
            [_gpg, "--list-secret-keys", "--with-colons", uid],
            capture_output=True, check=False,
        )
        if r.returncode == 0 and r.stdout.strip():
            return
    uids = ", ".join(gpg_cfg.user_ids)
    raise RewriteError(
        phase="pre-check",
        detail=(
            f"No GPG secret key available for any configured user ID ({uids})."
            " Verification requires git-crypt unlock via GPG."
            " Import the secret key or use symmetric mode."
        ),
    )


def _assert_work_dir_safe(repo: Path, work_dir: Path) -> None:
    src = repo.resolve()
    tgt = work_dir.resolve()
    if src == tgt:
        raise RewriteError(
            phase="pre-check",
            detail=f"Work directory '{tgt}' is the same as the source repo.",
        )
    if src in tgt.parents:
        raise RewriteError(
            phase="pre-check",
            detail=f"Work directory '{tgt}' is inside the source repo '{src}'.",
        )
    if tgt in src.parents:
        raise RewriteError(
            phase="pre-check",
            detail=f"Work directory '{tgt}' is a parent of the source repo '{src}'.",
        )


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
