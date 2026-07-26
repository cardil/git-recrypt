"""State persistence for git-recrypt in ~/.cache/git-recrypt/<repo-hash>/.

NOTE: Resume from interrupted rewrites is a planned feature, not yet implemented.
State is currently saved only after successful completion for post-rewrite
verification and debugging.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Final

DEBUG_ENV: Final = "GIT_RECRYPT_DEBUG"


@dataclass(frozen=True, slots=True)
class StateConfig:
    """Persisted configuration for a completed rewrite."""

    source_repo: str
    target_repo: str
    manifest_hash: str
    status: str
    timestamp: str


def state_dir_for_repo(source_repo: Path) -> Path:
    """Return the state directory for a given source repo path.

    Uses first 16 hex chars of SHA-256 of the resolved absolute path.
    """
    digest = hashlib.sha256(str(source_repo.resolve()).encode()).hexdigest()[:16]
    return Path.home() / ".cache" / "git-recrypt" / digest


def debug_dir_for_repo(source_repo: Path) -> Path:
    return state_dir_for_repo(source_repo) / "debug"


def is_debug() -> bool:
    return bool(os.environ.get(DEBUG_ENV))


def save_commit_map(state_dir: Path, mapping: dict[str, str]) -> None:
    """Write old->new SHA mapping to commit-map.json."""
    state_dir.mkdir(parents=True, exist_ok=True)
    state_dir.chmod(0o700)
    p = state_dir / "commit-map.json"
    _ = p.write_text(json.dumps(mapping, indent=2), encoding="utf-8")
    p.chmod(0o600)


def load_commit_map_from_state(state_dir: Path) -> dict[str, str]:
    """Load old->new SHA mapping from commit-map.json. Returns {} if missing."""
    path = state_dir / "commit-map.json"
    if not path.exists():
        return {}
    try:
        parsed: object = json.loads(path.read_text(encoding="utf-8"))  # pyright: ignore[reportAny]
    except json.JSONDecodeError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    result: dict[str, str] = {
        raw_k: raw_v
        for raw_k, raw_v in parsed.items()  # pyright: ignore[reportUnknownVariableType]
        if isinstance(raw_k, str) and isinstance(raw_v, str)
    }
    return result


def save_setup_commits(state_dir: Path, commits: list[str]) -> None:
    """Write setup commit SHAs to setup-commits.json."""
    state_dir.mkdir(parents=True, exist_ok=True)
    state_dir.chmod(0o700)
    p = state_dir / "setup-commits.json"
    _ = p.write_text(json.dumps(commits, indent=2), encoding="utf-8")
    p.chmod(0o600)


def load_setup_commits(state_dir: Path) -> list[str]:
    """Load setup commit SHAs from setup-commits.json. Returns [] if missing."""
    path = state_dir / "setup-commits.json"
    if not path.exists():
        return []
    try:
        parsed: object = json.loads(path.read_text(encoding="utf-8"))  # pyright: ignore[reportAny]
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [s for s in parsed if isinstance(s, str)]  # pyright: ignore[reportUnknownVariableType]


def save_config(state_dir: Path, config: StateConfig) -> None:
    """Write StateConfig to config.json."""
    state_dir.mkdir(parents=True, exist_ok=True)
    state_dir.chmod(0o700)
    data = {
        "source_repo": config.source_repo,
        "target_repo": config.target_repo,
        "manifest_hash": config.manifest_hash,
        "status": config.status,
        "timestamp": config.timestamp,
    }
    p = state_dir / "config.json"
    _ = p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    p.chmod(0o600)


def load_config(state_dir: Path) -> StateConfig | None:
    """Load StateConfig from config.json. Returns None if missing or invalid."""
    path = state_dir / "config.json"
    if not path.exists():
        return None
    try:
        parsed: object = json.loads(path.read_text(encoding="utf-8"))  # pyright: ignore[reportAny]
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    try:
        src = parsed["source_repo"]  # pyright: ignore[reportUnknownVariableType]
        tgt = parsed["target_repo"]  # pyright: ignore[reportUnknownVariableType]
        mh = parsed["manifest_hash"]  # pyright: ignore[reportUnknownVariableType]
        st = parsed["status"]  # pyright: ignore[reportUnknownVariableType]
        ts = parsed["timestamp"]  # pyright: ignore[reportUnknownVariableType]
        if not (
            isinstance(src, str)
            and isinstance(tgt, str)
            and isinstance(mh, str)
            and isinstance(st, str)
            and isinstance(ts, str)
        ):
            return None
        return StateConfig(
            source_repo=src,
            target_repo=tgt,
            manifest_hash=mh,
            status=st,
            timestamp=ts,
        )
    except KeyError:
        return None
