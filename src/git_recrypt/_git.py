"""Low-level git plumbing helpers."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING, Final

from git_recrypt._shellout import GIT as _GIT
from git_recrypt._shellout import find_gpg
from git_recrypt.errors import CryptoError

if TYPE_CHECKING:
    from pathlib import Path


_GIT_CRYPT: Final = "git-crypt"


def _get_gpg() -> str:
    """Lazy GPG binary resolution -- only called in GPG-specific functions."""
    return find_gpg()


def get_commit_list(repo_path: Path) -> list[str]:
    """Return list of commit SHAs in rev-list order (newest first).

    Args:
        repo_path: Path to the git repository.

    Returns:
        List of full SHA strings.
    """
    result = subprocess.run(  # noqa: S603
        [_GIT, "rev-list", "--all"],
        cwd=repo_path,
        capture_output=True,
        check=True,
    )
    output: str = result.stdout.decode().strip()
    if not output:
        return []
    return output.splitlines()


_SKIP_MODES: Final[frozenset[str]] = frozenset({"160000", "120000"})


def get_file_list(repo_path: Path, sha: str) -> list[str]:
    """Return list of regular file paths in a commit tree.

    Excludes submodules (160000) and symlinks (120000).

    Args:
        repo_path: Path to the git repository.
        sha: Commit SHA to inspect.

    Returns:
        List of file paths relative to repo root.
    """
    result = subprocess.run(  # noqa: S603
        [_GIT, "ls-tree", "-rz", sha],
        cwd=repo_path,
        capture_output=True,
        check=True,
    )
    if not result.stdout:
        return []
    files: list[str] = []
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        meta_raw, raw_filepath = record.split(b"\t", 1)
        mode = meta_raw.split(b" ", 1)[0].decode()
        if mode not in _SKIP_MODES:
            files.append(raw_filepath.decode(errors="surrogateescape"))
    return files


def load_commit_map(rewritten_path: Path) -> dict[str, str]:
    """Load commit map from state dir or legacy filter-repo location."""
    from pathlib import Path as _Path  # noqa: PLC0415

    from git_recrypt._state import (  # noqa: PLC0415
        load_commit_map_from_state,
        load_config,
    )

    cache_base = _Path.home() / ".cache" / "git-recrypt"
    if cache_base.is_dir():
        for entry in cache_base.iterdir():
            if not entry.is_dir():
                continue
            cfg = load_config(entry)
            if cfg is not None and cfg.target_repo == str(rewritten_path.resolve()):
                return load_commit_map_from_state(entry)

    map_file = rewritten_path / ".git" / "filter-repo" / "commit-map"
    if not map_file.exists():
        return {}
    mapping: dict[str, str] = {}
    for line in map_file.read_text(encoding="utf-8").splitlines():
        if line.startswith("old") or not line.strip():
            continue
        parts = line.split()
        if len(parts) == 2:  # noqa: PLR2004
            mapping[parts[0]] = parts[1]
    return mapping


def get_file_content(repo_path: Path, sha: str, filepath: str) -> bytes:
    """Return raw blob bytes for a file at a given commit.

    Args:
        repo_path: Path to the git repository.
        sha: Commit SHA.
        filepath: File path relative to repo root.

    Returns:
        Raw bytes of the file blob.
    """
    result = subprocess.run(  # noqa: S603
        [_GIT, "show", f"{sha}:{filepath}"],
        cwd=repo_path,
        capture_output=True,
        check=True,
    )
    return result.stdout


def git_checkout(repo_path: Path, sha: str) -> None:
    """Run git checkout <sha> in the given repository.

    Args:
        repo_path: Path to the git repository.
        sha: Commit SHA to check out.

    Raises:
        CryptoError: If git checkout fails.
    """
    result = subprocess.run(  # noqa: S603
        [_GIT, "checkout", sha],
        cwd=repo_path,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        stderr_str = result.stderr.decode(errors="replace") if result.stderr else None
        raise CryptoError(detail=f"git checkout {sha} failed", stderr=stderr_str)


def run_git_crypt_status(repo_path: Path) -> list[tuple[str, bool]]:
    """Run git-crypt status, return [(filepath, is_encrypted), ...].

    Args:
        repo_path: Path to the git repository.

    Returns:
        List of (filepath, is_encrypted) tuples.

    Raises:
        CryptoError: If git-crypt status fails.
    """
    result = subprocess.run(  # noqa: S603
        [_GIT_CRYPT, "status"],
        cwd=repo_path,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        stderr_str = result.stderr.decode(errors="replace") if result.stderr else None
        raise CryptoError(detail="git-crypt status failed", stderr=stderr_str)

    entries: list[tuple[str, bool]] = []
    for raw_line in result.stdout.decode(errors="replace").splitlines():
        stripped = raw_line.strip()
        if stripped.startswith("encrypted:"):
            filepath = stripped[len("encrypted:") :].strip()
            entries.append((filepath, True))
        elif stripped.startswith("not encrypted:"):
            filepath = stripped[len("not encrypted:") :].strip()
            entries.append((filepath, False))
    return entries


def run_git_crypt_unlock(
    repo_path: Path,
    key_file: Path | None = None,
    env: dict[str, str] | None = None,
) -> None:
    """Run git-crypt unlock. key_file=None for GPG mode.

    Args:
        repo_path: Path to the git repository.
        key_file: Path to symmetric key file, or None for GPG mode.
        env: Optional environment variables override (e.g. GNUPGHOME).

    Raises:
        CryptoError: If git-crypt unlock fails.
    """
    import os  # noqa: PLC0415

    cmd = [_GIT_CRYPT, "unlock"]
    if key_file is not None:
        cmd.append(str(key_file))
    run_env = {**os.environ, **(env or {})}
    result = subprocess.run(  # noqa: S603
        cmd,
        cwd=repo_path,
        capture_output=True,
        check=False,
        env=run_env,
    )
    if result.returncode != 0:
        stderr_str = result.stderr.decode(errors="replace") if result.stderr else None
        raise CryptoError(detail="git-crypt unlock failed", stderr=stderr_str)


def run_git_crypt_lock(repo_path: Path) -> None:
    """Run git-crypt lock (no --force).

    Args:
        repo_path: Path to the git repository.

    Raises:
        CryptoError: If git-crypt lock fails.
    """
    result = subprocess.run(  # noqa: S603
        [_GIT_CRYPT, "lock"],
        cwd=repo_path,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        stderr_str = result.stderr.decode(errors="replace") if result.stderr else None
        raise CryptoError(detail="git-crypt lock failed", stderr=stderr_str)


def export_gpg_secret_key(user_id: str, output_path: Path) -> None:
    """Export GPG secret key for user_id to output_path (armored).

    Args:
        user_id: GPG user ID (email or fingerprint).
        output_path: Destination file path for the exported key.

    Raises:
        CryptoError: If gpg export fails.
    """
    result = subprocess.run(  # noqa: S603
        [_get_gpg(), "--export-secret-keys", "--armor", user_id],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        stderr_str = result.stderr.decode(errors="replace") if result.stderr else None
        raise CryptoError(
            detail=f"gpg --export-secret-keys failed for {user_id}",
            stderr=stderr_str,
        )
    _ = output_path.write_bytes(result.stdout)


def import_gpg_key(key_path: Path, gnupghome: Path) -> None:
    """Import a GPG key into an isolated GNUPGHOME.

    Args:
        key_path: Path to the armored key file to import.
        gnupghome: Path to the isolated GNUPGHOME directory.

    Raises:
        CryptoError: If gpg import fails.
    """
    result = subprocess.run(  # noqa: S603
        [_get_gpg(), "--homedir", str(gnupghome), "--import", str(key_path)],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        stderr_str = result.stderr.decode(errors="replace") if result.stderr else None
        raise CryptoError(detail="gpg --import failed", stderr=stderr_str)
