"""Encryption/decryption via git-crypt clean/smudge plumbing commands."""

from __future__ import annotations

import getpass
import os
import secrets
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final

from git_recrypt._shellout import find_gpg
from git_recrypt.errors import CryptoError

if TYPE_CHECKING:
    from git_recrypt.manifest import KeyConfig

GITCRYPT_HEADER: Final = b"\x00GITCRYPT\x00"
_GIT_CRYPT_BIN: Final = "git-crypt"


@dataclass(frozen=True, slots=True)
class CryptoEngine:
    """Wraps git-crypt clean/smudge for file encryption/decryption."""

    key_file: Path

    def __post_init__(self) -> None:
        """Validate key file exists and git-crypt is available."""
        if not self.key_file.exists():
            raise CryptoError(detail=f"Key file not found: {self.key_file}")
        if shutil.which(_GIT_CRYPT_BIN) is None:
            raise CryptoError(detail="git-crypt binary not found in PATH")

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext via git-crypt clean --key-file.

        Returns encrypted bytes. If already encrypted (starts with GITCRYPT header),
        returns data unchanged (idempotent).
        Raises CryptoError on subprocess failure.
        """
        if is_encrypted(plaintext):
            return plaintext
        return self._run_git_crypt("clean", plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext via git-crypt smudge --key-file.

        Raises CryptoError on subprocess failure.
        """
        return self._run_git_crypt("smudge", ciphertext)

    def verify_roundtrip(self, plaintext: bytes) -> bool:
        """Encrypt then decrypt, verify result matches original."""
        encrypted = self.encrypt(plaintext)
        decrypted = self.decrypt(encrypted)
        return decrypted == plaintext

    def _run_git_crypt(self, subcommand: str, input_data: bytes) -> bytes:
        """Run git-crypt clean/smudge as a subprocess pipe."""
        result = subprocess.run(  # noqa: S603
            [_GIT_CRYPT_BIN, subcommand, "--key-file", str(self.key_file)],
            input=input_data,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            stderr_bytes: bytes = result.stderr
            stderr_str = stderr_bytes.decode(errors="replace") if stderr_bytes else None
            raise CryptoError(
                detail=f"git-crypt {subcommand} failed",
                stderr=stderr_str,
            )
        return result.stdout


def is_encrypted(data: bytes) -> bool:
    """Check if data starts with the GITCRYPT magic header."""
    return data[:10] == GITCRYPT_HEADER


def _run_cmd(
    args: list[str], cwd: Path | None = None
) -> subprocess.CompletedProcess[bytes]:
    """Run a command, returning CompletedProcess. Raises CryptoError on failure."""
    result = subprocess.run(  # noqa: S603
        args,
        capture_output=True,
        check=False,
        cwd=cwd,
    )
    if result.returncode != 0:
        stderr_bytes: bytes = result.stderr
        stderr_str = stderr_bytes.decode(errors="replace") if stderr_bytes else None
        raise CryptoError(
            detail=f"Command failed: {' '.join(args)}",
            stderr=stderr_str,
        )
    return result


def generate_symmetric_key(export_to: Path) -> Path:
    """Generate a symmetric git-crypt key file via `git-crypt keygen`.

    Shells out to `git-crypt keygen <export_to>`.
    Raises CryptoError if the command fails or the file is missing/empty.
    Returns the path to the generated key file.
    """
    if shutil.which(_GIT_CRYPT_BIN) is None:
        raise CryptoError(detail="git-crypt binary not found in PATH")
    _ = _run_cmd([_GIT_CRYPT_BIN, "keygen", str(export_to)])
    if not export_to.exists() or export_to.stat().st_size == 0:
        raise CryptoError(detail=f"Key file not created or empty: {export_to}")
    return export_to


def init_gpg_repo(repo_path: Path, user_ids: list[str]) -> None:
    """Run git-crypt init + add-gpg-user on a repo. Mutates the repo."""
    if shutil.which(_GIT_CRYPT_BIN) is None:
        raise CryptoError(detail="git-crypt binary not found in PATH")

    git_crypt_dir = repo_path / ".git" / "git-crypt"
    if not git_crypt_dir.is_dir():
        _ = _run_cmd([_GIT_CRYPT_BIN, "init"], cwd=repo_path)

    for uid in user_ids:
        _ = _run_cmd([_GIT_CRYPT_BIN, "add-gpg-user", uid], cwd=repo_path)


def export_gpg_key(repo_path: Path) -> Path:
    """Export the symmetric key from a git-crypt-initialized repo (read-only)."""
    if shutil.which(_GIT_CRYPT_BIN) is None:
        raise CryptoError(detail="git-crypt binary not found in PATH")

    git_crypt_dir = repo_path / ".git" / "git-crypt"
    if not git_crypt_dir.is_dir():
        raise CryptoError(
            detail=(
                f"git-crypt not initialized in {repo_path}. Run git-crypt init first."
            ),
        )

    tmp_fd, tmp_path_str = tempfile.mkstemp(prefix="gcri-gpg-key-", suffix=".key")
    os.close(tmp_fd)
    exported = Path(tmp_path_str)
    _ = _run_cmd([_GIT_CRYPT_BIN, "export-key", str(exported)], cwd=repo_path)

    if not exported.exists() or exported.stat().st_size == 0:
        raise CryptoError(detail=f"Exported key file missing or empty: {exported}")
    return exported


def setup_gpg_repo(repo_path: Path, user_ids: list[str]) -> Path:
    """Init git-crypt, add GPG users, and export key. Mutates the repo."""
    init_gpg_repo(repo_path, user_ids)
    return export_gpg_key(repo_path)


_GPG_ALGO_MAP: Final[dict[str, tuple[str, str, str, str]]] = {
    # algorithm -> (primary_type, primary_extra, sub_type, sub_extra)
    "ed25519": ("EDDSA", "Key-Curve: ed25519", "ECDH", "Subkey-Curve: cv25519"),
    "rsa4096": ("RSA", "Key-Length: 4096", "RSA", "Subkey-Length: 4096"),
    "rsa2048": ("RSA", "Key-Length: 2048", "RSA", "Subkey-Length: 2048"),
}



def generate_gpg_key(
    name: str,
    email: str,
    algorithm: str,
    expire: str,
    passphrase_mode: str,
) -> str:
    """Generate a GPG key pair using `gpg --batch --gen-key`.

    For passphrase_mode "random": generates a random passphrase and prints it.
    For passphrase_mode "provided": prompts the user via getpass.

    Returns the user ID string "<name> <email>" of the generated key.
    Raises CryptoError on failure.
    """
    try:
        gpg_bin: str | None = find_gpg()
    except RuntimeError:
        gpg_bin = None
    if gpg_bin is None:
        raise CryptoError(detail="gpg binary not found in PATH")

    if passphrase_mode == "random":  # noqa: S105
        passphrase = secrets.token_urlsafe(24)
        print(f"Generated GPG passphrase (save this): {passphrase}")  # noqa: T201
    else:
        passphrase = getpass.getpass(
            f"Enter passphrase for GPG key ({name} <{email}>): "
        )

    algo_info = _GPG_ALGO_MAP.get(algorithm)
    if algo_info is not None:
        primary_type, primary_extra, sub_type, sub_extra = algo_info
    else:
        primary_type, primary_extra, sub_type, sub_extra = algorithm, "", algorithm, ""

    primary_extra_line = f"{primary_extra}\n" if primary_extra else ""
    sub_extra_line = f"{sub_extra}\n" if sub_extra else ""
    batch_input = (
        f"%echo Generating GPG key\n"
        f"Key-Type: {primary_type}\n"
        f"{primary_extra_line}"
        f"Key-Usage: sign\n"
        f"Subkey-Type: {sub_type}\n"
        f"{sub_extra_line}"
        f"Subkey-Usage: encrypt\n"
        f"Name-Real: {name}\n"
        f"Name-Email: {email}\n"
        f"Expire-Date: {expire}\n"
        f"Passphrase: {passphrase}\n"
        f"%commit\n"
        f"%echo done\n"
    )

    result = subprocess.run(  # noqa: S603
        [gpg_bin, "--batch", "--gen-key"],
        input=batch_input.encode(),
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        stderr_bytes: bytes = result.stderr
        stderr_str = stderr_bytes.decode(errors="replace") if stderr_bytes else None
        raise CryptoError(detail="gpg key generation failed", stderr=stderr_str)

    return f"{name} <{email}>"


def resolve_key_from_manifest(
    key_config: KeyConfig,
    _repo_path: Path,
) -> tuple[Path, str | None]:
    """Resolve key file from manifest KeyConfig.

    Returns (key_path, message) where message describes what was done (or None).
    Raises CryptoError on failure.
    The _repo_path parameter is kept for API compatibility but is no longer used
    (GPG key setup now uses a fresh temp repo instead of cloning the source).
    """
    if key_config.symmetric is not None:
        kf = key_config.symmetric.key_file
        if kf == "generate":
            export_to = Path(key_config.symmetric.export_to)
            key_path = generate_symmetric_key(export_to)
            return key_path, f"Generated symmetric key: {key_path}"
        return Path(kf), None

    gpg_cfg = key_config.gpg
    if gpg_cfg is None:
        raise CryptoError(detail="No key configuration found in manifest")

    if gpg_cfg.generate is not None:
        raise CryptoError(
            detail=(
                "'key.gpg.generate' is not yet implemented."
                " Use 'key.gpg.user_ids' with pre-existing GPG keys instead."
            )
        )
    if gpg_cfg.user_ids is not None:
        return Path("/dev/null"), None
    raise CryptoError(
        detail="GPG config must specify either 'user_ids' or 'generate'"
    )
