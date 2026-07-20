"""Encryption/decryption via git-crypt clean/smudge plumbing commands."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from pathlib import Path

from git_recrypt.errors import CryptoError

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
