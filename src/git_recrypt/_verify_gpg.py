"""GPG isolation helpers for verifier phase 2."""

from __future__ import annotations

import contextlib
import shutil
import tempfile
from pathlib import Path

from git_recrypt._git import (
    export_gpg_secret_key,
    import_gpg_key,
    run_git_crypt_lock,
    run_git_crypt_unlock,
)
from git_recrypt.crypto import GITCRYPT_HEADER, is_encrypted
from git_recrypt.errors import CryptoError


def test_gpg_roundtrip(  # noqa: PLR0911
    rewritten_path: Path,
    encrypted_paths: list[Path],
    user_id: str,
) -> str | None:
    """Test lock/unlock roundtrip for a single GPG user ID in isolation.

    Creates a temp GNUPGHOME, exports only that user's key, imports it,
    then runs unlock/verify/lock.

    Returns an error string on failure, or None on success.
    """
    tmp_dir = tempfile.mkdtemp(prefix="gcri-gpg-")
    gnupghome = Path(tmp_dir)
    key_file = gnupghome / "exported.asc"
    try:
        try:
            export_gpg_secret_key(user_id, key_file)
        except CryptoError as exc:
            return f"Phase 2 GPG export failed for {user_id}: {exc}"

        try:
            import_gpg_key(key_file, gnupghome)
        except CryptoError as exc:
            return f"Phase 2 GPG import failed for {user_id}: {exc}"

        env = {"GNUPGHOME": str(gnupghome)}
        try:
            run_git_crypt_unlock(rewritten_path, key_file=None, env=env)
        except CryptoError as exc:
            return f"Phase 2 unlock failed for {user_id}: {exc}"

        for fp in encrypted_paths:
            content = fp.read_bytes()
            if content[:10] == GITCRYPT_HEADER:
                with contextlib.suppress(CryptoError):
                    run_git_crypt_lock(rewritten_path)
                return (
                    f"Phase 2: after unlock, {fp.name} still has GITCRYPT header"
                    f" (identity: {user_id})"
                )

        try:
            run_git_crypt_lock(rewritten_path)
        except CryptoError as exc:
            return f"Phase 2 lock failed for {user_id}: {exc}"

        for fp in encrypted_paths:
            content = fp.read_bytes()
            if not is_encrypted(content):
                return (
                    f"Phase 2: after lock, {fp.name} missing GITCRYPT header"
                    f" (identity: {user_id})"
                )

        return None
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
