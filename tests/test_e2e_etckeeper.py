"""End-to-end tests: etckeeper-like repo rewrite and verification."""

from __future__ import annotations

import os
import secrets
import subprocess
from typing import TYPE_CHECKING, Final

import pytest

from git_recrypt.crypto import GITCRYPT_HEADER, is_encrypted
from git_recrypt.manifest import KeyConfig, Manifest, SymmetricKeyConfig
from git_recrypt.patterns import PatternMatcher
from git_recrypt.rewriter import HistoryRewriter, RewriteConfig, RewriteResult
from git_recrypt.verifier import RewriteVerifier, VerifyMode

if TYPE_CHECKING:
    from pathlib import Path

_GIT: Final = "/usr/bin/git"
_GIT_ENV: Final[dict[str, str]] = {
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.com",
}

_PATTERNS: Final[list[str]] = [
    "**/*.key",
    "**/*.key.pem",
    "**/*.private",
    "**/*privkey*",
    "**/.htpasswd",
    "**/secret.*",
    "gshadow",
    "gshadow-",
    "letsencrypt/accounts/**/private_key.json",
    "letsencrypt/keys/*.pem",
    "machine-id",
    "pki/nssdb/key4.db",
    "shadow",
    "shadow-",
    "ssh/ssh_host_*_key",
    "ups/upsd.users",
    "ups/upsmon.conf",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_git(args: list[str], cwd: Path) -> None:
    _ = subprocess.run(  # noqa: S603
        [_GIT, *args],
        check=True,
        capture_output=True,
        cwd=cwd,
        env={**os.environ, **_GIT_ENV},
    )


def _commit(cwd: Path, message: str) -> None:
    _run_git(["add", "-A"], cwd=cwd)
    _run_git(["commit", "-m", message], cwd=cwd)


def _write(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        _ = path.write_bytes(content)
    else:
        _ = path.write_text(content, encoding="utf-8")


def _git_show(repo: Path, ref: str, filepath: str) -> bytes:
    result = subprocess.run(  # noqa: S603
        [_GIT, "show", f"{ref}:{filepath}"],
        cwd=repo,
        capture_output=True,
        check=False,
    )
    return result.stdout


def _head_sha(repo: Path) -> str:
    result = subprocess.run(  # noqa: S603
        [_GIT, "rev-parse", "HEAD"],
        cwd=repo,
        capture_output=True,
        check=True,
    )
    return result.stdout.decode().strip()


def _make_manifest(key_file: Path) -> Manifest:
    return Manifest(
        version=1,
        key=KeyConfig(symmetric=SymmetricKeyConfig(key_file=str(key_file))),
        patterns=_PATTERNS,
        exclude=[],
        introduce_at="root",
    )


def _run_rewrite(
    repo: Path,
    key_file: Path,
    work_dir: Path,
) -> RewriteResult:
    manifest = _make_manifest(key_file)
    config = RewriteConfig(
        manifest=manifest,
        key_file=key_file,
        repo_path=repo,
        work_dir=work_dir,
    )
    return HistoryRewriter(config).run()


# ---------------------------------------------------------------------------
# Fixture: etckeeper_repo (15 commits)
# ---------------------------------------------------------------------------

_FAKE_KEY1 = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "fakekey1data\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)
_FAKE_KEY2 = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "fakekey2data\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)
_FAKE_PRIVKEY = (
    "-----BEGIN PRIVATE KEY-----\n"
    "{name}\n"
    "-----END PRIVATE KEY-----\n"
)
_FAKE_CERT = (
    "-----BEGIN CERTIFICATE-----\n"
    "{name}\n"
    "-----END CERTIFICATE-----\n"
)
_BORGMATIC_CFG = (
    "location:\n"
    "  source_directories:\n"
    "    - /home\n"
    "  repositories:\n"
    "    - /backup/borg\n"
)
_UPSMON_CONF = (
    "MONITOR ups@localhost 1 admin upspassword master\n"
    'SHUTDOWNCMD "/sbin/shutdown -h +0"\n'
)


@pytest.fixture
def etckeeper_repo(tmp_path: Path) -> Path:  # noqa: PLR0915
    """Build a plausible etckeeper-like repo with 15 commits."""
    repo = tmp_path / "etckeeper"
    repo.mkdir()

    _run_git(["init"], cwd=repo)
    _run_git(["config", "user.email", "test@example.com"], cwd=repo)
    _run_git(["config", "user.name", "Test"], cwd=repo)

    # Commit 1: Initial etckeeper commit
    _write(repo / "hostname", "baldur")
    _write(repo / "machine-id", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4")
    _write(
        repo / "passwd",
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
    )
    _write(repo / "shadow", "root:$6$salt$hash:19000:0:99999:7:::\n")
    _write(repo / "gshadow", "root:!::\n")
    _write(
        repo / "ssh" / "sshd_config",
        "Port 22\nPermitRootLogin no\nPasswordAuthentication no\n",
    )
    _write(repo / "ssh" / "ssh_host_ed25519_key", _FAKE_KEY1)
    _write(
        repo / "ssh" / "ssh_host_ed25519_key.pub",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakePublicKey1 root@baldur\n",
    )
    _commit(repo, "etckeeper init")

    # Commit 2: Package install -- PKI files
    _write(
        repo / "pki" / "ca-trust" / "extracted" / "pem" / "tls-ca-bundle.pem",
        "-----BEGIN CERTIFICATE-----\nfakecacert\n-----END CERTIFICATE-----\n",
    )
    _write(repo / "pki" / "nssdb" / "key4.db", secrets.token_bytes(64))
    _write(repo / "pki" / "nssdb" / "cert9.db", secrets.token_bytes(64))
    _commit(repo, "pkg install: pki")

    # Commit 3: Let's Encrypt setup
    _le_acct = (
        repo
        / "letsencrypt"
        / "accounts"
        / "acme-v02"
        / "directory"
        / "abc123"
        / "private_key.json"
    )
    _write(_le_acct, '{"kty":"RSA","n":"fake_modulus_value_here","e":"AQAB"}\n')
    _le_arc = repo / "letsencrypt" / "archive" / "example.com"
    _write(_le_arc / "privkey1.pem", _FAKE_PRIVKEY.format(name="fakeprivkey1"))
    _write(_le_arc / "cert1.pem", _FAKE_CERT.format(name="fakecert1"))
    _commit(repo, "letsencrypt: initial setup")

    # Commit 4: Add container secrets
    _ldap = repo / "containers" / "apps" / "ldap"
    _write(
        _ldap / "secret.env",
        "LDAP_ADMIN_PASSWORD=secret123\nLDAP_CONFIG_PASSWORD=config456\n",
    )
    _write(_ldap / "config.yml", "image: osixia/openldap:1.5.0\nports:\n  - 389:389\n")
    _commit(repo, "containers: add ldap")

    # Commit 5: Modify shadow (user added)
    _write(
        repo / "shadow",
        "root:$6$salt$hash:19000:0:99999:7:::\nalice:$6$salt2$hash2:19100:0:99999:7:::\n",
    )
    _write(repo / "gshadow", "root:!::\nalice:!::\n")
    _commit(repo, "shadow: add alice")

    # Commit 6: SSH key rotation
    _write(repo / "ssh" / "ssh_host_ed25519_key", _FAKE_KEY2)
    _write(
        repo / "ssh" / "ssh_host_ed25519_key.pub",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakePublicKey2 root@baldur\n",
    )
    _commit(repo, "ssh: rotate host keys")

    # Commit 7: Let's Encrypt renewal
    _write(_le_arc / "privkey2.pem", _FAKE_PRIVKEY.format(name="fakeprivkey2"))
    _write(_le_arc / "cert2.pem", _FAKE_CERT.format(name="fakecert2"))
    _commit(repo, "letsencrypt: renewal 1")

    # Commit 8: Add borgmatic backup config
    _write(repo / "borgmatic" / "config.yaml", _BORGMATIC_CFG)
    _commit(repo, "borgmatic: add config")

    # Commit 9: Add nginx private key
    _write(
        repo / "pki" / "nginx" / "private" / "wildcard.example.com.key",
        _FAKE_PRIVKEY.format(name="fakenginxkey"),
    )
    _commit(repo, "pki: add nginx wildcard key")

    # Commit 10: Modify hostname
    _write(repo / "hostname", "baldur.example.com")
    _commit(repo, "hostname: set fqdn")

    # Commit 11: Add UPS config
    _write(
        repo / "ups" / "upsd.users",
        "[admin]\n  password = upspassword\n  actions = SET\n  instcmds = ALL\n",
    )
    _write(repo / "ups" / "upsmon.conf", _UPSMON_CONF)
    _commit(repo, "ups: add config")

    # Commit 12: Second Let's Encrypt renewal
    _write(_le_arc / "privkey3.pem", _FAKE_PRIVKEY.format(name="fakeprivkey3"))
    _commit(repo, "letsencrypt: renewal 2")

    # Commit 13: Modify container secret
    _write(
        _ldap / "secret.env",
        "LDAP_ADMIN_PASSWORD=newpassword789\nLDAP_CONFIG_PASSWORD=newconfig012\n",
    )
    _commit(repo, "containers: rotate ldap password")

    # Commit 14: Add cockpit web cert
    _write(
        repo / "cockpit" / "ws-certs.d" / "0-self-signed.key",
        _FAKE_PRIVKEY.format(name="fakecockpitkey"),
    )
    _commit(repo, "cockpit: add self-signed key")

    # Commit 15: System update -- add another user
    _write(
        repo / "passwd",
        (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bob:x:1001:1001:Bob:/home/bob:/bin/bash\n"
        ),
    )
    _commit(repo, "system update: add bob")

    return repo


# ---------------------------------------------------------------------------
# test_etckeeper_rewrite_and_verify
# ---------------------------------------------------------------------------


def test_etckeeper_rewrite_and_verify(
    etckeeper_repo: Path,
    sample_key_file: Path,
    tmp_path: Path,
) -> None:
    # Given: etckeeper_repo with 15 commits and the manifest patterns above
    work_dir = tmp_path / "work"

    # When: run HistoryRewriter
    result = _run_rewrite(etckeeper_repo, sample_key_file, work_dir)
    rewritten = result.work_dir

    # Then: 15 commits rewritten
    assert result.commits_rewritten == 15
    assert result.files_encrypted > 0

    # .gitattributes present in every commit of the target
    all_commits = subprocess.run(  # noqa: S603
        [_GIT, "rev-list", "--all", "--reverse"],
        cwd=rewritten,
        capture_output=True,
        check=True,
    ).stdout.decode().strip().splitlines()
    # Skip the 2 setup commits (initial + gitattributes) -- check only replayed ones
    replayed_commits = all_commits[2:]
    for sha in replayed_commits:
        ga = subprocess.run(  # noqa: S603
            [_GIT, "show", f"{sha}:.gitattributes"],
            cwd=rewritten,
            capture_output=True,
            check=False,
        )
        assert ga.returncode == 0, f".gitattributes missing in commit {sha}"

    # Source repo NOT mutated -- HEAD SHA is stable
    sha_src = _head_sha(etckeeper_repo)
    assert sha_src == _head_sha(etckeeper_repo)

    # Encrypted files at HEAD
    encrypted_at_head = [
        "shadow",
        "gshadow",
        "machine-id",
        "ssh/ssh_host_ed25519_key",
        "pki/nssdb/key4.db",
        "letsencrypt/accounts/acme-v02/directory/abc123/private_key.json",
        "letsencrypt/archive/example.com/privkey1.pem",
        "letsencrypt/archive/example.com/privkey2.pem",
        "letsencrypt/archive/example.com/privkey3.pem",
        "containers/apps/ldap/secret.env",
        "pki/nginx/private/wildcard.example.com.key",
        "ups/upsd.users",
        "ups/upsmon.conf",
        "cockpit/ws-certs.d/0-self-signed.key",
    ]
    for fp in encrypted_at_head:
        content = _git_show(rewritten, "HEAD", fp)
        assert content.startswith(GITCRYPT_HEADER), f"{fp} should be encrypted at HEAD"

    # Non-encrypted files at HEAD
    not_encrypted_at_head = [
        "hostname",
        "passwd",
        "ssh/ssh_host_ed25519_key.pub",
        "ssh/sshd_config",
        "pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "pki/nssdb/cert9.db",
        "letsencrypt/archive/example.com/cert1.pem",
        "letsencrypt/archive/example.com/cert2.pem",
        "borgmatic/config.yaml",
        "containers/apps/ldap/config.yml",
    ]
    for fp in not_encrypted_at_head:
        content = _git_show(rewritten, "HEAD", fp)
        assert not is_encrypted(content), f"{fp} should NOT be encrypted at HEAD"

    # Run verifier
    matcher = PatternMatcher(
        include_patterns=tuple(_PATTERNS),
        exclude_patterns=(),
    )
    verifier = RewriteVerifier(
        original_path=etckeeper_repo,
        rewritten_path=rewritten,
        key_file=sample_key_file,
        matcher=matcher,
        mode=VerifyMode.FULL,
        rewrite_commits=result.commits_rewritten,
        rewrite_files_encrypted=result.files_encrypted,
    )
    verify_result = verifier.verify()
    assert verify_result.passed is True


# ---------------------------------------------------------------------------
# test_etckeeper_source_not_mutated
# ---------------------------------------------------------------------------


def test_etckeeper_source_not_mutated(
    etckeeper_repo: Path,
    sample_key_file: Path,
    tmp_path: Path,
) -> None:
    # Given: record source HEAD SHA before rewrite
    sha_before = _head_sha(etckeeper_repo)

    # When: run rewrite
    _ = _run_rewrite(etckeeper_repo, sample_key_file, tmp_path / "work")

    # Then: source HEAD SHA unchanged
    sha_after = _head_sha(etckeeper_repo)
    assert sha_before == sha_after

    # No new commits in source (commit count unchanged)
    count_result = subprocess.run(  # noqa: S603
        [_GIT, "rev-list", "--count", "--all"],
        cwd=etckeeper_repo,
        capture_output=True,
        check=True,
    )
    assert int(count_result.stdout.decode().strip()) == 15


# ---------------------------------------------------------------------------
# test_etckeeper_binary_files_handled
# ---------------------------------------------------------------------------


def test_etckeeper_binary_files_handled(
    etckeeper_repo: Path,
    sample_key_file: Path,
    tmp_path: Path,
) -> None:
    # Given: rewritten repo
    result = _run_rewrite(etckeeper_repo, sample_key_file, tmp_path / "work")
    rewritten = result.work_dir

    # Then: pki/nssdb/key4.db (binary, in patterns) is encrypted at HEAD
    key4_content = _git_show(rewritten, "HEAD", "pki/nssdb/key4.db")
    assert key4_content.startswith(GITCRYPT_HEADER), (
        "pki/nssdb/key4.db (binary) should be encrypted"
    )

    # pki/nssdb/cert9.db (binary, NOT in patterns) is NOT encrypted
    cert9_content = _git_show(rewritten, "HEAD", "pki/nssdb/cert9.db")
    assert not is_encrypted(cert9_content), (
        "pki/nssdb/cert9.db should NOT be encrypted (not in patterns)"
    )


# ---------------------------------------------------------------------------
# test_etckeeper_modified_secrets_stay_encrypted
# ---------------------------------------------------------------------------


def test_etckeeper_modified_secrets_stay_encrypted(
    etckeeper_repo: Path,
    sample_key_file: Path,
    tmp_path: Path,
) -> None:
    # Given: rewritten repo
    result = _run_rewrite(etckeeper_repo, sample_key_file, tmp_path / "work")
    rewritten = result.work_dir

    # Then: shadow is encrypted in ALL commits where it exists.
    # Map original commits to rewritten commits via rev-list (both oldest-first).
    orig_commits = subprocess.run(  # noqa: S603
        [_GIT, "rev-list", "--all", "--reverse"],
        cwd=etckeeper_repo,
        capture_output=True,
        check=True,
    ).stdout.decode().strip().splitlines()

    rew_commits = subprocess.run(  # noqa: S603
        [_GIT, "rev-list", "--all", "--reverse"],
        cwd=rewritten,
        capture_output=True,
        check=True,
    ).stdout.decode().strip().splitlines()

    # Rewritten has 2 setup commits prepended; replayed commits start at index 2.
    rew_replayed = rew_commits[2:]
    assert len(rew_replayed) == len(orig_commits), (
        f"Expected {len(orig_commits)} replayed commits, got {len(rew_replayed)}"
    )

    # Find which original commits contain shadow.
    shadow_orig_indices: list[int] = []
    for idx, sha in enumerate(orig_commits):
        ls = subprocess.run(  # noqa: S603
            [_GIT, "ls-tree", sha, "shadow"],
            cwd=etckeeper_repo,
            capture_output=True,
            check=False,
        )
        if ls.stdout.strip():
            shadow_orig_indices.append(idx)

    # shadow is introduced in commit 1 (index 0) and modified in commit 5 (index 4).
    assert 0 in shadow_orig_indices, "shadow should exist from commit 1"
    assert 4 in shadow_orig_indices, "shadow should exist in commit 5"

    # Verify shadow is encrypted in every rewritten commit where it exists.
    for idx in shadow_orig_indices:
        rew_sha = rew_replayed[idx]
        content = _git_show(rewritten, rew_sha, "shadow")
        assert content.startswith(GITCRYPT_HEADER), (
            f"shadow not encrypted in rewritten commit {rew_sha} (orig index {idx})"
        )
