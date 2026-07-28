"""EtcKeeper secret detector."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Final, override

from pathspec import GitIgnoreSpec

from git_recrypt.detector.base import (
    BaseDetector,
    DetectedSecret,
    DetectionResult,
    Severity,
)

ETCKEEPER_CRITICAL: Final[tuple[str, ...]] = (
    "shadow",
    "shadow-",
    "gshadow",
    "gshadow-",
    "machine-id",
    "**/*.key",
    "**/*.key.pem",
    "**/*.private",
    "**/*.secret",
    "**/*privkey*",
    "**/secret.*",
    "**/.htpasswd",
    "ssh/ssh_host_*_key",
    "ssl/private/**",
    "pki/**/key/**",
    "pki/**/private/**",
    "pki/nssdb/**",
    "ups/upsd.users",
    "ups/upsmon.conf",
    "wireguard/*.conf",
    "openvpn/**/*.pem",
    "letsencrypt/accounts/**/private_key.json",
    "letsencrypt/keys/*.pem",
    "letsencrypt/live/**/privkey.pem",
    "letsencrypt/archive/**/privkey*.pem",
)

ETCKEEPER_SUSPICIOUS: Final[tuple[str, ...]] = (
    "mysql/**/*.cnf",
    "postgresql/**/*.conf",
    "postgres/**/*.conf",
    "ldap/**/*.conf",
    "samba/**/*.conf",
    "dovecot/**/*.conf",
    "postfix/**/*.cf",
    "postfix/sasl_passwd*",
    "sudoers",
    "sudoers.d/**",
    "environment",
    "default/**",
    "fstab",
    "NetworkManager/system-connections/*.nmconnection",
    "borgmatic.d/*.yaml",
    "sasl2/*.conf",
)

_PASSWORD_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(password|passwd|secret|credential)\s*[=:]\s*\S+",
)


def _build_spec(patterns: tuple[str, ...]) -> GitIgnoreSpec:
    return GitIgnoreSpec.from_lines(patterns)


_COMPILED_SPECS: dict[str, GitIgnoreSpec] = {}


def _get_spec(pattern: str) -> GitIgnoreSpec:
    if pattern not in _COMPILED_SPECS:
        _COMPILED_SPECS[pattern] = GitIgnoreSpec.from_lines([pattern])
    return _COMPILED_SPECS[pattern]


def _match_pattern(rel: str, patterns: tuple[str, ...]) -> str | None:
    """Return the first glob pattern from *patterns* that matches *rel*."""
    for pattern in patterns:
        if _get_spec(pattern).match_file(rel):
            return pattern
    return None


def _rel(repo_path: Path, file: Path) -> str:
    return file.relative_to(repo_path).as_posix()


def _has_password_content(file: Path) -> bool:
    try:
        with file.open("rb") as fh:
            raw = fh.read(8192)
    except OSError:
        return False
    text = raw.decode("utf-8", errors="replace")
    return bool(_PASSWORD_RE.search(text))


class EtcKeeperDetector(BaseDetector):
    """Detector for etckeeper-managed repos (repo root IS /etc)."""

    @staticmethod
    @override
    def matches_profile(repo_path: Path) -> bool:
        """Return True if repo looks like an etckeeper repo."""
        if (repo_path / ".etckeeper").exists():
            return True
        return (repo_path / "passwd").exists() and (repo_path / "shadow").exists()

    @override
    def detect(self, repo_path: Path) -> DetectionResult:
        """Run etckeeper detection on the given repo."""
        suspicious_spec = _build_spec(ETCKEEPER_SUSPICIOUS)

        secrets: list[DetectedSecret] = []
        suggested_set: set[str] = set()

        for dirpath, dirnames, filenames in os.walk(repo_path):
            dirnames[:] = [d for d in dirnames if d != ".git"]
            for filename in filenames:
                file = Path(dirpath) / filename
                if not file.is_file() or file.is_symlink():
                    continue
                rel = _rel(repo_path, file)

                critical_glob = _match_pattern(rel, ETCKEEPER_CRITICAL)
                if critical_glob is not None:
                    secrets.append(
                        DetectedSecret(
                            filepath=rel,
                            severity=Severity.CRITICAL,
                            reason="Critical etckeeper secret file",
                            suggested_pattern=critical_glob,
                        )
                    )
                    suggested_set.add(critical_glob)
                elif suspicious_spec.match_file(rel) and _has_password_content(file):
                    suspicious_glob = _match_pattern(rel, ETCKEEPER_SUSPICIOUS) or rel
                    secrets.append(
                        DetectedSecret(
                            filepath=rel,
                            severity=Severity.HIGH,
                            reason="Suspicious config file containing password field",
                            suggested_pattern=suspicious_glob,
                        )
                    )
                    suggested_set.add(suspicious_glob)

        return DetectionResult(
            profile="etckeeper",
            confidence="high",
            secrets=tuple(secrets),
            suggested_patterns=tuple(sorted(suggested_set)),
            suggested_excludes=(),
        )
