"""EtcKeeper secret detector."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final, override

from pathspec import GitIgnoreSpec

from git_recrypt.detector.base import (
    BaseDetector,
    DetectedSecret,
    DetectionResult,
    Severity,
)

if TYPE_CHECKING:
    from pathlib import Path

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

# Matches lines like: password = ..., passwd=..., secret:..., etc.
_PASSWORD_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(password|passwd|secret|credential)\s*[=:]\s*\S+",
)


def _build_spec(patterns: tuple[str, ...]) -> GitIgnoreSpec:
    return GitIgnoreSpec.from_lines(patterns)


def _match_pattern(rel: str, patterns: tuple[str, ...]) -> str | None:
    """Return the first glob pattern from *patterns* that matches *rel*."""
    for pattern in patterns:
        spec = GitIgnoreSpec.from_lines([pattern])
        if spec.match_file(rel):
            return pattern
    return None


def _rel(repo_path: Path, file: Path) -> str:
    return file.relative_to(repo_path).as_posix()


def _has_password_content(file: Path) -> bool:
    try:
        text = file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
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

        for file in repo_path.rglob("*"):
            if not file.is_file():
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

        return DetectionResult(
            profile="etckeeper",
            confidence="high",
            secrets=tuple(secrets),
            suggested_patterns=tuple(sorted(suggested_set)),
            suggested_excludes=(),
        )
