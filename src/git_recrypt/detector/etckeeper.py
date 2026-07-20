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
    "gshadow",
    "ssh/ssh_host_*_key",
    "ssl/private/**",
    "wireguard/*.conf",
    "wireguard/*.key",
    "openvpn/**/*.key",
    "openvpn/**/*.pem",
    "letsencrypt/live/**/privkey.pem",
    "letsencrypt/archive/**/privkey*.pem",
)

ETCKEEPER_SUSPICIOUS: Final[tuple[str, ...]] = (
    "mysql/**/*.cnf",
    "postgresql/**/*.conf",
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
)

# Matches lines like: password = ..., passwd=..., secret:..., etc.
_PASSWORD_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(password|passwd|secret|credential)\s*[=:]\s*\S+",
)


def _build_spec(patterns: tuple[str, ...]) -> GitIgnoreSpec:
    return GitIgnoreSpec.from_lines(patterns)


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
        critical_spec = _build_spec(ETCKEEPER_CRITICAL)
        suspicious_spec = _build_spec(ETCKEEPER_SUSPICIOUS)

        secrets: list[DetectedSecret] = []
        suggested: list[str] = []

        for file in repo_path.rglob("*"):
            if not file.is_file():
                continue
            rel = _rel(repo_path, file)

            if critical_spec.match_file(rel):
                secrets.append(
                    DetectedSecret(
                        filepath=rel,
                        severity=Severity.CRITICAL,
                        reason="Critical etckeeper secret file",
                        suggested_pattern=rel,
                    )
                )
                suggested.append(rel)
            elif suspicious_spec.match_file(rel) and _has_password_content(file):
                secrets.append(
                    DetectedSecret(
                        filepath=rel,
                        severity=Severity.HIGH,
                        reason="Suspicious config file containing password field",
                        suggested_pattern=rel,
                    )
                )

        return DetectionResult(
            profile="etckeeper",
            confidence="high",
            secrets=tuple(secrets),
            suggested_patterns=tuple(dict.fromkeys(suggested)),
            suggested_excludes=(),
        )
