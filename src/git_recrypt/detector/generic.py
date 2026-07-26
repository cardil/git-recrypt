"""Generic secret detector -- fallback profile for arbitrary repos."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Final, override

import pathspec

from git_recrypt.detector.base import (
    BaseDetector,
    DetectedSecret,
    DetectionResult,
    Severity,
)

GENERIC_PATH_PATTERNS: Final[tuple[str, ...]] = (
    "*.key",
    "*.pem",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    ".env",
    ".env.*",
    "**/.env",
    "**/.env.*",
    "**/credentials*",
    "**/secrets.*",
    "**/*secret*.*",
    "**/.htpasswd",
    "**/*.gpg",
    "**/id_rsa",
    "**/id_ed25519",
    "**/id_ecdsa",
)

CONTENT_INDICATORS: Final[dict[str, re.Pattern[str]]] = {
    "private_key_header": re.compile(r"-----BEGIN.*PRIVATE KEY-----"),
    "password_field": re.compile(r"(?i)(password|passwd|pwd)\s*[=:]"),
    "api_key_field": re.compile(r"(?i)(api[_-]?key|apikey)\s*[=:]"),
    "token_field": re.compile(r"(?i)(token|auth[_-]?token)\s*[=:]"),
    "secret_field": re.compile(r"(?i)(secret|api[_-]?secret)\s*[=:]"),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
}

DEFAULT_EXCLUDES: Final[tuple[str, ...]] = (
    "*.pub",
    "**/known_hosts",
    "**/*.crt",
    "**/*.cert",
    "**/authorized_keys",
    "**/test/**",
    "**/tests/**",
    "**/testdata/**",
    "**/*example*",
    "**/*sample*",
    "**/*template*",
    "**/fixtures/**",
)

_READ_LIMIT: Final[int] = 8192


def _is_text(data: bytes) -> bool:
    """Return True if data looks like text (no null bytes in first 512 bytes)."""
    sample = data[:512]
    return b"\x00" not in sample


def _content_match_reason(content: str) -> str | None:
    """Return the first matching indicator name, or None."""
    for name, pattern in CONTENT_INDICATORS.items():
        if pattern.search(content):
            return name
    return None


class GenericDetector(BaseDetector):
    """Generic profile detector -- fallback for arbitrary repos."""

    @staticmethod
    @override
    def matches_profile(repo_path: Path) -> bool:
        """Always returns True -- generic is the fallback profile."""
        _ = repo_path
        return True

    @override
    def detect(self, repo_path: Path) -> DetectionResult:
        """Scan repo_path for common secret files and content patterns."""
        path_spec = pathspec.PathSpec.from_lines("gitignore", GENERIC_PATH_PATTERNS)
        exclude_spec = pathspec.PathSpec.from_lines("gitignore", DEFAULT_EXCLUDES)

        secrets: list[DetectedSecret] = []
        suggested_set: set[str] = set()

        for dirpath, dirnames, filenames in os.walk(repo_path):
            # Skip .git in-place so os.walk won't descend into it.
            dirnames[:] = [d for d in dirnames if d != ".git"]

            for filename in filenames:
                abs_path = Path(dirpath) / filename
                rel_str = str(abs_path.relative_to(repo_path))

                if exclude_spec.match_file(rel_str):
                    continue

                if path_spec.match_file(rel_str):
                    # Derive a simple glob pattern from the file extension or name.
                    suggested = _glob_for(filename)
                    suggested_set.add(suggested)
                    secrets.append(
                        DetectedSecret(
                            filepath=rel_str,
                            severity=Severity.CRITICAL,
                            reason="path matches known secret file pattern",
                            suggested_pattern=suggested,
                        )
                    )
                    continue

                # Skip non-regular files (symlinks, pipes, sockets, etc.)
                if abs_path.is_symlink() or not abs_path.is_file():
                    continue

                # Content sniffing for files that didn't match by path.
                try:
                    with abs_path.open("rb") as fh:
                        raw = fh.read(_READ_LIMIT)
                except OSError:
                    continue

                if not _is_text(raw):
                    continue

                text = raw.decode("utf-8", errors="replace")
                reason = _content_match_reason(text)
                if reason is None:
                    continue

                suggested = _glob_for(filename)
                suggested_set.add(suggested)
                secrets.append(
                    DetectedSecret(
                        filepath=rel_str,
                        severity=Severity.HIGH,
                        reason=f"content matches indicator: {reason}",
                        suggested_pattern=suggested,
                    )
                )

        return DetectionResult(
            profile="generic",
            confidence="high",
            secrets=tuple(secrets),
            suggested_patterns=tuple(sorted(suggested_set)),
            suggested_excludes=(),
        )


_BROAD_EXTENSIONS: frozenset[str] = frozenset(
    {".json", ".yaml", ".yml", ".xml", ".conf", ".cfg", ".ini", ".toml"}
)


def _glob_for(filename: str) -> str:
    dot = filename.rfind(".")
    if filename.startswith(".") and dot in {0, -1}:
        return filename
    if dot > 0:
        ext = filename[dot:]
        if ext in _BROAD_EXTENSIONS:
            return f"**/{filename}"
        return f"**/*{ext}"
    return f"**/{filename}"
