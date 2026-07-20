"""Kubernetes secret detector."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final, override

from git_recrypt.detector.base import (
    BaseDetector,
    DetectedSecret,
    DetectionResult,
    Severity,
)

K8S_SECRET_PATTERNS: Final[dict[str, re.Pattern[str]]] = {
    "kind_secret": re.compile(r"^\s*kind:\s*Secret\s*$", re.MULTILINE),
    "type_opaque": re.compile(
        r"^\s*type:\s*(Opaque|kubernetes\.io/.*)\s*$", re.MULTILINE
    ),
    "string_data": re.compile(r"^\s*stringData:\s*$", re.MULTILINE),
}

K8S_PATH_PATTERNS: Final[tuple[str, ...]] = (
    "values.yaml",
    "values-*.yaml",
    "**/*.env",
    "**/secrets/**",
    "**/secret/**",
)

_YAML_GLOB = "**/*.yaml"
_PROFILE_YAML_THRESHOLD = 5


def _is_secret_yaml(content: str) -> bool:
    return bool(K8S_SECRET_PATTERNS["kind_secret"].search(content))


def _matches_path_pattern(rel: str) -> bool:
    p = Path(rel)
    name = p.name
    parts = p.parts
    if name == "values.yaml":
        return True
    if name.startswith("values-") and name.endswith(".yaml"):
        return True
    if name.endswith(".env"):
        return True
    return bool("secrets" in parts or "secret" in parts)


def _secret_yaml_pattern(rel: str) -> str:
    parent = Path(rel).parent
    if parent == Path():
        return "*.yaml"
    return str(parent / "*.yaml")


def _path_match_pattern(rel: str) -> str:
    p = Path(rel)
    if p.suffix in {".yaml", ".yml"}:
        if p.name.startswith("values-"):
            return "values-*.yaml"
        return p.name
    if p.suffix == ".env":
        return "**/*.env"
    return rel


class KubernetesDetector(BaseDetector):
    """Detector for Kubernetes manifest repos."""

    @staticmethod
    @override
    def matches_profile(repo_path: Path) -> bool:
        """Return True if repo looks like a Kubernetes repo."""
        if (repo_path / "Chart.yaml").exists():
            return True
        if (repo_path / "kustomization.yaml").exists():
            return True
        if (repo_path / "values.yaml").exists():
            yaml_count = sum(1 for _ in repo_path.glob(_YAML_GLOB))
            if yaml_count > _PROFILE_YAML_THRESHOLD:
                return True
        return False

    @override
    def detect(self, repo_path: Path) -> DetectionResult:
        """Run Kubernetes detection on the given repo."""
        secrets: list[DetectedSecret] = []
        pattern_set: set[str] = set()

        for path in repo_path.rglob("*"):
            if not path.is_file():
                continue
            rel = str(path.relative_to(repo_path))
            if Path(rel).parts and Path(rel).parts[0] == ".git":
                continue

            if path.suffix in {".yaml", ".yml"}:
                try:
                    content = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _is_secret_yaml(content):
                    pattern = _secret_yaml_pattern(rel)
                    secrets.append(
                        DetectedSecret(
                            filepath=rel,
                            severity=Severity.CRITICAL,
                            reason="Kubernetes Secret manifest (kind: Secret)",
                            suggested_pattern=pattern,
                        )
                    )
                    pattern_set.add(pattern)
                    continue

            if _matches_path_pattern(rel):
                pattern = _path_match_pattern(rel)
                secrets.append(
                    DetectedSecret(
                        filepath=rel,
                        severity=Severity.HIGH,
                        reason="Kubernetes values/secrets path pattern match",
                        suggested_pattern=pattern,
                    )
                )
                pattern_set.add(pattern)

        return DetectionResult(
            profile="kubernetes",
            confidence="high" if secrets else "low",
            secrets=tuple(secrets),
            suggested_patterns=tuple(sorted(pattern_set)),
            suggested_excludes=(),
        )
