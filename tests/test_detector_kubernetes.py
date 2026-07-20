"""Tests for KubernetesDetector."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from git_recrypt.detector.base import Severity
from git_recrypt.detector.kubernetes import KubernetesDetector

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def helm_repo(tmp_path: Path) -> Path:
    (tmp_path / "Chart.yaml").write_text("apiVersion: v2\nname: myapp\nversion: 0.1.0")
    (tmp_path / "values.yaml").write_text("replicaCount: 1\nimage:\n  tag: latest\n")
    (tmp_path / "values-production.yaml").write_text("db:\n  password: prod-secret\n")
    templates = tmp_path / "templates"
    templates.mkdir()
    (templates / "deployment.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\n"
    )
    (templates / "secret.yaml").write_text(
        "apiVersion: v1\nkind: Secret\ntype: Opaque\nstringData:\n  api-key: abc123\n"
    )
    (templates / "configmap.yaml").write_text("apiVersion: v1\nkind: ConfigMap\n")
    return tmp_path


# --- matches_profile ---


def test_matches_profile_with_chart_yaml(tmp_path: Path) -> None:
    """Given Chart.yaml exists, matches_profile returns True."""
    (tmp_path / "Chart.yaml").write_text("apiVersion: v2\nname: myapp\nversion: 0.1.0")
    assert KubernetesDetector.matches_profile(tmp_path) is True


def test_matches_profile_with_kustomization(tmp_path: Path) -> None:
    """Given kustomization.yaml exists, matches_profile returns True."""
    (tmp_path / "kustomization.yaml").write_text("resources:\n  - deployment.yaml\n")
    assert KubernetesDetector.matches_profile(tmp_path) is True


def test_matches_profile_with_values_and_yamls(tmp_path: Path) -> None:
    """Given values.yaml and >5 YAML files in tree, matches_profile returns True."""
    (tmp_path / "values.yaml").write_text("key: value\n")
    for i in range(6):
        (tmp_path / f"file{i}.yaml").write_text(f"item: {i}\n")
    assert KubernetesDetector.matches_profile(tmp_path) is True


def test_matches_profile_false_for_generic(tmp_path: Path) -> None:
    """Given no Kubernetes indicators, matches_profile returns False."""
    (tmp_path / "README.md").write_text("# Generic repo\n")
    (tmp_path / "main.py").write_text("print('hello')\n")
    assert KubernetesDetector.matches_profile(tmp_path) is False


# --- detect ---


def test_detects_secret_yaml(helm_repo: Path) -> None:
    """Given a file with kind: Secret, detect returns CRITICAL severity."""
    detector = KubernetesDetector()
    result = detector.detect(helm_repo)

    critical = [s for s in result.secrets if s.severity == Severity.CRITICAL]
    assert len(critical) >= 1
    filepaths = [s.filepath for s in critical]
    assert any("secret.yaml" in fp for fp in filepaths)


def test_detects_values_production(helm_repo: Path) -> None:
    """Given values-production.yaml, detect returns HIGH severity."""
    detector = KubernetesDetector()
    result = detector.detect(helm_repo)

    high = [s for s in result.secrets if s.severity == Severity.HIGH]
    filepaths = [s.filepath for s in high]
    assert any("values-production.yaml" in fp for fp in filepaths)


def test_does_not_flag_deployment(helm_repo: Path) -> None:
    """Given a regular Deployment YAML, detect does not flag it."""
    detector = KubernetesDetector()
    result = detector.detect(helm_repo)

    flagged = [s for s in result.secrets if "deployment.yaml" in s.filepath]
    assert flagged == []


def test_suggested_patterns_correct(helm_repo: Path) -> None:
    """detect returns non-empty suggested_patterns covering secret paths."""
    detector = KubernetesDetector()
    result = detector.detect(helm_repo)

    assert result.profile == "kubernetes"
    assert len(result.suggested_patterns) > 0
    # At least one pattern covers the templates directory secrets
    all_patterns = " ".join(result.suggested_patterns)
    assert "yaml" in all_patterns or "secret" in all_patterns.lower()
