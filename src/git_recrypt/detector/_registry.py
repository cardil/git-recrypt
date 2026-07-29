"""Registry: profile auto-detection and detector dispatch."""

from __future__ import annotations

from typing import TYPE_CHECKING

from git_recrypt.detector.etckeeper import EtcKeeperDetector
from git_recrypt.detector.generic import GenericDetector
from git_recrypt.detector.kubernetes import KubernetesDetector
from git_recrypt.errors import DetectionError

if TYPE_CHECKING:
    from pathlib import Path

    from git_recrypt.detector.base import BaseDetector, DetectionResult


def detect_profile(repo_path: Path) -> str:
    """Auto-detect the best profile for a repo.

    Order: etckeeper > kubernetes > generic (first match wins).
    Returns the profile name string.
    """
    if EtcKeeperDetector.matches_profile(repo_path):
        return "etckeeper"
    if KubernetesDetector.matches_profile(repo_path):
        return "kubernetes"
    return "generic"


def run_detection(repo_path: Path, profile: str | None = None) -> DetectionResult:
    """Run detection with explicit or auto-detected profile."""
    resolved = profile or detect_profile(repo_path)

    detectors: dict[str, BaseDetector] = {
        "generic": GenericDetector(),
        "etckeeper": EtcKeeperDetector(),
        "kubernetes": KubernetesDetector(),
    }

    detector = detectors.get(resolved)
    if detector is None:
        raise DetectionError(
            profile=resolved,
            detail=f"Unknown profile: {resolved}",
        )

    return detector.detect(repo_path)
