"""Abstract base for secret detection profiles and result types."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


class Severity(StrEnum):
    """Severity level for detected secrets."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True, slots=True)
class DetectedSecret:
    """A single detected secret file."""

    filepath: str
    severity: Severity
    reason: str
    suggested_pattern: str


@dataclass(frozen=True, slots=True)
class DetectionResult:
    """Result of running secret detection on a repo."""

    profile: str
    confidence: str  # "high", "medium", "low"
    secrets: tuple[DetectedSecret, ...]
    suggested_patterns: tuple[str, ...]
    suggested_excludes: tuple[str, ...]


class BaseDetector(ABC):
    """Abstract base for secret detection profiles."""

    @abstractmethod
    def detect(self, repo_path: Path) -> DetectionResult:
        """Run detection on the given repo and return results."""
        ...

    @staticmethod
    @abstractmethod
    def matches_profile(repo_path: Path) -> bool:
        """Return True if this detector is appropriate for the given repo."""
        ...
