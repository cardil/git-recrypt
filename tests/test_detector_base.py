"""Tests for git_recrypt.detector.base types and abstract interface."""

from __future__ import annotations

import pytest

from git_recrypt.detector.base import (
    BaseDetector,
    DetectedSecret,
    DetectionResult,
    Severity,
)


def test_severity_enum_values() -> None:
    assert Severity.CRITICAL == "critical"
    assert Severity.HIGH == "high"
    assert Severity.MEDIUM == "medium"
    assert Severity.LOW == "low"


def test_detected_secret_frozen() -> None:
    secret = DetectedSecret(
        filepath="/etc/shadow",
        severity=Severity.CRITICAL,
        reason="Shadow password file",
        suggested_pattern="etc/shadow",
    )
    with pytest.raises(AttributeError):
        secret.filepath = "/etc/passwd"  # type: ignore[misc]  # pyright: ignore[reportAttributeAccessIssue]


def test_detected_secret_hashable() -> None:
    s1 = DetectedSecret(
        filepath="/etc/shadow",
        severity=Severity.CRITICAL,
        reason="Shadow password file",
        suggested_pattern="etc/shadow",
    )
    s2 = DetectedSecret(
        filepath="/etc/ssl/private/key.pem",
        severity=Severity.HIGH,
        reason="Private key",
        suggested_pattern="*.pem",
    )
    result = {s1, s2}
    assert len(result) == 2


def test_detection_result_frozen() -> None:
    result = DetectionResult(
        profile="generic",
        confidence="high",
        secrets=(),
        suggested_patterns=(),
        suggested_excludes=(),
    )
    with pytest.raises(AttributeError):
        result.profile = "etckeeper"  # type: ignore[misc]  # pyright: ignore[reportAttributeAccessIssue]


def test_base_detector_not_instantiable() -> None:
    with pytest.raises(TypeError):
        _ = BaseDetector()  # type: ignore[abstract]  # pyright: ignore[reportAbstractUsage]


def test_detected_secret_equal_instances_deduplicate() -> None:
    s1 = DetectedSecret(
        filepath="/etc/shadow",
        severity=Severity.CRITICAL,
        reason="Shadow password file",
        suggested_pattern="etc/shadow",
    )
    s2 = DetectedSecret(
        filepath="/etc/shadow",
        severity=Severity.CRITICAL,
        reason="Shadow password file",
        suggested_pattern="etc/shadow",
    )
    assert s1 == s2
    assert hash(s1) == hash(s2)
    assert len({s1, s2}) == 1


def test_detection_result_creation() -> None:
    secret = DetectedSecret(
        filepath="/etc/shadow",
        severity=Severity.CRITICAL,
        reason="Shadow password file",
        suggested_pattern="etc/shadow",
    )
    result = DetectionResult(
        profile="etckeeper",
        confidence="high",
        secrets=(secret,),
        suggested_patterns=("etc/shadow",),
        suggested_excludes=("etc/shadow",),
    )
    assert result.profile == "etckeeper"
    assert result.confidence == "high"
    assert len(result.secrets) == 1
    assert result.secrets[0].severity == Severity.CRITICAL
    assert result.suggested_patterns == ("etc/shadow",)
    assert result.suggested_excludes == ("etc/shadow",)
