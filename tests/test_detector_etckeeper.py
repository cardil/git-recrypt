"""Tests for git_recrypt.detector.etckeeper."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from git_recrypt.detector.base import Severity
from git_recrypt.detector.etckeeper import EtcKeeperDetector


@pytest.fixture
def etckeeper_repo(tmp_path: Path) -> Path:
    (tmp_path / ".etckeeper").write_text("")
    (tmp_path / "passwd").write_text("root:x:0:0::/root:/bin/bash")
    (tmp_path / "shadow").write_text("root:$6$hash:19000:0:99999:7:::")
    (tmp_path / "gshadow").write_text("root:::root")
    ssh_dir = tmp_path / "ssh"
    ssh_dir.mkdir()
    (ssh_dir / "ssh_host_ed25519_key").write_text("-----BEGIN OPENSSH PRIVATE KEY-----")
    (ssh_dir / "ssh_host_ed25519_key.pub").write_text("ssh-ed25519 AAAA...")
    mysql_dir = tmp_path / "mysql"
    mysql_dir.mkdir()
    (mysql_dir / "debian.cnf").write_text("[client]\npassword = secret123\n")
    (tmp_path / "hostname").write_text("myserver")
    return tmp_path


def test_matches_profile_with_etckeeper_file(tmp_path: Path) -> None:
    (tmp_path / ".etckeeper").write_text("")
    assert EtcKeeperDetector.matches_profile(tmp_path) is True


def test_matches_profile_with_passwd_shadow(tmp_path: Path) -> None:
    (tmp_path / "passwd").write_text("root:x:0:0::/root:/bin/bash")
    (tmp_path / "shadow").write_text("root:$6$hash:19000:0:99999:7:::")
    assert EtcKeeperDetector.matches_profile(tmp_path) is True


def test_matches_profile_false_for_generic(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# project")
    assert EtcKeeperDetector.matches_profile(tmp_path) is False


def test_detects_shadow_as_critical(etckeeper_repo: Path) -> None:
    result = EtcKeeperDetector().detect(etckeeper_repo)
    critical_paths = {
        s.filepath for s in result.secrets if s.severity == Severity.CRITICAL
    }
    assert "shadow" in critical_paths


def test_detects_ssh_host_key_as_critical(etckeeper_repo: Path) -> None:
    result = EtcKeeperDetector().detect(etckeeper_repo)
    critical_paths = {
        s.filepath for s in result.secrets if s.severity == Severity.CRITICAL
    }
    assert "ssh/ssh_host_ed25519_key" in critical_paths


def test_detects_mysql_with_password(etckeeper_repo: Path) -> None:
    result = EtcKeeperDetector().detect(etckeeper_repo)
    high_paths = {s.filepath for s in result.secrets if s.severity == Severity.HIGH}
    assert "mysql/debian.cnf" in high_paths


def test_suggested_patterns_correct(etckeeper_repo: Path) -> None:
    result = EtcKeeperDetector().detect(etckeeper_repo)
    patterns = set(result.suggested_patterns)
    assert "shadow" in patterns
    assert "ssh/ssh_host_ed25519_key" in patterns
