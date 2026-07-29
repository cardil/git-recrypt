"""Tests for git_recrypt.detector.generic.GenericDetector."""

from __future__ import annotations

from pathlib import Path

import pytest

from git_recrypt.detector.base import Severity
from git_recrypt.detector.generic import GenericDetector


@pytest.fixture
def generic_repo(tmp_path: Path) -> Path:
    """Create a directory with various files for generic detection."""
    _ = (tmp_path / "server.key").write_text("private key content")
    _ = (tmp_path / ".env").write_text("DATABASE_URL=postgres://user:pass@host/db")
    _ = (tmp_path / "config.yaml").write_text("password: secret123")
    _ = (tmp_path / "id_rsa.pub").write_text("ssh-rsa AAAA...")  # should be excluded
    _ = (tmp_path / "README.md").write_text("# Project")
    (tmp_path / "src").mkdir()
    _ = (tmp_path / "src" / "app.py").write_text("print('hello')")
    # Create .git dir to test it's skipped.
    (tmp_path / ".git").mkdir()
    _ = (tmp_path / ".git" / "config").write_text("[core]")
    return tmp_path


def test_matches_profile_always_true(tmp_path: Path) -> None:
    """matches_profile returns True for any path."""
    assert GenericDetector.matches_profile(tmp_path) is True
    assert GenericDetector.matches_profile(Path("/nonexistent/path")) is True


def test_detects_key_file(generic_repo: Path) -> None:
    """*.key files are detected as CRITICAL."""
    detector = GenericDetector()
    result = detector.detect(generic_repo)

    key_secrets = [s for s in result.secrets if s.filepath == "server.key"]
    assert len(key_secrets) == 1
    assert key_secrets[0].severity == Severity.CRITICAL


def test_detects_env_file(generic_repo: Path) -> None:
    """.env files are detected as CRITICAL."""
    detector = GenericDetector()
    result = detector.detect(generic_repo)

    env_secrets = [s for s in result.secrets if s.filepath == ".env"]
    assert len(env_secrets) == 1
    assert env_secrets[0].severity == Severity.CRITICAL


def test_content_sniffing_password(generic_repo: Path) -> None:
    """Files with 'password:' content are detected as HIGH via content sniffing."""
    detector = GenericDetector()
    result = detector.detect(generic_repo)

    yaml_secrets = [s for s in result.secrets if s.filepath == "config.yaml"]
    assert len(yaml_secrets) == 1
    assert yaml_secrets[0].severity == Severity.HIGH
    assert "password_field" in yaml_secrets[0].reason


def test_excludes_pub_files(generic_repo: Path) -> None:
    """*.pub files are excluded from detection."""
    detector = GenericDetector()
    result = detector.detect(generic_repo)

    pub_secrets = [s for s in result.secrets if "id_rsa.pub" in s.filepath]
    assert pub_secrets == []


def test_excludes_test_directories(tmp_path: Path) -> None:
    """Files under tests/ directories are excluded."""
    (tmp_path / "tests").mkdir()
    _ = (tmp_path / "tests" / "secret.key").write_text("key content")

    detector = GenericDetector()
    result = detector.detect(tmp_path)

    test_secrets = [s for s in result.secrets if "tests" in s.filepath]
    assert test_secrets == []


def test_skips_git_directory(generic_repo: Path) -> None:
    """.git/ directory contents are not scanned."""
    detector = GenericDetector()
    result = detector.detect(generic_repo)

    git_secrets = [s for s in result.secrets if s.filepath.startswith(".git")]
    assert git_secrets == []


def test_suggested_patterns_generated(generic_repo: Path) -> None:
    """Result contains suggested_patterns derived from matched files."""
    detector = GenericDetector()
    result = detector.detect(generic_repo)

    assert len(result.suggested_patterns) > 0
    assert result.profile == "generic"
    assert result.confidence == "high"


def test_empty_directory(tmp_path: Path) -> None:
    """Empty directory returns empty results."""
    detector = GenericDetector()
    result = detector.detect(tmp_path)

    assert result.secrets == ()
    assert result.suggested_patterns == ()
    assert result.profile == "generic"


def test_binary_files_skipped(tmp_path: Path) -> None:
    """Binary files are not scanned for content patterns."""
    binary_file = tmp_path / "data.bin"
    # Write binary content with null bytes and embedded 'password=' text.
    _ = binary_file.write_bytes(b"\x00\x01\x02password=secret\x00\xff\xfe")

    detector = GenericDetector()
    result = detector.detect(tmp_path)

    bin_secrets = [s for s in result.secrets if "data.bin" in s.filepath]
    assert bin_secrets == []
