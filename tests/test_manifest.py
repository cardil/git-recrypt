"""Tests for git_recrypt.manifest module."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from git_recrypt.errors import ManifestError
from git_recrypt.manifest import Manifest, load_manifest, save_manifest

if TYPE_CHECKING:
    from pathlib import Path


def _write_yaml(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "manifest.yaml"
    p.write_text(content, encoding="utf-8")
    return p


def test_valid_manifest_symmetric(tmp_path: Path) -> None:
    # Given a valid manifest YAML with symmetric key
    yaml_content = """\
version: 1
key:
  symmetric:
    key_file: generate
patterns:
  - "*.key"
"""
    path = _write_yaml(tmp_path, yaml_content)

    # When loading the manifest
    manifest = load_manifest(path)

    # Then it parses correctly
    assert manifest.version == 1
    assert manifest.key.symmetric is not None
    assert manifest.key.symmetric.key_file == "generate"
    assert manifest.key.gpg is None
    assert manifest.patterns == ["*.key"]


def test_valid_manifest_gpg(tmp_path: Path) -> None:
    # Given a valid manifest YAML with GPG user_ids
    yaml_content = """\
version: 1
key:
  gpg:
    user_ids:
      - alice@example.com
      - bob@example.com
patterns:
  - "secrets/**"
  - ".env"
"""
    path = _write_yaml(tmp_path, yaml_content)

    # When loading the manifest
    manifest = load_manifest(path)

    # Then it parses correctly
    assert manifest.key.gpg is not None
    assert manifest.key.gpg.user_ids == ["alice@example.com", "bob@example.com"]
    assert manifest.key.symmetric is None
    assert manifest.patterns == ["secrets/**", ".env"]


def test_missing_version(tmp_path: Path) -> None:
    # Given a manifest YAML without version
    yaml_content = """\
key:
  symmetric:
    key_file: generate
patterns:
  - "*.key"
"""
    path = _write_yaml(tmp_path, yaml_content)

    # When loading the manifest
    # Then ManifestError is raised
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_wrong_version(tmp_path: Path) -> None:
    # Given a manifest YAML with version: 2
    yaml_content = """\
version: 2
key:
  symmetric:
    key_file: generate
patterns:
  - "*.key"
"""
    path = _write_yaml(tmp_path, yaml_content)

    # When loading the manifest
    # Then ManifestError is raised
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_both_symmetric_and_gpg(tmp_path: Path) -> None:
    # Given a manifest with both symmetric and gpg keys
    yaml_content = """\
version: 1
key:
  symmetric:
    key_file: generate
  gpg:
    user_ids:
      - alice@example.com
patterns:
  - "*.key"
"""
    path = _write_yaml(tmp_path, yaml_content)

    # When loading the manifest
    # Then ManifestError is raised
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_neither_symmetric_nor_gpg(tmp_path: Path) -> None:
    # Given a manifest with neither symmetric nor gpg key
    yaml_content = """\
version: 1
key: {}
patterns:
  - "*.key"
"""
    path = _write_yaml(tmp_path, yaml_content)

    # When loading the manifest
    # Then ManifestError is raised
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_empty_patterns(tmp_path: Path) -> None:
    # Given a manifest with an empty patterns list
    yaml_content = """\
version: 1
key:
  symmetric:
    key_file: generate
patterns: []
"""
    path = _write_yaml(tmp_path, yaml_content)

    # When loading the manifest
    # Then ManifestError is raised
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_introduce_at_root(tmp_path: Path) -> None:
    # Given a manifest with introduce_at: root
    yaml_content = """\
version: 1
key:
  symmetric:
    key_file: generate
patterns:
  - "*.key"
introduce_at: root
"""
    path = _write_yaml(tmp_path, yaml_content)

    # When loading the manifest
    manifest = load_manifest(path)

    # Then introduce_at is accepted
    assert manifest.introduce_at == "root"


def test_introduce_at_first_match(tmp_path: Path) -> None:
    # Given a manifest with introduce_at: first-match
    yaml_content = """\
version: 1
key:
  symmetric:
    key_file: generate
patterns:
  - "*.key"
introduce_at: first-match
"""
    path = _write_yaml(tmp_path, yaml_content)

    # When loading the manifest
    manifest = load_manifest(path)

    # Then introduce_at is accepted
    assert manifest.introduce_at == "first-match"


def test_introduce_at_valid_sha(tmp_path: Path) -> None:
    # Given a manifest with a valid 40-char hex SHA as introduce_at
    sha = "a" * 40
    yaml_content = f"""\
version: 1
key:
  symmetric:
    key_file: generate
patterns:
  - "*.key"
introduce_at: "{sha}"
"""
    path = _write_yaml(tmp_path, yaml_content)

    # When loading the manifest
    manifest = load_manifest(path)

    # Then introduce_at is accepted
    assert manifest.introduce_at == sha


def test_introduce_at_invalid(tmp_path: Path) -> None:
    # Given a manifest with an invalid introduce_at value
    yaml_content = """\
version: 1
key:
  symmetric:
    key_file: generate
patterns:
  - "*.key"
introduce_at: invalid
"""
    path = _write_yaml(tmp_path, yaml_content)

    # When loading the manifest
    # Then ManifestError is raised
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_defaults_applied(tmp_path: Path) -> None:
    # Given a minimal valid manifest (no branches or exclude specified)
    yaml_content = """\
version: 1
key:
  symmetric:
    key_file: generate
patterns:
  - "*.key"
"""
    path = _write_yaml(tmp_path, yaml_content)

    # When loading the manifest
    manifest = load_manifest(path)

    # Then defaults are applied
    assert manifest.branches == ["HEAD"]
    assert manifest.exclude == []
    assert manifest.introduce_at == "root"


def test_save_load_roundtrip(tmp_path: Path) -> None:
    # Given a manifest object
    original = Manifest.model_validate(
        {
            "version": 1,
            "key": {
                "symmetric": {"key_file": "generate", "export_to": "./git-crypt.key"}
            },
            "patterns": ["*.key", "secrets/**"],
            "branches": ["main", "develop"],
            "exclude": ["*.pub"],
        }
    )
    save_path = tmp_path / "roundtrip.yaml"

    # When saving then loading
    save_manifest(original, save_path)
    loaded = load_manifest(save_path)

    # Then the loaded manifest is equivalent
    assert loaded.version == original.version
    assert loaded.patterns == original.patterns
    assert loaded.branches == original.branches
    assert loaded.exclude == original.exclude
    assert loaded.key.symmetric is not None
    assert original.key.symmetric is not None
    assert loaded.key.symmetric.key_file == original.key.symmetric.key_file


def test_file_not_found(tmp_path: Path) -> None:
    # Given a path to a non-existent file
    missing = tmp_path / "nonexistent.yaml"

    # When loading the manifest
    # Then ManifestError is raised with the path
    with pytest.raises(ManifestError) as exc_info:
        load_manifest(missing)

    assert str(missing) in str(exc_info.value)


def test_invalid_yaml(tmp_path: Path) -> None:
    # Given a file with invalid YAML content
    path = tmp_path / "bad.yaml"
    path.write_text("key: [unclosed bracket\n", encoding="utf-8")

    # When loading the manifest
    # Then ManifestError is raised
    with pytest.raises(ManifestError):
        load_manifest(path)
