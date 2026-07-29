"""Tests for git_recrypt.manifest module."""

from __future__ import annotations

from pathlib import Path

import pytest

from git_recrypt.errors import ManifestError
from git_recrypt.manifest import (
    Manifest,
    load_manifest,
    resolve_repo_path,
    save_manifest,
)
from git_recrypt.patterns import generate_gitattributes


def _write_yaml(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "manifest.yaml"
    _ = p.write_text(content, encoding="utf-8")
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
        _ = load_manifest(path)


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
        _ = load_manifest(path)


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
        _ = load_manifest(path)


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
        _ = load_manifest(path)


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
        _ = load_manifest(path)


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
    # Given a manifest with introduce_at: first-match (not yet implemented)
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
    # Then ManifestError is raised with "not yet implemented" message
    with pytest.raises(ManifestError, match="not yet implemented"):
        _ = load_manifest(path)


def test_introduce_at_valid_sha(tmp_path: Path) -> None:
    # Given a manifest with a valid 40-char hex SHA as introduce_at
    # (SHA-based introduction is not yet implemented)
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
    # Then ManifestError is raised with "not yet implemented" message
    with pytest.raises(ManifestError, match="not yet implemented"):
        _ = load_manifest(path)


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
        _ = load_manifest(path)


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
            "branches": ["main"],
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
        _ = load_manifest(missing)

    assert str(missing) in str(exc_info.value)


def test_invalid_yaml(tmp_path: Path) -> None:
    # Given a file with invalid YAML content
    path = tmp_path / "bad.yaml"
    _ = path.write_text("key: [unclosed bracket\n", encoding="utf-8")

    # When loading the manifest
    # Then ManifestError is raised
    with pytest.raises(ManifestError):
        _ = load_manifest(path)


def _make_manifest(**overrides: object) -> Manifest:
    base: dict[str, object] = {
        "version": 1,
        "key": {"symmetric": {"key_file": "generate"}},
        "patterns": ["*.key"],
    }
    base.update(overrides)
    return Manifest.model_validate(base)


def test_repo_default_is_dot_slash() -> None:
    m = _make_manifest()
    assert m.repo == "./"


def test_resolve_repo_default_uses_manifest_parent(tmp_path: Path) -> None:
    # Given a manifest at /some/dir/git-recrypt.yaml with default repo: ./
    manifest_path = tmp_path / "git-recrypt.yaml"
    m = _make_manifest()

    # When resolving repo path without CLI override
    result = resolve_repo_path(m, manifest_path)

    # Then it resolves to the manifest's parent directory
    assert result == tmp_path.resolve()


def test_resolve_repo_relative_to_manifest(tmp_path: Path) -> None:
    # Given a manifest with repo: ../other-repo
    subdir = tmp_path / "configs"
    subdir.mkdir()
    manifest_path = subdir / "git-recrypt.yaml"
    m = _make_manifest(repo="../other-repo")

    # When resolving repo path
    result = resolve_repo_path(m, manifest_path)

    # Then it resolves relative to manifest parent, not pwd
    assert result == (tmp_path / "other-repo").resolve()


def test_resolve_repo_absolute_in_manifest(tmp_path: Path) -> None:
    # Given a manifest with an absolute repo path
    abs_repo = str(tmp_path / "my-repo")
    manifest_path = tmp_path / "git-recrypt.yaml"
    m = _make_manifest(repo=abs_repo)

    # When resolving repo path
    result = resolve_repo_path(m, manifest_path)

    # Then the absolute path is used as-is
    assert result == Path(abs_repo)


def test_resolve_repo_cli_overrides_manifest(tmp_path: Path) -> None:
    # Given a manifest with repo: ./some-dir
    manifest_path = tmp_path / "git-recrypt.yaml"
    m = _make_manifest(repo="./some-dir")

    # When resolving with a CLI --repo override
    cli_repo = str(tmp_path / "cli-target")
    result = resolve_repo_path(m, manifest_path, cli_repo=cli_repo)

    # Then CLI wins over manifest
    assert result == Path(cli_repo).resolve()


def test_repo_field_in_yaml_roundtrip(tmp_path: Path) -> None:
    # Given a manifest with a custom repo field
    original = _make_manifest(repo="/etc")
    save_path = tmp_path / "roundtrip.yaml"

    # When saving then loading
    save_manifest(original, save_path)
    loaded = load_manifest(save_path)

    # Then repo field is preserved
    assert loaded.repo == "/etc"


def test_exclude_dir_style_rejected() -> None:
    # Given an exclude pattern ending with '/'
    # When generating gitattributes with a dir-style exclude pattern
    # Then ValueError is raised
    with pytest.raises(ValueError, match="ends with '/'"):
        _ = generate_gitattributes(["*.key"], exclude=["private/"])


def test_include_dir_style_rejected() -> None:
    # Given an include pattern ending with '/'
    # When generating gitattributes with a dir-style include pattern
    # Then ValueError is raised
    with pytest.raises(ValueError, match="ends with '/'"):
        _ = generate_gitattributes(["secrets/"])
