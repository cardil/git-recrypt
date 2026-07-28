"""Tests for git_recrypt.cli module."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from git_recrypt.cli import app

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()

_MINIMAL_MANIFEST = """\
version: 1
key:
  symmetric:
    key_file: /tmp/test.key
patterns:
  - "*.key"
  - secrets/**
exclude:
  - "*.pub"
"""


def test_help_shows_commands() -> None:
    # Given the CLI app
    # When invoking --help
    result = runner.invoke(app, ["--help"])

    # Then exit code is 0 and all 5 commands are listed
    assert result.exit_code == 0
    output = result.output
    assert "detect" in output
    assert "init" in output
    assert "run" in output
    assert "verify" in output
    assert "dry-run" in output


def test_detect_with_fixture_repo(tmp_path: Path) -> None:
    # Given a temporary directory (empty repo-like dir)
    # When invoking detect --repo <tmp_path>
    result = runner.invoke(app, ["detect", "--repo", str(tmp_path)])

    # Then exit code is 0 (detection runs without error on empty dir)
    assert result.exit_code == 0


def test_dry_run_with_manifest(tmp_path: Path) -> None:
    # Given a valid manifest file
    manifest_path = tmp_path / "git-recrypt.yaml"
    _ = manifest_path.write_text(_MINIMAL_MANIFEST, encoding="utf-8")

    # When invoking dry-run --manifest <path>
    result = runner.invoke(app, ["dry-run", "--manifest", str(manifest_path)])

    # Then exit code is 0 and output contains pattern info
    assert result.exit_code == 0
    assert "*.key" in result.output
    assert "secrets/**" in result.output
    assert "*.pub" in result.output


def test_run_missing_manifest(tmp_path: Path) -> None:
    # Given a non-existent manifest path
    missing = tmp_path / "nonexistent.yaml"

    # When invoking run --manifest <missing>
    result = runner.invoke(app, ["run", "--manifest", str(missing)])

    # Then exit code is non-zero
    assert result.exit_code != 0


def test_verify_missing_args() -> None:
    # Given no arguments
    # When invoking verify with no positional args
    result = runner.invoke(app, ["verify"])

    # Then exit code is non-zero (missing required arguments)
    assert result.exit_code != 0


def test_detect_unknown_profile(tmp_path: Path) -> None:
    # Given an unknown profile name
    # When invoking detect --profile unknown --repo <tmp_path>
    result = runner.invoke(
        app, ["detect", "--profile", "unknown_profile_xyz", "--repo", str(tmp_path)]
    )

    # Then exit code is non-zero and error is reported
    assert result.exit_code != 0


_GENERATE_KEY_MANIFEST = """\
version: 1
key:
  symmetric:
    key_file: generate
    export_to: {export_to}
patterns:
  - "*.key"
"""

_GPG_USER_IDS_MANIFEST = """\
version: 1
key:
  gpg:
    user_ids:
      - alice@example.com
patterns:
  - "*.key"
"""


def test_run_generate_symmetric_key(tmp_path: Path) -> None:
    # Given -- manifest with key_file: generate, mocked resolve_key_from_manifest
    export_to = tmp_path / "out.key"
    manifest_path = tmp_path / "git-recrypt.yaml"
    _ = manifest_path.write_text(
        _GENERATE_KEY_MANIFEST.format(export_to=str(export_to)), encoding="utf-8"
    )
    fake_key = tmp_path / "fake.key"
    _ = fake_key.write_bytes(b"\x00GITCRYPT\x00" + b"\x00" * 138)

    fake_result = MagicMock()
    fake_result.commits_rewritten = 0
    fake_result.files_encrypted = 0
    fake_result.elapsed_seconds = 0.1
    fake_result.work_dir = tmp_path / "work"

    key_patch = patch(
        "git_recrypt.cli.resolve_key_from_manifest",
        return_value=(fake_key, "Generated symmetric key"),
    )
    rewriter_patch = patch("git_recrypt.cli.HistoryRewriter")
    with key_patch as mock_resolve, rewriter_patch as mock_rewriter:
        mock_rewriter.return_value.run.return_value = fake_result  # pyright: ignore[reportAny]
        result = runner.invoke(
            app,
            ["run", "--manifest", str(manifest_path), "--skip-verify", "--force"],
        )

    mock_resolve.assert_called_once()
    assert result.exit_code == 0


def test_run_gpg_user_ids(tmp_path: Path) -> None:
    # Given -- manifest with gpg.user_ids, mocked resolve_key_from_manifest
    manifest_path = tmp_path / "git-recrypt.yaml"
    _ = manifest_path.write_text(_GPG_USER_IDS_MANIFEST, encoding="utf-8")
    fake_key = tmp_path / "gpg-exported.key"
    _ = fake_key.write_bytes(b"\x00GITCRYPT\x00" + b"\x00" * 138)

    fake_result = MagicMock()
    fake_result.commits_rewritten = 0
    fake_result.files_encrypted = 0
    fake_result.elapsed_seconds = 0.1
    fake_result.work_dir = tmp_path / "work"

    key_patch = patch(
        "git_recrypt.cli.resolve_key_from_manifest",
        return_value=(fake_key, None),
    )
    rewriter_patch = patch("git_recrypt.cli.HistoryRewriter")
    with key_patch as mock_resolve, rewriter_patch as mock_rewriter:
        mock_rewriter.return_value.run.return_value = fake_result  # pyright: ignore[reportAny]
        result = runner.invoke(
            app,
            ["run", "--manifest", str(manifest_path), "--skip-verify", "--force"],
        )

    mock_resolve.assert_called_once()
    assert result.exit_code == 0
