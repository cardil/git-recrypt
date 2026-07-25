"""Tests for git_recrypt.wizard and git_recrypt._wizard_steps modules."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from git_recrypt.wizard import run_wizard

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SHA = "a" * 40


def _make_question(return_value: object) -> MagicMock:
    """Return a mock questionary.Question whose .ask() returns return_value."""
    q = MagicMock()
    q.configure_mock(**{"ask.return_value": return_value})
    return q


def _minimal_manifest_yaml(patterns: list[str] | None = None) -> str:
    pats = patterns or ["secrets/**"]
    pat_lines = "\n".join(f'  - "{p}"' for p in pats)
    return f"""\
version: 1
key:
  symmetric:
    key_file: generate
patterns:
{pat_lines}
"""


def _select_default(
    _message: str, choices: list[str], default: str = "", **_kw: object
) -> MagicMock:
    """Return a mock Question that returns the default value."""
    return _make_question(default or choices[0])


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_detection() -> MagicMock:
    """A DetectionResult mock with generic profile and one suggested pattern."""
    from git_recrypt.detector.base import (  # noqa: PLC0415
        DetectedSecret,
        DetectionResult,
        Severity,
    )

    secret = DetectedSecret(
        filepath="secrets/api.key",
        severity=Severity.HIGH,
        reason="API key file",
        suggested_pattern="secrets/**",
    )
    return MagicMock(
        spec=DetectionResult,
        profile="generic",
        confidence="high",
        secrets=(secret,),
        suggested_patterns=("secrets/**",),
        suggested_excludes=(),
    )


def _iter_select(answers: list[str]) -> object:
    """Return a side_effect function that pops from answers in order."""
    it = iter(answers)

    def _fn(*_a: object, **_kw: object) -> MagicMock:
        return _make_question(next(it))

    return _fn


def _iter_text(answers: list[str]) -> object:
    """Return a side_effect function that pops from answers in order."""
    it = iter(answers)

    def _fn(*_a: object, **_kw: object) -> MagicMock:
        return _make_question(next(it))

    return _fn


def _iter_path(answers: list[str]) -> object:
    """Return a side_effect function that pops from answers in order."""
    it = iter(answers)

    def _fn(*_a: object, **_kw: object) -> MagicMock:
        return _make_question(next(it))

    return _fn


# ---------------------------------------------------------------------------
# Full wizard flow -- all defaults
# ---------------------------------------------------------------------------
# Call order for symmetric+generate:
#   select: profile, key_type, sym_mode, passphrase_mode, introduce_at, branches
#   text:   custom_pattern_stop, exclusion_stop


def test_run_wizard_all_defaults(tmp_path: Path, mock_detection: MagicMock) -> None:
    # Given: all prompts return their defaults
    output = tmp_path / "manifest.yaml"

    with (
        patch("git_recrypt._wizard_steps.run_detection", return_value=mock_detection),
        patch("questionary.select", side_effect=_select_default),
        patch("questionary.checkbox", return_value=_make_question(["secrets/**"])),
        patch("questionary.text", return_value=_make_question("")),
    ):
        # When
        manifest = run_wizard(tmp_path, output)

    # Then
    assert manifest.version == 1
    assert manifest.key.symmetric is not None
    assert manifest.key.symmetric.key_file == "generate"
    assert "secrets/**" in manifest.patterns
    assert manifest.introduce_at == "root"
    assert manifest.branches == ["HEAD"]
    assert manifest.exclude == []
    assert output.exists()


# ---------------------------------------------------------------------------
# Symmetric key -- generate
# ---------------------------------------------------------------------------


def test_symmetric_key_generate(tmp_path: Path, mock_detection: MagicMock) -> None:
    # Given: user selects symmetric + generate
    output = tmp_path / "manifest.yaml"

    # select order: profile, key_type, sym_mode, introduce_at, branches
    # text order: custom_pattern_stop, exclusion_stop
    with (
        patch("git_recrypt._wizard_steps.run_detection", return_value=mock_detection),
        patch(
            "questionary.select",
            side_effect=_iter_select(
                ["generic", "symmetric", "generate", "root", "HEAD"]
            ),
        ),
        patch("questionary.checkbox", return_value=_make_question(["secrets/**"])),
        patch("questionary.text", return_value=_make_question("")),
    ):
        manifest = run_wizard(tmp_path, output)

    # Then
    assert manifest.key.symmetric is not None
    assert manifest.key.symmetric.key_file == "generate"
    assert manifest.key.gpg is None


# ---------------------------------------------------------------------------
# Symmetric key -- provide existing
# ---------------------------------------------------------------------------


def test_symmetric_key_existing_file(tmp_path: Path, mock_detection: MagicMock) -> None:
    # Given: user selects symmetric + provide existing + a key path
    output = tmp_path / "manifest.yaml"
    key_file = tmp_path / "my.key"
    _ = key_file.write_text("key-data", encoding="utf-8")

    # select order: profile, key_type, sym_mode, introduce_at, branches
    # (no passphrase_mode when "provide existing")
    # path order: key_file_path
    # text order: custom_pattern_stop, exclusion_stop
    with (
        patch("git_recrypt._wizard_steps.run_detection", return_value=mock_detection),
        patch(
            "questionary.select",
            side_effect=_iter_select(
                ["generic", "symmetric", "provide existing", "root", "HEAD"]
            ),
        ),
        patch("questionary.checkbox", return_value=_make_question(["secrets/**"])),
        patch("questionary.text", return_value=_make_question("")),
        patch(
            "questionary.path",
            side_effect=_iter_path([str(key_file)]),
        ),
    ):
        manifest = run_wizard(tmp_path, output)

    # Then
    assert manifest.key.symmetric is not None
    assert manifest.key.symmetric.key_file == str(key_file)


# ---------------------------------------------------------------------------
# GPG key -- user IDs
# ---------------------------------------------------------------------------
# Call order for gpg+user_ids:
#   select: profile, key_type, introduce_at, branches
#   text:   custom_pattern_stop, gpg_user_ids, exclusion_stop


def test_gpg_key_user_ids(tmp_path: Path, mock_detection: MagicMock) -> None:
    # Given: user selects gpg + provides user IDs
    output = tmp_path / "manifest.yaml"

    # select order: profile, key_type, introduce_at, branches
    # text order: custom_pattern_stop, gpg_user_ids, exclusion_stop
    with (
        patch("git_recrypt._wizard_steps.run_detection", return_value=mock_detection),
        patch(
            "questionary.select",
            side_effect=_iter_select(["generic", "gpg", "root", "HEAD"]),
        ),
        patch("questionary.checkbox", return_value=_make_question(["secrets/**"])),
        patch(
            "questionary.text",
            side_effect=_iter_text(["", "alice@example.com, bob@example.com", ""]),
        ),
    ):
        manifest = run_wizard(tmp_path, output)

    # Then
    assert manifest.key.gpg is not None
    assert manifest.key.gpg.user_ids == ["alice@example.com", "bob@example.com"]
    assert manifest.key.symmetric is None


# ---------------------------------------------------------------------------
# GPG key -- generate
# ---------------------------------------------------------------------------
# Call order for gpg+generate:
#   select: profile, key_type, gpg_passphrase_mode, introduce_at, branches
#   text:   custom_pattern_stop, gpg_user_ids (empty), exclusion_stop


def test_gpg_key_generate(tmp_path: Path, mock_detection: MagicMock) -> None:
    # Given: user selects gpg + empty user IDs (generate) + random passphrase
    output = tmp_path / "manifest.yaml"

    # select order: profile, key_type, gpg_passphrase_mode, introduce_at, branches
    # text order: custom_pattern_stop, gpg_user_ids (empty → generate), exclusion_stop
    with (
        patch("git_recrypt._wizard_steps.run_detection", return_value=mock_detection),
        patch(
            "questionary.select",
            side_effect=_iter_select(["generic", "gpg", "random", "root", "HEAD"]),
        ),
        patch("questionary.checkbox", return_value=_make_question(["secrets/**"])),
        patch("questionary.text", side_effect=_iter_text(["", "", ""])),
    ):
        manifest = run_wizard(tmp_path, output)

    # Then
    assert manifest.key.gpg is not None
    assert manifest.key.gpg.generate is not None
    assert manifest.key.gpg.generate.passphrase == "random"  # noqa: S105
    assert manifest.key.gpg.user_ids is None


# ---------------------------------------------------------------------------
# Custom pattern addition
# ---------------------------------------------------------------------------
# text order: custom_pattern_1, custom_pattern_stop, exclusion_stop


def test_custom_pattern_addition(tmp_path: Path, mock_detection: MagicMock) -> None:
    # Given: user adds a custom pattern then stops
    output = tmp_path / "manifest.yaml"

    # text order: custom_pattern_1, custom_pattern_stop, exclusion_stop
    with (
        patch("git_recrypt._wizard_steps.run_detection", return_value=mock_detection),
        patch("questionary.select", side_effect=_select_default),
        patch("questionary.checkbox", return_value=_make_question(["secrets/**"])),
        patch(
            "questionary.text",
            side_effect=_iter_text(["custom/*.secret", "", ""]),
        ),
    ):
        manifest = run_wizard(tmp_path, output)

    # Then
    assert "custom/*.secret" in manifest.patterns
    assert "secrets/**" in manifest.patterns


# ---------------------------------------------------------------------------
# Manifest conflict -- overwrite
# ---------------------------------------------------------------------------


def test_conflict_overwrite(tmp_path: Path, mock_detection: MagicMock) -> None:
    # Given: output file already exists; user chooses overwrite
    output = tmp_path / "manifest.yaml"
    _ = output.write_text(_minimal_manifest_yaml(), encoding="utf-8")

    # select: profile, key_type, sym_mode, introduce_at, branches, conflict
    # text order: custom_pattern_stop, exclusion_stop
    with (
        patch("git_recrypt._wizard_steps.run_detection", return_value=mock_detection),
        patch(
            "questionary.select",
            side_effect=_iter_select(
                [
                    "generic",
                    "symmetric",
                    "generate",
                    "root",
                    "HEAD",
                    "overwrite",
                ]
            ),
        ),
        patch("questionary.checkbox", return_value=_make_question(["secrets/**"])),
        patch("questionary.text", return_value=_make_question("")),
    ):
        manifest = run_wizard(tmp_path, output)

    # Then: file is overwritten with new manifest
    assert output.exists()
    assert manifest.key.symmetric is not None
    assert manifest.key.symmetric.key_file == "generate"


# ---------------------------------------------------------------------------
# Manifest conflict -- merge
# ---------------------------------------------------------------------------


def test_conflict_merge(tmp_path: Path, mock_detection: MagicMock) -> None:
    # Given: output file exists with pattern "old/**"; new manifest has "secrets/**"
    output = tmp_path / "manifest.yaml"
    _ = output.write_text(_minimal_manifest_yaml(["old/**"]), encoding="utf-8")

    # select: profile, key_type, sym_mode, introduce_at, branches, conflict
    # text order: custom_pattern_stop, exclusion_stop
    with (
        patch("git_recrypt._wizard_steps.run_detection", return_value=mock_detection),
        patch(
            "questionary.select",
            side_effect=_iter_select(
                [
                    "generic",
                    "symmetric",
                    "generate",
                    "root",
                    "HEAD",
                    "merge",
                ]
            ),
        ),
        patch("questionary.checkbox", return_value=_make_question(["secrets/**"])),
        patch("questionary.text", return_value=_make_question("")),
    ):
        manifest = run_wizard(tmp_path, output)

    # Then: patterns are unioned
    assert "old/**" in manifest.patterns
    assert "secrets/**" in manifest.patterns


# ---------------------------------------------------------------------------
# Manifest conflict -- save to different path
# ---------------------------------------------------------------------------


def test_conflict_different_path(tmp_path: Path, mock_detection: MagicMock) -> None:
    # Given: output file exists; user chooses a different path
    output = tmp_path / "manifest.yaml"
    _ = output.write_text(_minimal_manifest_yaml(), encoding="utf-8")
    alt_path = tmp_path / "alt-manifest.yaml"

    # select: profile, key_type, sym_mode, introduce_at, branches, conflict
    # path order: new_manifest_path
    # text order: custom_pattern_stop, exclusion_stop
    with (
        patch("git_recrypt._wizard_steps.run_detection", return_value=mock_detection),
        patch(
            "questionary.select",
            side_effect=_iter_select(
                [
                    "generic",
                    "symmetric",
                    "generate",
                    "root",
                    "HEAD",
                    "save to different path",
                ]
            ),
        ),
        patch("questionary.checkbox", return_value=_make_question(["secrets/**"])),
        patch("questionary.text", return_value=_make_question("")),
        patch("questionary.path", side_effect=_iter_path([str(alt_path)])),
    ):
        manifest = run_wizard(tmp_path, output)

    # Then: manifest written to alt path, not original
    assert alt_path.exists()
    assert manifest.key.symmetric is not None


# ---------------------------------------------------------------------------
# SHA introduction point
# ---------------------------------------------------------------------------
# text order: custom_pattern_stop, sha_value, exclusion_stop


def test_sha_introduction_point(tmp_path: Path, mock_detection: MagicMock) -> None:
    # Given: user selects "specific SHA" and provides a valid SHA
    output = tmp_path / "manifest.yaml"

    # select order: profile, key_type, sym_mode, introduce_at, branches
    # text order: custom_pattern_stop, sha_value, exclusion_stop
    with (
        patch("git_recrypt._wizard_steps.run_detection", return_value=mock_detection),
        patch(
            "questionary.select",
            side_effect=_iter_select(
                [
                    "generic",
                    "symmetric",
                    "generate",
                    "specific SHA",
                    "HEAD",
                ]
            ),
        ),
        patch("questionary.checkbox", return_value=_make_question(["secrets/**"])),
        patch("questionary.text", side_effect=_iter_text(["", _SHA, ""])),
    ):
        manifest = run_wizard(tmp_path, output)

    # Then
    assert manifest.introduce_at == _SHA


# ---------------------------------------------------------------------------
# Specific branch selection
# ---------------------------------------------------------------------------
# text order: custom_pattern_stop, branch_names, exclusion_stop


def test_specific_branch_selection(tmp_path: Path, mock_detection: MagicMock) -> None:
    # Given: user selects "specific" branches and provides branch names
    output = tmp_path / "manifest.yaml"

    # select order: profile, key_type, sym_mode, introduce_at, branches
    # text order: custom_pattern_stop, branch_names, exclusion_stop
    with (
        patch("git_recrypt._wizard_steps.run_detection", return_value=mock_detection),
        patch(
            "questionary.select",
            side_effect=_iter_select(
                ["generic", "symmetric", "generate", "root", "specific"]
            ),
        ),
        patch("questionary.checkbox", return_value=_make_question(["secrets/**"])),
        patch("questionary.text", side_effect=_iter_text(["", "main, develop", ""])),
    ):
        manifest = run_wizard(tmp_path, output)

    # Then
    assert "main" in manifest.branches
    assert "develop" in manifest.branches


# ---------------------------------------------------------------------------
# Exclusion patterns
# ---------------------------------------------------------------------------
# text order: custom_pattern_stop, excl_1, excl_2, excl_stop


def test_exclusion_patterns(tmp_path: Path, mock_detection: MagicMock) -> None:
    # Given: user adds two exclusion patterns then stops
    output = tmp_path / "manifest.yaml"

    # select order: profile, key_type, sym_mode, introduce_at, branches
    # text order: custom_pattern_stop, excl_1, excl_2, excl_stop
    with (
        patch("git_recrypt._wizard_steps.run_detection", return_value=mock_detection),
        patch(
            "questionary.select",
            side_effect=_iter_select(
                ["generic", "symmetric", "generate", "root", "HEAD"]
            ),
        ),
        patch("questionary.checkbox", return_value=_make_question(["secrets/**"])),
        patch("questionary.text", side_effect=_iter_text(["", "*.pub", "*.bak", ""])),
    ):
        manifest = run_wizard(tmp_path, output)

    # Then
    assert "*.pub" in manifest.exclude
    assert "*.bak" in manifest.exclude


# ---------------------------------------------------------------------------
# Cancellation raises KeyboardInterrupt
# ---------------------------------------------------------------------------


def test_cancel_on_profile_raises(tmp_path: Path, mock_detection: MagicMock) -> None:
    # Given: user cancels at profile selection (questionary returns None)
    output = tmp_path / "manifest.yaml"

    with (
        patch("git_recrypt._wizard_steps.run_detection", return_value=mock_detection),
        patch("questionary.select", return_value=_make_question(None)),
        patch("questionary.checkbox", return_value=_make_question(["secrets/**"])),
        patch("questionary.text", return_value=_make_question("")),
        pytest.raises(KeyboardInterrupt),
    ):
        run_wizard(tmp_path, output)


# ---------------------------------------------------------------------------
# Manifest written to disk
# ---------------------------------------------------------------------------


def test_manifest_written_to_disk(tmp_path: Path, mock_detection: MagicMock) -> None:
    # Given: output does not exist
    output = tmp_path / "new-manifest.yaml"
    assert not output.exists()

    with (
        patch("git_recrypt._wizard_steps.run_detection", return_value=mock_detection),
        patch("questionary.select", side_effect=_select_default),
        patch("questionary.checkbox", return_value=_make_question(["secrets/**"])),
        patch("questionary.text", return_value=_make_question("")),
    ):
        _ = run_wizard(tmp_path, output)

    assert output.exists()


# ---------------------------------------------------------------------------
# Detection profile propagated to manifest
# ---------------------------------------------------------------------------


def test_detection_profile_in_manifest(
    tmp_path: Path, mock_detection: MagicMock
) -> None:
    # Given: auto-detected profile is "generic"
    output = tmp_path / "manifest.yaml"

    with (
        patch("git_recrypt._wizard_steps.run_detection", return_value=mock_detection),
        patch("questionary.select", side_effect=_select_default),
        patch("questionary.checkbox", return_value=_make_question(["secrets/**"])),
        patch("questionary.text", return_value=_make_question("")),
    ):
        manifest = run_wizard(tmp_path, output)

    # Then
    assert manifest.detection_profile == "generic"


# ---------------------------------------------------------------------------
# Empty checkbox selection falls back to wildcard
# ---------------------------------------------------------------------------


def test_empty_pattern_selection_uses_fallback(
    tmp_path: Path, mock_detection: MagicMock
) -> None:
    # Given: user selects no patterns from checkbox
    output = tmp_path / "manifest.yaml"

    with (
        patch("git_recrypt._wizard_steps.run_detection", return_value=mock_detection),
        patch("questionary.select", side_effect=_select_default),
        patch("questionary.checkbox", return_value=_make_question([])),
        patch("questionary.text", return_value=_make_question("")),
    ):
        manifest = run_wizard(tmp_path, output)

    # Then: fallback wildcard is used
    assert manifest.patterns == ["**/*"]


# ---------------------------------------------------------------------------
# Merge deduplicates patterns
# ---------------------------------------------------------------------------


def test_conflict_merge_deduplicates(tmp_path: Path, mock_detection: MagicMock) -> None:
    # Given: existing manifest has "secrets/**" too; new manifest also has it
    output = tmp_path / "manifest.yaml"
    _ = output.write_text(
        _minimal_manifest_yaml(["secrets/**", "other/**"]), encoding="utf-8"
    )

    # select: profile, key_type, sym_mode, introduce_at, branches, conflict
    # text order: custom_pattern_stop, exclusion_stop
    with (
        patch("git_recrypt._wizard_steps.run_detection", return_value=mock_detection),
        patch(
            "questionary.select",
            side_effect=_iter_select(
                [
                    "generic",
                    "symmetric",
                    "generate",
                    "root",
                    "HEAD",
                    "merge",
                ]
            ),
        ),
        patch("questionary.checkbox", return_value=_make_question(["secrets/**"])),
        patch("questionary.text", return_value=_make_question("")),
    ):
        manifest = run_wizard(tmp_path, output)

    # Then: no duplicates
    assert manifest.patterns.count("secrets/**") == 1
    assert "other/**" in manifest.patterns


# ---------------------------------------------------------------------------
# "all" branch selection
# ---------------------------------------------------------------------------


def test_all_branches_selection(tmp_path: Path, mock_detection: MagicMock) -> None:
    # Given: user selects "all" branches
    output = tmp_path / "manifest.yaml"

    # select order: profile, key_type, sym_mode, introduce_at, branches
    # text order: custom_pattern_stop, exclusion_stop
    with (
        patch("git_recrypt._wizard_steps.run_detection", return_value=mock_detection),
        patch(
            "questionary.select",
            side_effect=_iter_select(
                ["generic", "symmetric", "generate", "root", "all"]
            ),
        ),
        patch("questionary.checkbox", return_value=_make_question(["secrets/**"])),
        patch("questionary.text", return_value=_make_question("")),
    ):
        manifest = run_wizard(tmp_path, output)

    # Then: "all" is not yet supported, falls back to HEAD
    assert manifest.branches == ["HEAD"]


# ---------------------------------------------------------------------------
# "first-match" introduction point
# ---------------------------------------------------------------------------


def test_first_match_introduction_point(
    tmp_path: Path, mock_detection: MagicMock
) -> None:
    # Given: user selects "first-match" introduction point
    output = tmp_path / "manifest.yaml"

    # select order: profile, key_type, sym_mode, introduce_at, branches
    # text order: custom_pattern_stop, exclusion_stop
    with (
        patch("git_recrypt._wizard_steps.run_detection", return_value=mock_detection),
        patch(
            "questionary.select",
            side_effect=_iter_select(
                [
                    "generic",
                    "symmetric",
                    "generate",
                    "first-match",
                    "HEAD",
                ]
            ),
        ),
        patch("questionary.checkbox", return_value=_make_question(["secrets/**"])),
        patch("questionary.text", return_value=_make_question("")),
    ):
        manifest = run_wizard(tmp_path, output)

    # Then
    assert manifest.introduce_at == "first-match"
