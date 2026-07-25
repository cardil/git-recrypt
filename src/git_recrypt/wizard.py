"""Interactive wizard for generating a git-recrypt manifest."""

from __future__ import annotations

from typing import TYPE_CHECKING

from git_recrypt._wizard_steps import (
    step_branches,
    step_conflict,
    step_detect,
    step_exclusions,
    step_introduce_at,
    step_key,
    step_patterns,
    step_profile,
    step_write,
)
from git_recrypt.manifest import Manifest

if TYPE_CHECKING:
    from pathlib import Path

_DEFAULT_REPO = "./"


def run_wizard(repo_path: Path, output_path: Path) -> Manifest:
    """Run the interactive wizard to produce a manifest file."""
    detection = step_detect(repo_path)

    profile = step_profile(detection.profile)
    if profile != detection.profile:
        detection = step_detect(repo_path)

    patterns = step_patterns(detection)
    key = step_key()
    introduce_at = step_introduce_at()
    branches = step_branches()
    exclude = step_exclusions()

    if not patterns:
        from rich.console import Console  # noqa: PLC0415

        Console().print(
            "[yellow]Warning: No patterns selected."
            " Defaulting to '**/*' (encrypt everything).[/yellow]"
        )
    manifest_data: dict[str, object] = {
        "version": 1,
        "key": key.model_dump(exclude_none=True),
        "patterns": patterns or ["**/*"],
        "introduce_at": introduce_at,
        "branches": branches,
        "exclude": exclude,
        "detection_profile": profile,
    }
    repo_str = str(repo_path)
    if repo_str != _DEFAULT_REPO:
        manifest_data["repo"] = repo_str

    manifest = Manifest.model_validate(manifest_data)
    final_manifest, final_path = step_conflict(output_path, manifest)
    step_write(final_manifest, final_path)
    return final_manifest
