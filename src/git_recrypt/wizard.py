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


def run_wizard(repo_path: Path, output_path: Path) -> Manifest:
    """Run the interactive wizard to produce a manifest file.

    Args:
        repo_path: Path to the repository to configure.
        output_path: Path where the manifest YAML will be written.

    Returns:
        The generated Manifest.

    Raises:
        KeyboardInterrupt: If the user cancels any prompt.
    """
    # Step 1: Detect secrets
    detection = step_detect(repo_path)

    # Step 2: Profile selection
    profile = step_profile(detection.profile)

    # Step 3: Pattern selection
    patterns = step_patterns(detection)

    # Step 4: Key configuration
    key = step_key()

    # Step 5: Introduction point
    introduce_at = step_introduce_at()

    # Step 6: Branch selection
    branches = step_branches()

    # Step 7: Exclusions
    exclude = step_exclusions()

    # Build manifest
    manifest = Manifest.model_validate(
        {
            "version": 1,
            "key": key.model_dump(exclude_none=True),
            "patterns": patterns or ["**/*"],
            "introduce_at": introduce_at,
            "branches": branches,
            "exclude": exclude,
            "detection_profile": profile,
        }
    )

    # Step 8: Conflict check
    final_manifest, final_path = step_conflict(output_path, manifest)

    # Step 9: Write manifest
    step_write(final_manifest, final_path)

    return final_manifest
