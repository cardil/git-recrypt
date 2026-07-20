"""Interactive wizard for generating a git-recrypt manifest."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from git_recrypt.manifest import Manifest


def run_wizard(repo_path: Path, output_path: Path) -> Manifest:
    """Run the interactive wizard to produce a manifest file.

    Args:
        repo_path: Path to the repository to configure.
        output_path: Path where the manifest YAML will be written.

    Returns:
        The generated Manifest.

    Raises:
        NotImplementedError: Wizard is not yet implemented.
    """
    _ = repo_path, output_path
    msg = "Wizard not yet implemented"
    raise NotImplementedError(msg)
