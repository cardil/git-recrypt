"""Individual wizard step implementations for git-recrypt manifest generation."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Literal, cast

import questionary
from questionary import Choice
from rich.console import Console
from rich.table import Table

from git_recrypt.detector._registry import run_detection
from git_recrypt.manifest import (
    GpgGenerateConfig,
    GpgKeyConfig,
    KeyConfig,
    Manifest,
    SymmetricKeyConfig,
    load_manifest,
    save_manifest,
)

if TYPE_CHECKING:
    from git_recrypt.detector.base import DetectionResult

_console = Console()

_PROFILES = ["generic", "etckeeper", "kubernetes"]
_INTRO_CHOICES = ["root", "first-match", "specific SHA"]
_BRANCH_CHOICES = ["HEAD", "all", "specific"]
_KEY_TYPE_CHOICES = ["symmetric", "gpg"]
_SYM_MODE_CHOICES = ["generate", "provide existing"]
_CONFLICT_CHOICES = ["overwrite", "merge", "save to different path"]
_PASSPHRASE_CHOICES = ["provided", "random"]


def _ask_str(q: questionary.Question, label: str) -> str:
    """Ask a question expecting str; raise KeyboardInterrupt on cancel."""
    raw = cast("str | None", q.ask())
    if raw is None:
        msg = f"Wizard cancelled at: {label}"
        raise KeyboardInterrupt(msg)
    return raw


def _ask_list(q: questionary.Question, label: str) -> list[str]:
    """Ask a question expecting list[str]; raise KeyboardInterrupt on cancel."""
    raw = cast("list[str] | None", q.ask())
    if raw is None:
        msg = f"Wizard cancelled at: {label}"
        raise KeyboardInterrupt(msg)
    return raw


def step_detect(repo_path: Path, *, profile: str | None = None) -> DetectionResult:
    """Step 1: Run detection and print results table."""
    result = run_detection(repo_path, profile)
    table = Table(title=f"Detected secrets (profile: {result.profile})")
    table.add_column("Severity", style="bold")
    table.add_column("File")
    table.add_column("Reason")
    for secret in result.secrets:
        style = "red" if secret.severity == "critical" else "yellow"
        table.add_row(
            secret.severity,
            secret.filepath,
            secret.reason,
            style=style,
        )
    _console.print(table)
    if result.suggested_patterns:
        _console.print("\n[bold]Suggested patterns:[/bold]")
        for p in result.suggested_patterns:
            _console.print(f"  {p}")
    return result


def step_profile(detected_profile: str) -> str:
    """Step 2: Select detection profile."""
    default = detected_profile if detected_profile in _PROFILES else "generic"
    return _ask_str(
        questionary.select(
            "Select detection profile:", choices=_PROFILES, default=default
        ),
        "profile selection",
    )


def step_patterns(detection: DetectionResult) -> list[str]:
    """Step 3: Select patterns (pre-checked from detection) and add custom ones."""
    suggested = set(detection.suggested_patterns)
    choices = [
        Choice(title=p, value=p, checked=(p in suggested))
        for p in detection.suggested_patterns
    ]
    patterns = _ask_list(
        questionary.checkbox(
            "Select patterns to encrypt:",
            choices=choices,
        ),
        "pattern selection",
    )
    while True:
        custom = _ask_str(
            questionary.text("Add custom pattern (empty to stop):", default=""),
            "custom pattern",
        )
        if not custom.strip():
            break
        patterns.append(custom.strip())
    return patterns


def step_key() -> KeyConfig:
    """Step 4: Configure key (symmetric or GPG)."""
    key_type = _ask_str(
        questionary.select("Key type:", choices=_KEY_TYPE_CHOICES, default="symmetric"),
        "key type",
    )
    if key_type == "symmetric":
        return _step_symmetric_key()
    return _step_gpg_key()


def _step_symmetric_key() -> KeyConfig:
    mode = _ask_str(
        questionary.select(
            "Symmetric key mode:", choices=_SYM_MODE_CHOICES, default="generate"
        ),
        "symmetric key mode",
    )
    if mode == "provide existing":
        key_path = _ask_str(
            questionary.path("Path to existing key file:"),
            "key file path",
        )
        return KeyConfig(symmetric=SymmetricKeyConfig(key_file=key_path))
    return KeyConfig(symmetric=SymmetricKeyConfig(key_file="generate"))


def _step_gpg_key() -> KeyConfig:
    """Step 4b: GPG key sub-flow."""
    raw_ids = _ask_str(
        questionary.text(
            "GPG user IDs (comma-separated, empty to generate):", default=""
        ),
        "GPG user IDs",
    )
    if raw_ids.strip():
        user_ids = [uid.strip() for uid in raw_ids.split(",") if uid.strip()]
        return KeyConfig(gpg=GpgKeyConfig(user_ids=user_ids))
    passphrase_mode = _ask_str(
        questionary.select(
            "Passphrase mode for generated GPG key:",
            choices=_PASSPHRASE_CHOICES,
            default="provided",
        ),
        "GPG passphrase mode",
    )
    pm: Literal["provided", "random"] = (
        "random" if passphrase_mode == "random" else "provided"  # noqa: S105
    )
    return KeyConfig(gpg=GpgKeyConfig(generate=GpgGenerateConfig(passphrase=pm)))


def step_introduce_at() -> str:
    """Step 5: Select introduction point."""
    choice = _ask_str(
        questionary.select(
            "Introduce git-crypt at:", choices=_INTRO_CHOICES, default="root"
        ),
        "introduce_at",
    )
    if choice == "specific SHA":
        sha = _ask_str(
            questionary.text("Enter the 40-char commit SHA:"),
            "SHA value",
        )
        return sha.strip()
    return choice


def step_branches() -> list[str]:
    """Step 6: Select branches."""
    choice = _ask_str(
        questionary.select(
            "Branches to rewrite:", choices=_BRANCH_CHOICES, default="HEAD"
        ),
        "branch selection",
    )
    if choice == "all":
        _console.print(
            "[yellow]Multi-branch rewrite is planned but not yet supported. "
            "Falling back to HEAD.[/yellow]"
        )
        return ["HEAD"]
    if choice == "specific":
        raw = _ask_str(
            questionary.text("Branch names (comma-separated):"),
            "branch names",
        )
        return [b.strip() for b in raw.split(",") if b.strip()]
    return ["HEAD"]


def step_exclusions() -> list[str]:
    """Step 7: Collect exclude patterns."""
    excludes: list[str] = []
    while True:
        pattern = _ask_str(
            questionary.text("Add exclude pattern (empty to stop):", default=""),
            "exclude pattern",
        )
        if not pattern.strip():
            break
        excludes.append(pattern.strip())
    return excludes


def step_conflict(output_path: Path, manifest: Manifest) -> tuple[Manifest, Path]:
    """Step 8: Handle manifest conflict if output_path exists.

    Returns (final_manifest, final_path).
    """
    if not output_path.exists():
        return manifest, output_path
    choice = _ask_str(
        questionary.select(
            f"{output_path} already exists. What to do?",
            choices=_CONFLICT_CHOICES,
            default="overwrite",
        ),
        "conflict resolution",
    )
    if choice == "merge":
        existing = load_manifest(output_path)
        merged_patterns = list(dict.fromkeys(existing.patterns + manifest.patterns))
        merged_exclude = list(dict.fromkeys(existing.exclude + manifest.exclude))
        merged = Manifest.model_validate(
            {
                **manifest.model_dump(exclude_none=True),
                "patterns": merged_patterns,
                "exclude": merged_exclude,
            }
        )
        return merged, output_path
    if choice == "save to different path":
        new_path_str = _ask_str(
            questionary.path("Save manifest to:", default=str(output_path)),
            "new manifest path",
        )
        return manifest, Path(new_path_str)
    return manifest, output_path


def step_write(manifest: Manifest, path: Path) -> None:
    """Step 9: Write manifest to disk."""
    save_manifest(manifest, path)
    _console.print(f"\n[green]Manifest written to:[/green] {path}")
