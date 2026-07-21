"""CLI helpers for verification commands."""

from __future__ import annotations

from typing import TYPE_CHECKING

import typer
from rich.console import Console

from git_recrypt.patterns import PatternMatcher
from git_recrypt.verifier import RewriteVerifier, VerifyMode

if TYPE_CHECKING:
    from pathlib import Path

_console = Console()


def build_verifier(  # noqa: PLR0913
    m: object,
    original: Path,
    rewritten: Path,
    key_file: Path,
    mode: VerifyMode = VerifyMode.FAST,
    rewrite_commits: int = 0,
    rewrite_files_encrypted: int = 0,
) -> RewriteVerifier | None:
    """Build a RewriteVerifier from a manifest object, or None if invalid."""
    from git_recrypt.manifest import Manifest  # noqa: PLC0415

    if not isinstance(m, Manifest):
        return None
    matcher = PatternMatcher(
        include_patterns=tuple(m.patterns),
        exclude_patterns=tuple(m.exclude),
    )
    verifier = RewriteVerifier(
        original_path=original,
        rewritten_path=rewritten,
        key_file=key_file,
        matcher=matcher,
        mode=mode,
        rewrite_commits=rewrite_commits,
        rewrite_files_encrypted=rewrite_files_encrypted,
    )
    if m.key.gpg is not None and m.key.gpg.user_ids is not None:
        verifier.set_gpg_user_ids(m.key.gpg.user_ids)
    return verifier


def print_phase_progress(
    verifier: RewriteVerifier,
    indent: str = "",
) -> None:
    """Print phase progress messages and wire up commit progress callback."""
    _console.print(f"{indent}Phase 1/3: Checking git-crypt status...")
    _console.print(f"{indent}Phase 2/3: Testing lock/unlock...")
    verifier.set_progress_callback(
        lambda cur, tot: _console.print(
            f"{indent}Phase 3/3: Verifying commits {cur + 1}/{tot}...", end="\r"
        )
    )


def run_post_rewrite_verify(  # noqa: PLR0913
    m: object,
    repo_path: Path,
    work_dir: Path,
    key_file: Path,
    rewrite_commits: int = 0,
    rewrite_files_encrypted: int = 0,
) -> None:
    """Run verification after a history rewrite and exit on failure."""
    _console.print("\nRunning verification...")
    verifier = build_verifier(
        m,
        repo_path,
        work_dir,
        key_file,
        rewrite_commits=rewrite_commits,
        rewrite_files_encrypted=rewrite_files_encrypted,
    )
    if verifier is None:
        return
    print_phase_progress(verifier, indent="  ")
    vresult = verifier.verify()
    _console.print()
    if vresult.passed:
        _console.print("[green]Verification PASSED[/green]")
    else:
        _console.print("[red]Verification FAILED[/red]")
        for err in vresult.errors:
            _console.print(f"  [red]{err}[/red]")
        raise typer.Exit(code=2)
