"""CLI entry point for git-recrypt."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from git_recrypt._cli_verify import (
    build_verifier,
    print_phase_progress,
    run_post_rewrite_verify,
)
from git_recrypt.crypto import resolve_key_from_manifest
from git_recrypt.detector._registry import run_detection
from git_recrypt.detector.base import Severity
from git_recrypt.errors import (
    CryptoError,
    DetectionError,
    GitRecryptError,
    ManifestError,
)
from git_recrypt.manifest import load_manifest, resolve_repo_path
from git_recrypt.rewriter import HistoryRewriter, RewriteConfig, RewriteProgress
from git_recrypt.verifier import VerifyMode

app = typer.Typer(
    name="git-recrypt",
    help="Retroactively introduce git-crypt to existing repos.",
)
_console = Console()

_DEFAULT_MANIFEST = "git-recrypt.yaml"
_DEFAULT_REPO = "."


@app.command()
def detect(
    profile: Annotated[str | None, typer.Option(help="Detection profile")] = None,
    repo: Annotated[str, typer.Option(help="Repository path")] = _DEFAULT_REPO,
) -> None:
    """Scan repo and suggest encryption patterns."""
    try:
        result = run_detection(Path(repo), profile)
    except DetectionError as exc:
        _console.print(f"[red]Detection error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    table = Table(title=f"Detected secrets ({result.profile})")
    table.add_column("Severity", style="bold")
    table.add_column("File")
    table.add_column("Reason")
    for secret in result.secrets:
        style = "red" if secret.severity == Severity.CRITICAL else "yellow"
        table.add_row(
            secret.severity.value, secret.filepath, secret.reason, style=style
        )
    _console.print(table)

    if result.suggested_patterns:
        _console.print("\nSuggested .gitattributes patterns:")
        for pattern in result.suggested_patterns:
            _console.print(f"  {pattern} filter=git-crypt diff=git-crypt")


@app.command()
def init(
    repo: Annotated[str, typer.Option(help="Repository path")] = _DEFAULT_REPO,
    output: Annotated[
        str, typer.Option(help="Output manifest path")
    ] = _DEFAULT_MANIFEST,
) -> None:
    """Interactive wizard to produce a manifest file."""
    _run_wizard(Path(repo), Path(output))


def _run_wizard(repo: Path, output: Path) -> None:
    try:
        from git_recrypt import wizard as _wizard_mod  # noqa: PLC0415
    except ImportError as exc:
        _console.print(
            "[red]Wizard dependencies not available. Check your environment.[/red]"
        )
        raise typer.Exit(code=1) from exc
    _ = _wizard_mod.run_wizard(repo, output)


@app.command()
def run(
    manifest: Annotated[
        str, typer.Option(help="Manifest file path")
    ] = _DEFAULT_MANIFEST,
    repo: Annotated[
        str | None, typer.Option(help="Target repository path (overrides manifest)")
    ] = None,
    force: Annotated[bool, typer.Option(help="Skip confirmation")] = False,
    work_dir: Annotated[
        str | None, typer.Option(help="Working directory for clone")
    ] = None,
    skip_verify: Annotated[bool, typer.Option(help="Skip verification")] = False,
) -> None:
    """Execute history rewrite from manifest."""
    manifest_path = Path(manifest)
    try:
        m = load_manifest(manifest_path)
    except ManifestError as exc:
        _console.print(f"[red]Manifest error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    repo_path = resolve_repo_path(m, manifest_path, repo)
    auto_created = work_dir is None
    resolved_work_dir = (
        Path(work_dir)
        if work_dir is not None
        else Path(tempfile.mkdtemp(prefix="gcri-"))
    )

    if not force:
        _console.print(f"Repository: {repo_path}")
        _console.print(f"Will rewrite [bold]{len(m.patterns)}[/bold] pattern(s)")
        _console.print(f"Work directory: {resolved_work_dir}")
        typer.confirm("Proceed with rewrite?", abort=True)

    try:
        key_file, key_msg = resolve_key_from_manifest(m.key, repo_path)
        if key_msg:
            _console.print(key_msg)
    except CryptoError as exc:
        _console.print(f"[red]Key error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    config = RewriteConfig(
        manifest=m,
        key_file=key_file,
        repo_path=repo_path,
        work_dir=resolved_work_dir,
    )

    try:

        def _on_progress(p: RewriteProgress) -> None:
            if p.message is not None:
                _console.print(f"  {p.message}")
                return
            _console.print(
                f"  Replaying commit {p.commits_processed}/{p.commits_total}...",
                end="\r",
            )

        rewriter = HistoryRewriter(config, progress_callback=_on_progress)
        result = rewriter.run()
    except GitRecryptError as exc:
        _console.print(f"\n[red]Rewrite failed:[/red] {exc}")
        if auto_created and resolved_work_dir.exists():
            shutil.rmtree(resolved_work_dir)
        raise typer.Exit(code=1) from exc

    _console.print("\n[green]Rewrite complete![/green]")
    _console.print(f"  Commits rewritten: {result.commits_rewritten}")
    _console.print(f"  Files encrypted: {result.files_encrypted}")
    _console.print(f"  Elapsed: {result.elapsed_seconds:.1f}s")
    _console.print(f"  Work directory: {result.work_dir}")

    if not skip_verify:
        run_post_rewrite_verify(
            m,
            repo_path,
            result.work_dir,
            key_file,
            rewrite_commits=result.commits_rewritten,
            rewrite_files_encrypted=result.files_encrypted,
        )

    _finalize_target(result.work_dir, result.branch)
    _console.print(f"\nRewritten repo: {result.work_dir}")


def _finalize_target(work_dir: Path, branch: str) -> None:
    if not (work_dir / ".git").is_dir():
        return
    import subprocess  # noqa: PLC0415

    from git_recrypt._shellout import GIT  # noqa: PLC0415

    r = subprocess.run(  # noqa: S603
        [GIT, "checkout", branch],
        cwd=work_dir, capture_output=True, check=False,
    )
    if r.returncode != 0:
        _console.print(f"[yellow]Warning: could not checkout branch {branch}[/yellow]")


@app.command()
def verify(
    original: Annotated[str, typer.Argument(help="Original repo path")],
    rewritten: Annotated[str, typer.Argument(help="Rewritten repo path")],
    key_file: Annotated[str, typer.Argument(help="Key file path")],
    manifest: Annotated[
        str, typer.Option(help="Manifest for patterns")
    ] = _DEFAULT_MANIFEST,
    mode: Annotated[str, typer.Option(help="full or fast")] = "fast",
) -> None:
    """Verify a rewritten repo matches original content."""
    try:
        m = load_manifest(Path(manifest))
    except ManifestError as exc:
        _console.print(f"[red]Manifest error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if mode not in ("fast", "full"):
        _console.print(f"[red]Invalid mode:[/red] '{mode}'. Must be 'fast' or 'full'.")
        raise typer.Exit(code=1)
    verify_mode = VerifyMode.FULL if mode == "full" else VerifyMode.FAST
    verifier = build_verifier(
        m,
        Path(original),
        Path(rewritten),
        Path(key_file),
        verify_mode,
    )
    if verifier is None:
        _console.print("[red]Invalid manifest[/red]")
        raise typer.Exit(code=1)
    print_phase_progress(verifier)
    result = verifier.verify()
    _console.print()
    _console.print(
        f"Commits verified: {result.commits_verified}/{result.commits_total}"
    )
    _console.print(f"Files verified: {result.files_verified}")
    if result.passed:
        _console.print("[green]RESULT: PASS[/green]")
    else:
        _console.print("[red]RESULT: FAIL[/red]")
        for err in result.errors:
            _console.print(f"  [red]{err}[/red]")
        raise typer.Exit(code=2)


@app.command(name="dry-run")
def dry_run(
    manifest: Annotated[
        str, typer.Option(help="Manifest file path")
    ] = _DEFAULT_MANIFEST,
    repo: Annotated[
        str | None, typer.Option(help="Target repository path (overrides manifest)")
    ] = None,
) -> None:
    """Show what would be encrypted without modifying anything."""
    manifest_path = Path(manifest)
    try:
        m = load_manifest(manifest_path)
    except ManifestError as exc:
        _console.print(f"[red]Manifest error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    repo_path = resolve_repo_path(m, manifest_path, repo)
    _console.print(f"Manifest: {manifest}")
    _console.print(f"Repository: {repo_path}")
    _console.print(f"Patterns: {len(m.patterns)}")
    for p in m.patterns:
        _console.print(f"  {p}")
    _console.print(f"Exclude: {len(m.exclude)}")
    for e in m.exclude:
        _console.print(f"  {e}")
    _console.print(f"Introduce at: {m.introduce_at}")
    _console.print(f"Branches: {m.branches}")
