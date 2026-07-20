"""CLI entry point for git-recrypt."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from git_recrypt.detector._registry import run_detection
from git_recrypt.detector.base import Severity
from git_recrypt.errors import DetectionError, GitRecryptError, ManifestError
from git_recrypt.manifest import load_manifest
from git_recrypt.patterns import PatternMatcher
from git_recrypt.rewriter import HistoryRewriter, RewriteConfig
from git_recrypt.verifier import RewriteVerifier, VerifyMode

if TYPE_CHECKING:
    from git_recrypt.manifest import Manifest

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
    """Invoke the optional wizard module, raising Exit if unavailable."""
    try:
        from git_recrypt import wizard as _wizard_mod  # noqa: PLC0415
    except ImportError as exc:
        _console.print(
            "[red]Wizard not available. Install optional dependencies.[/red]"
        )
        raise typer.Exit(code=1) from exc
    _ = _wizard_mod.run_wizard(repo, output)


@app.command()
def run(
    manifest: Annotated[
        str, typer.Option(help="Manifest file path")
    ] = _DEFAULT_MANIFEST,
    force: Annotated[bool, typer.Option(help="Skip confirmation")] = False,
    work_dir: Annotated[
        str | None, typer.Option(help="Working directory for clone")
    ] = None,
    skip_verify: Annotated[bool, typer.Option(help="Skip verification")] = False,
) -> None:
    """Execute history rewrite from manifest."""
    try:
        m = load_manifest(Path(manifest))
    except ManifestError as exc:
        _console.print(f"[red]Manifest error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    resolved_work_dir = (
        Path(work_dir)
        if work_dir is not None
        else Path(tempfile.mkdtemp(prefix="gcri-"))
    )

    if not force:
        _console.print(f"Will rewrite [bold]{len(m.patterns)}[/bold] pattern(s)")
        _console.print(f"Work directory: {resolved_work_dir}")

    try:
        key_file = _resolve_key_file(m)
    except typer.BadParameter as exc:
        _console.print(f"[red]Key error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    config = RewriteConfig(
        manifest=m,
        key_file=key_file,
        repo_path=Path(),
        work_dir=resolved_work_dir,
    )

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=_console,
        ) as progress:
            task = progress.add_task("Rewriting history...", total=None)
            rewriter = HistoryRewriter(config)
            result = rewriter.run()
            progress.update(task, completed=True)
    except GitRecryptError as exc:
        _console.print(f"[red]Rewrite failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    _console.print("\n[green]Rewrite complete![/green]")
    _console.print(f"  Commits rewritten: {result.commits_rewritten}")
    _console.print(f"  Files encrypted: {result.files_encrypted}")
    _console.print(f"  Elapsed: {result.elapsed_seconds:.1f}s")
    _console.print(f"  Work directory: {result.work_dir}")

    if not skip_verify:
        _console.print("\nRunning verification...")
        matcher = PatternMatcher(
            include_patterns=tuple(m.patterns),
            exclude_patterns=tuple(m.exclude),
        )
        verifier = RewriteVerifier(
            original_path=Path(),
            rewritten_path=result.work_dir,
            key_file=key_file,
            matcher=matcher,
        )
        vresult = verifier.verify()
        if vresult.passed:
            _console.print("[green]Verification PASSED[/green]")
        else:
            _console.print("[red]Verification FAILED[/red]")
            for err in vresult.errors:
                _console.print(f"  [red]{err}[/red]")
            raise typer.Exit(code=2)

    _console.print(f"\nTo apply: cd {result.work_dir} && git push --force --all")


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

    matcher = PatternMatcher(
        include_patterns=tuple(m.patterns),
        exclude_patterns=tuple(m.exclude),
    )
    verify_mode = VerifyMode.FULL if mode == "full" else VerifyMode.FAST
    verifier = RewriteVerifier(
        original_path=Path(original),
        rewritten_path=Path(rewritten),
        key_file=Path(key_file),
        matcher=matcher,
        mode=verify_mode,
    )
    result = verifier.verify()
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
) -> None:
    """Show what would be encrypted without modifying anything."""
    try:
        m = load_manifest(Path(manifest))
    except ManifestError as exc:
        _console.print(f"[red]Manifest error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    _console.print(f"Manifest: {manifest}")
    _console.print(f"Patterns: {len(m.patterns)}")
    for p in m.patterns:
        _console.print(f"  {p}")
    _console.print(f"Exclude: {len(m.exclude)}")
    for e in m.exclude:
        _console.print(f"  {e}")
    _console.print(f"Introduce at: {m.introduce_at}")
    _console.print(f"Branches: {m.branches}")


def _resolve_key_file(m: Manifest) -> Path:
    """Resolve the key file path from manifest config."""
    if m.key.symmetric is not None:
        kf = m.key.symmetric.key_file
        if kf == "generate":
            msg = "Key generation not yet implemented. Provide an existing key file."
            raise typer.BadParameter(msg)
        return Path(kf)
    msg = "GPG key mode not yet implemented."
    raise typer.BadParameter(msg)
