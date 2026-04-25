from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from airt import detectors as _detectors
from airt import loader as _loader
from airt.transforms import apply_transform, list_transforms

app = typer.Typer()
console = Console()


# ---------------------------------------------------------------------------
# list-payloads
# ---------------------------------------------------------------------------

@app.command("list-payloads")
def list_payloads(
    payloads_dir: Path = typer.Option(
        Path("payloads"),
        "-d",
        "--payloads-dir",
        help="Directory containing payload YAML files",
    ),
    attack_class: Optional[str] = typer.Option(
        None, "--class", help="Filter by attack class"
    ),
    owasp: Optional[str] = typer.Option(None, "--owasp", help="Filter by OWASP category (e.g. LLM01, LLM06)"),
    tag: Optional[str] = typer.Option(None, "--tag", help="Filter by tag"),
    severity: Optional[str] = typer.Option(None, "--severity", help="Filter by exact severity level"),
    min_severity: Optional[str] = typer.Option(None, "--min-severity", help="Filter by minimum severity level"),
) -> None:
    """List available payloads with optional filtering."""
    try:
        payloads = _loader.load_payloads_dir(
            payloads_dir,
            attack_class=attack_class,
            owasp=owasp,
            tag=tag,
            severity=severity,
            min_severity=min_severity,
        )
    except Exception as e:
        console.print(f"[red]Error loading payloads: {e}[/red]")
        raise typer.Exit(1)

    table = Table(show_header=True)
    table.add_column("ID")
    table.add_column("Class")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Tags")

    for p in payloads:
        table.add_row(
            p.id,
            p.attack_class.value,
            p.severity_if_success.value,
            p.title,
            ", ".join(p.tags),
        )

    console.print(table)
    console.print(f"{len(payloads)} payloads")


# ---------------------------------------------------------------------------
# list-detectors
# ---------------------------------------------------------------------------

@app.command("list-detectors")
def list_detectors() -> None:
    """List all available response detectors."""
    items = _detectors.list_detectors()

    table = Table(show_header=True)
    table.add_column("Name")
    table.add_column("Description")

    for item in items:
        table.add_row(item["name"], item["description"])

    console.print(table)
    console.print(f"{len(items)} detectors")


# ---------------------------------------------------------------------------
# transform
# ---------------------------------------------------------------------------

@app.command("transform")
def transform(
    text: Optional[str] = typer.Argument(None, help="Text to transform"),
    name: Optional[str] = typer.Option(None, "-n", "--name", help="Name of the transform to apply"),
    list_: bool = typer.Option(False, "--list", help="Print all available transform names and exit"),
) -> None:
    """Apply an encoding transform to TEXT."""
    if list_:
        names = list_transforms()
        for n in names:
            console.print(n)
        raise typer.Exit(0)

    if not name:
        console.print("[red]Error: --name/-n is required when not using --list[/red]")
        raise typer.Exit(1)

    if text is None:
        console.print("[red]Error: TEXT argument is required[/red]")
        raise typer.Exit(1)

    try:
        result = apply_transform(text, name)
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)

    console.print(result)


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

@app.command("validate")
def validate(
    target: Optional[Path] = typer.Option(None, "--target", help="Validate a single target YAML file"),
    payload: Optional[Path] = typer.Option(None, "--payload", help="Validate a single payload YAML file"),
    dir_: Optional[Path] = typer.Option(None, "--dir", help="Validate all YAML files in a directory"),
) -> None:
    """Validate target or payload YAML files."""
    if target is None and payload is None and dir_ is None:
        console.print("[red]Error: at least one of --target, --payload, or --dir must be specified[/red]")
        raise typer.Exit(1)

    any_issues = False

    if target is not None:
        issues = _loader.validate_target(target)
        if issues:
            console.print(f"[red]✗ {target}[/red]")
            for issue in issues:
                console.print(f"  [red]{issue}[/red]")
            any_issues = True
        else:
            console.print(f"[green]✓ {target}[/green]")

    if payload is not None:
        issues = _loader.validate_payload(payload)
        if issues:
            console.print(f"[red]✗ {payload}[/red]")
            for issue in issues:
                console.print(f"  [red]{issue}[/red]")
            any_issues = True
        else:
            console.print(f"[green]✓ {payload}[/green]")

    if dir_ is not None:
        import yaml as _yaml

        dir_path = Path(dir_)
        yaml_files = sorted(dir_path.rglob("*.yaml")) + sorted(dir_path.rglob("*.yml"))
        # Deduplicate
        seen: set[Path] = set()
        unique_files: list[Path] = []
        for f in yaml_files:
            resolved = f.resolve()
            if resolved not in seen:
                seen.add(resolved)
                unique_files.append(f)

        for f in unique_files:
            try:
                data = _yaml.safe_load(f.read_text())
            except Exception:
                data = {}

            # Auto-detect type: target has "request" key, payload has "attack_class"
            if isinstance(data, dict) and "request" in data:
                issues = _loader.validate_target(f)
            else:
                issues = _loader.validate_payload(f)

            if issues:
                console.print(f"[red]✗ {f}[/red]")
                for issue in issues:
                    console.print(f"  [red]{issue}[/red]")
                any_issues = True
            else:
                console.print(f"[green]✓ {f}[/green]")

    if any_issues:
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# coverage
# ---------------------------------------------------------------------------

@app.command("coverage")
def coverage(
    payloads_dir: Path = typer.Option(
        Path("payloads"),
        "-d",
        "--payloads-dir",
        help="Directory containing payload YAML files",
    ),
) -> None:
    """Show OWASP LLM Top 10 coverage across payloads."""
    try:
        from airt import owasp as _owasp
    except ImportError:
        console.print("[red]Error: airt.owasp module is not yet available[/red]")
        raise typer.Exit(1)

    try:
        payloads = _loader.load_payloads_dir(payloads_dir)
    except Exception as e:
        console.print(f"[red]Error loading payloads: {e}[/red]")
        raise typer.Exit(1)

    entries = _owasp.coverage_report(payloads)

    table = Table(show_header=True)
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Attack Classes")
    table.add_column("Payloads")
    table.add_column("Status")

    covered_count = 0
    for entry in entries:
        if entry.covered:
            covered_count += 1
            status = "[green]covered[/green]"
        else:
            status = "[red]not covered[/red]"

        table.add_row(
            entry.id,
            entry.name,
            ", ".join(entry.attack_classes),
            str(entry.payload_count),
            status,
        )

    console.print(table)
    console.print(f"{covered_count}/10 OWASP categories covered")
