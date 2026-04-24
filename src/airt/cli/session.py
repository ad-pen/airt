from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from airt import report
from airt.models import Severity, Status
from airt.storage import Storage

app = typer.Typer()
console = Console()

STATUS_STYLES = {
    Status.LIKELY_SUCCESS: "bold red",
    Status.FLAGS_PRESENT: "yellow",
    Status.DEFLECTED: "dim",
    Status.NO_SIGNAL: "dim",
    Status.ERROR: "bold magenta",
}


@app.command("list", short_help="List recent sessions")
def list_sessions(
    limit: int = typer.Option(50, "-n", "--limit", help="Max sessions to show"),
    db: Path | None = typer.Option(None, "--db"),
) -> None:
    """List recent attack sessions."""
    storage = Storage(db)
    try:
        sessions = storage.list_sessions(limit=limit)
    finally:
        storage.close()

    table = Table(show_header=True)
    table.add_column("session")
    table.add_column("payload")
    table.add_column("target")
    table.add_column("status")
    table.add_column("started")
    for s in sessions:
        style = STATUS_STYLES.get(s.overall_status, "")
        table.add_row(
            s.id,
            s.payload_id,
            s.target_name,
            f"[{style}]{s.overall_status.value}[/{style}]",
            s.started_at.isoformat(timespec="seconds"),
        )
    console.print(table)


@app.command()
def show(
    session_id: str = typer.Argument(..., help="Session ID to display"),
    db: Path | None = typer.Option(None, "--db"),
) -> None:
    """Show a session transcript."""
    storage = Storage(db)
    try:
        s = storage.get_session(session_id)
    finally:
        storage.close()
    if not s:
        console.print(f"[red]session {session_id} not found[/red]")
        raise typer.Exit(1)
    console.print(report.render_session(s))


@app.command()
def promote(
    session_id: str = typer.Argument(..., help="Session ID to promote"),
    title: str = typer.Option(..., "-t", "--title", help="Finding title"),
    severity: Severity = typer.Option(Severity.MEDIUM, "-s", "--severity", help="Finding severity"),
    notes: str = typer.Option("", "-n", "--notes", help="Additional notes"),
    db: Path | None = typer.Option(None, "--db"),
) -> None:
    """Promote a session into a confirmed finding."""
    storage = Storage(db)
    try:
        s = storage.get_session(session_id)
        if not s:
            console.print(f"[red]session {session_id} not found[/red]")
            raise typer.Exit(1)
        f = storage.promote_to_finding(
            session_id,
            title=title,
            severity=severity,
            attack_class=s.attack_class,
            notes=notes,
        )
    finally:
        storage.close()
    console.print(f"[green]finding[/green] [cyan]{f.id}[/cyan] promoted")


@app.command()
def findings(
    db: Path | None = typer.Option(None, "--db"),
) -> None:
    """List confirmed findings."""
    storage = Storage(db)
    try:
        items = storage.list_findings()
    finally:
        storage.close()
    table = Table(show_header=True)
    table.add_column("id")
    table.add_column("severity")
    table.add_column("class")
    table.add_column("title")
    table.add_column("session")
    for f in items:
        table.add_row(f.id, f.severity.value, f.attack_class.value, f.title, f.session_id)
    console.print(table)
