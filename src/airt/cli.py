from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from airt import loader, report
from airt.adapters.http import HttpAdapter
from airt.engine import run_chain
from airt.models import Severity, Status
from airt.storage import Storage

app = typer.Typer(
    help="airt — AI Red Teaming Workbench",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
console = Console()

STATUS_STYLES = {
    Status.LIKELY_SUCCESS: "bold red",
    Status.FLAGS_PRESENT: "yellow",
    Status.DEFLECTED: "dim",
    Status.NO_SIGNAL: "dim",
    Status.ERROR: "bold magenta",
}


async def _run_one(target_path: Path, payload_path: Path, db: Path | None) -> None:
    target = loader.load_target(target_path)
    payload = loader.load_payload(payload_path)
    adapter = HttpAdapter(target)
    try:
        session = await run_chain(adapter=adapter, target=target, payload=payload)
    finally:
        await adapter.close()

    storage = Storage(db)
    try:
        storage.save_session(session)
    finally:
        storage.close()

    _print_session_summary(session)


def _print_session_summary(session) -> None:
    style = STATUS_STYLES.get(session.overall_status, "")
    console.rule(f"[bold]{session.payload_id}[/bold] → [{style}]{session.overall_status.value}[/{style}]")
    console.print(f"session: [cyan]{session.id}[/cyan]  ·  target: {session.target_name}")
    for t in session.turns:
        ts = STATUS_STYLES.get(t.status, "")
        console.print(f"  turn {t.idx} [{ts}]{t.status.value}[/{ts}]  · {t.latency_ms}ms")
        if t.flags:
            for f in t.flags:
                console.print(f"    · [yellow]{f.name}[/yellow] {f.evidence[:80]}")
        if t.error:
            console.print(f"    [red]error:[/red] {t.error}")


@app.command()
def run(
    target: Path = typer.Option(
        ..., "-t", "--target", exists=True, readable=True, help="Target YAML config",
    ),
    payload: Path = typer.Option(
        ..., "-p", "--payload", exists=True, readable=True, help="Payload YAML",
    ),
    db: Path | None = typer.Option(
        None, "--db", help="SQLite DB path (default ~/.airt/airt.db)",
    ),
) -> None:
    """Run a single payload against a target."""
    asyncio.run(_run_one(target, payload, db))


async def _run_suite(target_path: Path, payloads_dir: Path, db: Path | None) -> None:
    target = loader.load_target(target_path)
    payloads = loader.load_payloads_dir(payloads_dir)
    if not payloads:
        console.print(f"[red]No payloads found in {payloads_dir}[/red]")
        raise typer.Exit(1)

    adapter = HttpAdapter(target)
    storage = Storage(db)
    try:
        for p in payloads:
            session = await run_chain(adapter=adapter, target=target, payload=p)
            storage.save_session(session)
            _print_session_summary(session)
    finally:
        await adapter.close()
        storage.close()


@app.command("run-suite")
def run_suite(
    target: Path = typer.Option(
        ..., "-t", "--target", exists=True, help="Target YAML config",
    ),
    payloads_dir: Path = typer.Option(
        ..., "-d", "--payloads-dir", exists=True, file_okay=False, help="Directory of payload YAMLs",
    ),
    db: Path | None = typer.Option(None, "--db"),
) -> None:
    """Run all payloads in a directory against a target."""
    asyncio.run(_run_suite(target, payloads_dir, db))


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


@app.command("report")
def report_cmd(
    session_id: str | None = typer.Option(None, "-s", "--session", help="Session ID to report"),
    all_findings: bool = typer.Option(False, "-a", "--all", help="Report all findings"),
    out: Path | None = typer.Option(None, "-o", "--out", help="Output file path"),
    db: Path | None = typer.Option(None, "--db"),
) -> None:
    """Export a markdown report for a session or all findings."""
    storage = Storage(db)
    try:
        if all_findings:
            findings_list = storage.list_findings()
            pairs = []
            for f in findings_list:
                s = storage.get_session(f.session_id)
                if s:
                    pairs.append((f, s))
            out_text = report.render_report(pairs)
        elif session_id:
            s = storage.get_session(session_id)
            if not s:
                console.print(f"[red]session {session_id} not found[/red]")
                raise typer.Exit(1)
            out_text = report.render_session(s)
        else:
            console.print("[red]specify -s <id> or -a/--all[/red]")
            raise typer.Exit(1)
    finally:
        storage.close()

    if out:
        out.write_text(out_text)
        console.print(f"[green]wrote[/green] {out}")
    else:
        console.print(out_text)


if __name__ == "__main__":
    app()
