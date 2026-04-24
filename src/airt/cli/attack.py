from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console

from airt import loader
from airt.adapters.http import HttpAdapter
from airt.engine import run_chain
from airt.models import Status
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
