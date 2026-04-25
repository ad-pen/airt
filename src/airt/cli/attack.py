from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

from airt import loader
from airt.adapters.http import HttpAdapter
from airt.engine import run_chain
from airt.models import Payload, Status
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


def _apply_transform_to_payload(payload: Payload, transform_name: str) -> Payload:
    from airt.transforms import apply_transform

    new_turns = [
        turn.model_copy(update={"user": apply_transform(turn.user, transform_name)})
        for turn in payload.turns
    ]
    return payload.model_copy(update={"turns": new_turns})


async def _run_one(
    target_path: Path,
    payload_path: Path,
    db: Path | None,
    transform: str | None = None,
    fail_on_success: bool = False,
) -> None:
    target = loader.load_target(target_path)
    payload = loader.load_payload(payload_path)
    if transform:
        payload = _apply_transform_to_payload(payload, transform)

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

    if fail_on_success and session.overall_status == Status.LIKELY_SUCCESS:
        raise typer.Exit(1)


async def _run_suite(
    target_path: Path,
    payloads_dir: Path,
    db: Path | None,
    transform: str | None = None,
    attack_class: str | None = None,
    owasp: str | None = None,
    tag: str | None = None,
    min_severity: str | None = None,
    fail_on_success: bool = False,
    concurrency: int = 1,
) -> None:
    target = loader.load_target(target_path)
    payloads = loader.load_payloads_dir(
        payloads_dir,
        attack_class=attack_class,
        owasp=owasp,
        tag=tag,
        min_severity=min_severity,
    )
    if not payloads:
        console.print(f"[red]No payloads found in {payloads_dir}[/red]")
        raise typer.Exit(1)

    if transform:
        payloads = [_apply_transform_to_payload(p, transform) for p in payloads]

    adapter = HttpAdapter(target)
    storage = Storage(db)
    any_success = False
    sem = asyncio.Semaphore(concurrency)

    async def _run_one(p):
        async with sem:
            return await run_chain(adapter=adapter, target=target, payload=p)

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Running suite...", total=len(payloads))

            if concurrency == 1:
                for p in payloads:
                    session = await run_chain(adapter=adapter, target=target, payload=p)
                    storage.save_session(session)
                    if session.overall_status == Status.LIKELY_SUCCESS:
                        any_success = True
                    progress.advance(task)
            else:
                tasks = [asyncio.create_task(_run_one(p)) for p in payloads]
                for coro in asyncio.as_completed(tasks):
                    session = await coro
                    storage.save_session(session)
                    if session.overall_status == Status.LIKELY_SUCCESS:
                        any_success = True
                    progress.advance(task)
    finally:
        await adapter.close()
        storage.close()

    if fail_on_success and any_success:
        console.print("[bold red]Failing: at least one payload succeeded[/bold red]")
        raise typer.Exit(1)


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
    transform: Optional[str] = typer.Option(
        None, "--transform", help="Apply encoding transform to user messages",
    ),
    fail_on_success: bool = typer.Option(
        False, "--fail-on-success", help="Exit 1 if payload succeeds (for CI)",
    ),
) -> None:
    """Run a single payload against a target."""
    asyncio.run(_run_one(target, payload, db, transform=transform, fail_on_success=fail_on_success))


@app.command("run-suite")
def run_suite(
    target: Path = typer.Option(
        ..., "-t", "--target", exists=True, help="Target YAML config",
    ),
    payloads_dir: Path = typer.Option(
        ..., "-d", "--payloads-dir", exists=True, file_okay=False, help="Directory of payload YAMLs",
    ),
    db: Path | None = typer.Option(None, "--db"),
    transform: Optional[str] = typer.Option(
        None, "--transform", help="Apply encoding transform to all payloads",
    ),
    attack_class: Optional[str] = typer.Option(
        None, "--attack-class", help="Filter: only run this attack class",
    ),
    owasp: Optional[str] = typer.Option(
        None, "--owasp", help="Filter: only run payloads for this OWASP category (e.g. LLM01)",
    ),
    tag: Optional[str] = typer.Option(
        None, "--tag", help="Filter: only run payloads with this tag",
    ),
    min_severity: Optional[str] = typer.Option(
        None, "--min-severity", help="Filter: minimum severity (info/low/medium/high/critical)",
    ),
    fail_on_success: bool = typer.Option(
        False, "--fail-on-success", help="Exit 1 if any payload succeeds (for CI)",
    ),
    concurrency: int = typer.Option(
        1, "-c", "--concurrency",
        help="Number of payloads to run concurrently (default: 1)",
        min=1, max=50,
    ),
) -> None:
    """Run all payloads in a directory against a target."""
    asyncio.run(
        _run_suite(
            target, payloads_dir, db,
            transform=transform,
            attack_class=attack_class,
            owasp=owasp,
            tag=tag,
            min_severity=min_severity,
            fail_on_success=fail_on_success,
            concurrency=concurrency,
        )
    )
