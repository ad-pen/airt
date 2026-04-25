from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from airt import report
from airt.diff import diff_sessions
from airt.models import JudgeConfig, Severity, Status
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


@app.command("diff")
def diff_cmd(
    old_db: Path = typer.Argument(..., help="Baseline scan database", exists=True),
    new_db: Path = typer.Argument(..., help="New scan database to compare", exists=True),
) -> None:
    """Compare two scan databases to show regressions and fixes."""
    old_storage = Storage(old_db)
    new_storage = Storage(new_db)
    try:
        old_sessions = old_storage.list_sessions(limit=10000)
        new_sessions = new_storage.list_sessions(limit=10000)
    finally:
        old_storage.close()
        new_storage.close()

    result = diff_sessions(old_sessions, new_sessions)

    if result.regressions:
        console.print(f"\n[bold red]Regressions ({len(result.regressions)}):[/bold red]")
        reg_table = Table(show_header=True)
        reg_table.add_column("Payload")
        reg_table.add_column("Old Status")
        reg_table.add_column("New Status")
        for e in result.regressions:
            reg_table.add_row(
                e.payload_id,
                e.old_status.value if e.old_status else "-",
                f"[bold red]{e.new_status.value}[/bold red]" if e.new_status else "-",
            )
        console.print(reg_table)

    if result.fixes:
        console.print(f"\n[bold green]Fixes ({len(result.fixes)}):[/bold green]")
        fix_table = Table(show_header=True)
        fix_table.add_column("Payload")
        fix_table.add_column("Old Status")
        fix_table.add_column("New Status")
        for e in result.fixes:
            fix_table.add_row(
                e.payload_id,
                f"[red]{e.old_status.value}[/red]" if e.old_status else "-",
                f"[green]{e.new_status.value}[/green]" if e.new_status else "-",
            )
        console.print(fix_table)

    if result.added:
        console.print(f"\n[cyan]New payloads ({len(result.added)}):[/cyan]")
        for e in result.added:
            style = STATUS_STYLES.get(e.new_status, "") if e.new_status else ""
            console.print(f"  + {e.payload_id} [{style}]{e.new_status.value if e.new_status else '-'}[/{style}]")

    if result.removed:
        console.print(f"\n[dim]Removed payloads ({len(result.removed)}):[/dim]")
        for e in result.removed:
            console.print(f"  - {e.payload_id}")

    if result.changed:
        console.print(f"\n[yellow]Other changes ({len(result.changed)}):[/yellow]")
        for e in result.changed:
            console.print(
                f"  ~ {e.payload_id}: "
                f"{e.old_status.value if e.old_status else '-'} → "
                f"{e.new_status.value if e.new_status else '-'}"
            )

    summary = Table(title="Summary")
    summary.add_column("Category")
    summary.add_column("Count", justify="right")
    summary.add_row("[red]Regressions[/red]", str(len(result.regressions)))
    summary.add_row("[green]Fixes[/green]", str(len(result.fixes)))
    summary.add_row("New payloads", str(len(result.added)))
    summary.add_row("Removed", str(len(result.removed)))
    summary.add_row("Other changes", str(len(result.changed)))
    summary.add_row("[dim]Unchanged[/dim]", str(len(result.unchanged)))
    summary.add_row("[bold]Total[/bold]", str(len(result.entries)))
    console.print(summary)


# ---------------------------------------------------------------
# judge
# ---------------------------------------------------------------

VERDICT_STYLES = {
    "success": "bold red",
    "partial": "yellow",
    "failure": "dim",
    "unclear": "magenta",
}


async def _run_judge(
    judge_config: JudgeConfig,
    sessions: list,
    goal: str,
    min_confidence: float,
) -> list[dict]:
    from airt.judge import Judge

    judge = Judge(judge_config)
    results = []
    try:
        for session in sessions:
            for turn in session.turns:
                if not turn.assistant:
                    continue
                verdict = await judge.evaluate(
                    goal=goal or session.payload_title,
                    user_turn=turn.user,
                    assistant_response=turn.assistant,
                )
                verdict["session_id"] = session.id
                verdict["payload_id"] = session.payload_id
                verdict["turn_idx"] = turn.idx
                results.append(verdict)
    finally:
        await judge.close()
    return results


@app.command("judge")
def judge_cmd(
    session_id: Optional[str] = typer.Argument(
        None, help="Session ID to judge (omit for all ambiguous sessions)",
    ),
    api_base: str = typer.Option(
        ..., "--api-base", help="Judge LLM API base URL (e.g. https://api.openai.com)",
    ),
    model: str = typer.Option(
        ..., "--model", help="Judge model name (e.g. gpt-4o)",
    ),
    api_key: str = typer.Option(
        "", "--api-key", "-k", help="API key for the judge LLM",
    ),
    goal: str = typer.Option(
        "", "--goal", "-g", help="Attack goal description (default: payload title)",
    ),
    min_confidence: float = typer.Option(
        0.0, "--min-confidence", help="Only show verdicts above this confidence",
    ),
    status_filter: Optional[str] = typer.Option(
        None, "--status",
        help="Filter sessions by status (e.g. flags-present, no-signal)",
    ),
    db: Optional[Path] = typer.Option(None, "--db"),
) -> None:
    """Use an LLM to triage ambiguous scan results.

    \b
    Evaluates attack transcripts with a judge LLM to determine whether
    ambiguous results (FLAGS_PRESENT, NO_SIGNAL) are true positives.

    \b
    Examples:
      airt judge --api-base https://api.openai.com --model gpt-4o -k $KEY
      airt judge sess-abc123 --api-base https://api.openai.com --model gpt-4o -k $KEY
      airt judge --status flags-present --api-base https://api.openai.com --model gpt-4o -k $KEY
    """
    config = JudgeConfig(api_base=api_base, api_key=api_key, model=model)

    storage = Storage(db)
    try:
        if session_id:
            s = storage.get_session(session_id)
            if not s:
                console.print(f"[red]session {session_id} not found[/red]")
                raise typer.Exit(1)
            sessions = [s]
        else:
            all_sessions = storage.list_sessions(limit=10000)
            if status_filter:
                try:
                    target_status = Status(status_filter)
                except ValueError:
                    console.print(f"[red]invalid status: {status_filter}[/red]")
                    raise typer.Exit(1)
                sessions = [s for s in all_sessions if s.overall_status == target_status]
            else:
                sessions = [
                    s for s in all_sessions
                    if s.overall_status in (Status.FLAGS_PRESENT, Status.NO_SIGNAL)
                ]
    finally:
        storage.close()

    if not sessions:
        console.print("[dim]No sessions to judge.[/dim]")
        return

    console.print(f"Judging [bold]{len(sessions)}[/bold] session(s)...\n")

    verdicts = asyncio.run(
        _run_judge(config, sessions, goal, min_confidence)
    )

    filtered = [v for v in verdicts if v["confidence"] >= min_confidence]

    if not filtered:
        console.print("[dim]No verdicts above confidence threshold.[/dim]")
        return

    table = Table(title="Judge Verdicts")
    table.add_column("Session")
    table.add_column("Payload")
    table.add_column("Turn")
    table.add_column("Verdict")
    table.add_column("Confidence")
    table.add_column("Reasoning")

    for v in filtered:
        style = VERDICT_STYLES.get(v["verdict"], "")
        table.add_row(
            v["session_id"],
            v["payload_id"],
            str(v["turn_idx"]),
            f"[{style}]{v['verdict']}[/{style}]",
            f"{v['confidence']:.0%}",
            v["reasoning"][:80],
        )

    console.print(table)

    counts = {}
    for v in filtered:
        counts[v["verdict"]] = counts.get(v["verdict"], 0) + 1

    console.print()
    summary = Table(title="Summary")
    summary.add_column("Verdict")
    summary.add_column("Count", justify="right")
    for verdict, count in sorted(counts.items()):
        style = VERDICT_STYLES.get(verdict, "")
        summary.add_row(f"[{style}]{verdict}[/{style}]", str(count))
    console.print(summary)

    successes = counts.get("success", 0)
    partials = counts.get("partial", 0)
    if successes or partials:
        console.print(
            f"\n[bold]{successes} success, {partials} partial[/bold] — "
            "review and `airt promote` confirmed findings."
        )
