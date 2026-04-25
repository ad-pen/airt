from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from airt import report
from airt.storage import Storage

app = typer.Typer()
console = Console()


@app.command("report")
def report_cmd(
    session_id: str | None = typer.Option(None, "-s", "--session", help="Session ID to report"),
    all_findings: bool = typer.Option(False, "-a", "--all", help="Report all findings"),
    out: Path | None = typer.Option(None, "-o", "--out", help="Output file path (.md or .pdf)"),
    db: Path | None = typer.Option(None, "--db"),
) -> None:
    """Export a markdown or PDF report for a session or all findings."""
    is_pdf = out is not None and out.suffix.lower() == ".pdf"

    if is_pdf and not all_findings:
        console.print("[red]PDF output requires --all/-a flag[/red]")
        raise typer.Exit(1)

    storage = Storage(db)
    try:
        if all_findings:
            findings_list = storage.list_findings()
            if is_pdf:
                from airt.pdf_report import render_pdf_report

                sessions_map = {}
                for f in findings_list:
                    s = storage.get_session(f.session_id)
                    if s:
                        sessions_map[s.id] = s
                render_pdf_report(findings_list, sessions_map, str(out))
                console.print(f"[green]wrote PDF report[/green] {out}")
                return

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
