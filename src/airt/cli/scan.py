"""Quick-start scan command — point at a URL, get results."""
from __future__ import annotations

import asyncio
import importlib.resources
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

from airt import loader
from airt.adapters.http import HttpAdapter
from airt.engine import run_chain
from airt.models import Status
from airt.presets import build_target, list_presets
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


def _bundled_payloads_dir() -> Path:
    pkg_root = Path(__file__).resolve().parent.parent.parent.parent
    candidate = pkg_root / "payloads"
    if candidate.is_dir():
        return candidate
    cwd_candidate = Path.cwd() / "payloads"
    if cwd_candidate.is_dir():
        return cwd_candidate
    raise typer.BadParameter(
        "Cannot find bundled payloads directory. "
        "Run from the airt project root or pass --payloads-dir."
    )


async def _run_scan(
    url: str,
    preset: str | None,
    api_key: str,
    model: str | None,
    payloads_dir: Path | None,
    db: Path | None,
    attack_class: str | None,
    tag: str | None,
    min_severity: str | None,
    fail_on_success: bool,
    output: Path | None,
) -> None:
    target = build_target(url, preset=preset, api_key=api_key, model=model)

    console.print(f"[bold]Target:[/bold]  {target.name}")
    console.print(f"[bold]URL:[/bold]     {url}")
    if preset:
        console.print(f"[bold]Preset:[/bold]  {preset}")
    console.print()

    pdir = payloads_dir or _bundled_payloads_dir()
    payloads = loader.load_payloads_dir(
        pdir,
        attack_class=attack_class,
        tag=tag,
        min_severity=min_severity,
    )
    if not payloads:
        console.print("[red]No payloads matched the given filters.[/red]")
        raise typer.Exit(1)

    console.print(f"Loaded [bold]{len(payloads)}[/bold] payloads from {pdir}\n")

    adapter = HttpAdapter(target)
    storage = Storage(db)
    counts: dict[Status, int] = {s: 0 for s in Status}
    results = []

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=len(payloads))
            for p in payloads:
                session = await run_chain(adapter=adapter, target=target, payload=p)
                storage.save_session(session)
                counts[session.overall_status] += 1
                results.append(session)
                progress.advance(task)
    finally:
        await adapter.close()
        storage.close()

    console.print()

    hits = [s for s in results if s.overall_status in (Status.LIKELY_SUCCESS, Status.FLAGS_PRESENT)]
    if hits:
        hit_table = Table(title="Findings")
        hit_table.add_column("Payload", style="bold")
        hit_table.add_column("Class")
        hit_table.add_column("Status")
        hit_table.add_column("Key Evidence")
        for s in hits:
            style = STATUS_STYLES.get(s.overall_status, "")
            evidence = ""
            for t in s.turns:
                for f in t.flags:
                    evidence = f.evidence[:60]
                    break
                if evidence:
                    break
            hit_table.add_row(
                s.payload_title,
                s.attack_class.value,
                f"[{style}]{s.overall_status.value}[/{style}]",
                evidence,
            )
        console.print(hit_table)
        console.print()

    summary = Table(title="Summary")
    summary.add_column("Status")
    summary.add_column("Count", justify="right")
    for status, count in counts.items():
        if count > 0:
            style = STATUS_STYLES.get(status, "")
            summary.add_row(f"[{style}]{status.value}[/{style}]", str(count))
    summary.add_row("[bold]Total[/bold]", str(len(payloads)))
    console.print(summary)

    if output:
        _write_results_file(output, results, target)

    success_count = counts[Status.LIKELY_SUCCESS]
    if success_count:
        console.print(
            f"\n[bold red]{success_count} payload(s) likely succeeded[/bold red] — review findings above."
        )

    if fail_on_success and counts[Status.LIKELY_SUCCESS] > 0:
        raise typer.Exit(1)


def _write_results_file(output: Path, results, target) -> None:
    import json

    data = {
        "target": target.name,
        "url": target.request.url,
        "total": len(results),
        "findings": [
            {
                "payload_id": s.payload_id,
                "title": s.payload_title,
                "attack_class": s.attack_class.value,
                "status": s.overall_status.value,
                "turns": len(s.turns),
            }
            for s in results
            if s.overall_status in (Status.LIKELY_SUCCESS, Status.FLAGS_PRESENT)
        ],
        "summary": {s.value: 0 for s in Status},
    }
    for s in results:
        data["summary"][s.overall_status.value] += 1

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2))
    console.print(f"\n[green]Results written to {output}[/green]")


@app.command("scan")
def scan(
    url: str = typer.Argument(..., help="Target endpoint URL"),
    preset: Optional[str] = typer.Option(
        None, "--preset", "-P",
        help="API preset: openai, anthropic, ollama, azure, generic",
    ),
    api_key: str = typer.Option(
        "", "--api-key", "-k",
        help="API key / bearer token for the target",
    ),
    model: Optional[str] = typer.Option(
        None, "--model", "-m",
        help="Override the model name in the request body",
    ),
    payloads_dir: Optional[Path] = typer.Option(
        None, "-d", "--payloads-dir",
        help="Payload directory (default: bundled payloads)",
    ),
    db: Optional[Path] = typer.Option(None, "--db"),
    attack_class: Optional[str] = typer.Option(
        None, "--attack-class",
        help="Filter: only run this attack class",
    ),
    tag: Optional[str] = typer.Option(
        None, "--tag",
        help="Filter: only run payloads with this tag",
    ),
    min_severity: Optional[str] = typer.Option(
        None, "--min-severity",
        help="Filter: minimum severity (info/low/medium/high/critical)",
    ),
    fail_on_success: bool = typer.Option(
        False, "--fail-on-success",
        help="Exit 1 if any payload succeeds (for CI)",
    ),
    output: Optional[Path] = typer.Option(
        None, "-o", "--output",
        help="Write JSON results to file",
    ),
    list_presets_flag: bool = typer.Option(
        False, "--list-presets",
        help="List available presets and exit",
    ),
) -> None:
    """Scan an AI endpoint. Just give it a URL.

    \b
    Examples:
      airt scan https://api.openai.com/v1/chat/completions -k $OPENAI_API_KEY
      airt scan http://localhost:11434/api/chat --preset ollama
      airt scan https://my-app.com/api/chat --preset generic
      airt scan https://api.openai.com/v1/chat/completions -k $KEY --attack-class jailbreak
      airt scan https://api.openai.com/v1/chat/completions -k $KEY --min-severity high
    """
    if list_presets_flag:
        for name in list_presets():
            console.print(name)
        raise typer.Exit(0)

    asyncio.run(
        _run_scan(
            url, preset, api_key, model, payloads_dir, db,
            attack_class, tag, min_severity, fail_on_success, output,
        )
    )
