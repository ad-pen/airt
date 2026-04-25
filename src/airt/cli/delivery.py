from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

from airt import loader
from airt.adapters.http import HttpAdapter
from airt.engine import run_chain
from airt.models import Status, Target, TargetRequest
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


# ---------------------------------------------------------------------------
# demo
# ---------------------------------------------------------------------------


async def _run_demo(
    target_path: Path | None,
    port: int,
    payloads_dir: Path,
    db: Path | None,
) -> None:
    from airt.demo_bot import AcmeBotServer

    server = AcmeBotServer(port=port)
    bot_url = server.start()
    console.print(f"[bold green]AcmeBot started at[/bold green] {bot_url}")

    if target_path:
        target = loader.load_target(target_path)
        target = target.model_copy(
            update={"request": target.request.model_copy(update={"url": bot_url})}
        )
    else:
        target = Target(
            name="acmebot-demo",
            request=TargetRequest(url=bot_url, history_format="openai"),
        )

    payloads = loader.load_payloads_dir(payloads_dir)
    if not payloads:
        server.stop()
        console.print(f"[red]No payloads found in {payloads_dir}[/red]")
        raise typer.Exit(1)

    adapter = HttpAdapter(target)
    storage = Storage(db)
    counts = {s: 0 for s in Status}

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Running demo...", total=len(payloads))
            for p in payloads:
                session = await run_chain(adapter=adapter, target=target, payload=p)
                storage.save_session(session)
                counts[session.overall_status] += 1
                progress.advance(task)
    finally:
        await adapter.close()
        storage.close()
        server.stop()

    table = Table(title="Demo Results")
    table.add_column("Status")
    table.add_column("Count")
    for status, count in counts.items():
        if count > 0:
            style = STATUS_STYLES.get(status, "")
            table.add_row(f"[{style}]{status.value}[/{style}]", str(count))
    table.add_row("[bold]Total[/bold]", str(len(payloads)))
    console.print(table)


@app.command("demo")
def demo(
    target: Optional[Path] = typer.Option(
        None, "-t", "--target", help="Target YAML config (optional, overrides URL)"
    ),
    port: int = typer.Option(0, "--port", help="AcmeBot port (0 = random)"),
    payloads_dir: Path = typer.Option(
        Path("payloads"), "-d", "--payloads-dir", help="Payload directory"
    ),
    db: Optional[Path] = typer.Option(None, "--db"),
) -> None:
    """Run demo attacks against the built-in AcmeBot."""
    asyncio.run(_run_demo(target, port, payloads_dir, db))


# ---------------------------------------------------------------------------
# dynamic
# ---------------------------------------------------------------------------


async def _run_dynamic(
    target_path: Path,
    goal: str,
    api_base: str,
    model: str,
    api_key: str,
    max_turns: int,
    db: Path | None,
) -> None:
    from airt.dynamic import DynamicChain
    from airt.models import DynamicConfig

    target = loader.load_target(target_path)
    config = DynamicConfig(
        api_base=api_base, model=model, api_key=api_key, max_turns=max_turns
    )
    adapter = HttpAdapter(target)
    chain = DynamicChain(adapter, config)

    try:
        session = await chain.run(goal, target_name=target.name, max_turns=max_turns)
    finally:
        await chain.close()
        await adapter.close()

    storage = Storage(db)
    try:
        storage.save_session(session)
    finally:
        storage.close()

    _print_session_summary(session)


@app.command("dynamic")
def dynamic(
    goal: str = typer.Option(..., "--goal", help="Attack goal description"),
    target: Path = typer.Option(
        ..., "-t", "--target", exists=True, help="Target YAML config"
    ),
    attacker_api_base: str = typer.Option(
        ..., "--attacker-api-base", help="Attacker LLM API base URL"
    ),
    attacker_model: str = typer.Option(
        ..., "--attacker-model", help="Attacker LLM model name"
    ),
    attacker_api_key: str = typer.Option("", "--attacker-api-key", help="Attacker LLM API key"),
    max_turns: int = typer.Option(10, "--max-turns", help="Maximum conversation turns"),
    db: Optional[Path] = typer.Option(None, "--db"),
) -> None:
    """Run dynamic LLM-driven adaptive attacks."""
    asyncio.run(
        _run_dynamic(target, goal, attacker_api_base, attacker_model, attacker_api_key, max_turns, db)
    )


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------


@app.command("serve")
def serve(
    payload: str = typer.Argument(..., help="Payload text to embed in the page"),
    port: int = typer.Option(0, "--port", help="Port (0 = random)"),
    template: str = typer.Option("article", "--template", help="Page template: article, email, documentation, raw"),
) -> None:
    """Serve a poisoned page for indirect injection testing."""
    from airt.adapters.url_embed import UrlEmbedServer

    srv = UrlEmbedServer(payload, template=template, port=port)
    url = srv.start()
    console.print(f"[bold green]Serving poisoned page at:[/bold green] {url}")
    console.print("[dim]Point an AI agent at this URL. Ctrl+C to stop.[/dim]")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        hits = len(srv.callback_log)
        srv.stop()
        console.print(f"\nStopped. Callback hits: {hits}")


# ---------------------------------------------------------------------------
# email
# ---------------------------------------------------------------------------


@app.command("email")
def email_cmd(
    to: str = typer.Option(..., "--to", help="Recipient email address"),
    from_addr: str = typer.Option(..., "--from", help="Sender email address"),
    subject: str = typer.Option("Test Email", "--subject", help="Email subject"),
    payload: str = typer.Option(..., "--payload", help="Payload text"),
    smtp_host: str = typer.Option(..., "--smtp-host", help="SMTP server hostname"),
    smtp_port: int = typer.Option(587, "--smtp-port", help="SMTP server port"),
    method: str = typer.Option("body", "--method", help="Injection method: body, html-hidden, attachment, header"),
) -> None:
    """Send a crafted email for AI email assistant testing."""
    from airt.adapters.smtp import EmailConfig, SmtpAdapter

    config = EmailConfig(
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        from_address=from_addr,
        to_address=to,
        subject=subject,
    )
    adapter = SmtpAdapter(config)
    try:
        asyncio.run(adapter.send_payload(payload, method=method))
        console.print("[green]Email sent successfully[/green]")
    except Exception as e:
        console.print(f"[red]Failed to send email: {e}[/red]")
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# craft-doc
# ---------------------------------------------------------------------------


@app.command("craft-doc")
def craft_doc(
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file path"),
    visible: Optional[str] = typer.Option(None, "--visible", help="Visible document text"),
    payload: Optional[str] = typer.Option(None, "--payload", help="Hidden payload text"),
    method: str = typer.Option("pdf-white-on-white", "--method", help="Injection method"),
    list_methods: bool = typer.Option(False, "--list-methods", help="List available methods"),
) -> None:
    """Create a poisoned document with hidden injection payloads."""
    from airt.adapters.doc_inject import craft_document, list_methods as _list_methods

    if list_methods:
        for m in _list_methods():
            console.print(m)
        raise typer.Exit(0)

    if not output or not visible or not payload:
        console.print("[red]--output, --visible, and --payload are required[/red]")
        raise typer.Exit(1)

    try:
        result = craft_document(visible, payload, output, method=method)
        console.print(f"[green]Created[/green] {result}")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# import-curl
# ---------------------------------------------------------------------------


@app.command("import-curl")
def import_curl(
    curl_command: str = typer.Argument(..., help="curl command string"),
    output: Path = typer.Option(..., "-o", "--output", help="Output YAML file path"),
) -> None:
    """Import a target config from a curl command."""
    from airt.importers import parse_curl, target_to_yaml

    try:
        target = parse_curl(curl_command)
    except Exception as e:
        console.print(f"[red]Failed to parse curl command: {e}[/red]")
        raise typer.Exit(1)

    yaml_text = target_to_yaml(target)
    output.write_text(yaml_text)
    console.print(f"[green]Wrote target[/green] [bold]{target.name}[/bold] → {output}")


# ---------------------------------------------------------------------------
# import-har
# ---------------------------------------------------------------------------


@app.command("import-har")
def import_har(
    har_file: Path = typer.Argument(..., help="HAR file path", exists=True),
    output_dir: Path = typer.Option(..., "-o", "--output-dir", help="Output directory"),
    filter_url: Optional[str] = typer.Option(None, "--filter-url", help="Only include URLs containing this substring"),
) -> None:
    """Import target configs from an HTTP Archive (HAR) file."""
    from airt.importers import parse_har, target_to_yaml

    try:
        har_json = json.loads(har_file.read_text())
    except Exception as e:
        console.print(f"[red]Failed to read HAR file: {e}[/red]")
        raise typer.Exit(1)

    targets = parse_har(har_json)
    if filter_url:
        targets = [t for t in targets if filter_url in t.request.url]

    if not targets:
        console.print("[yellow]No matching targets found in HAR file[/yellow]")
        raise typer.Exit(0)

    output_dir.mkdir(parents=True, exist_ok=True)
    for t in targets:
        fname = t.name.replace(" ", "-").lower() + ".yaml"
        (output_dir / fname).write_text(target_to_yaml(t))

    console.print(f"[green]Wrote {len(targets)} target(s)[/green] → {output_dir}")


# ---------------------------------------------------------------------------
# recon
# ---------------------------------------------------------------------------


async def _run_recon(target_path: Path) -> None:
    from airt.recon import Recon

    target = loader.load_target(target_path)
    recon = Recon(target)
    try:
        result = await recon.run()
    finally:
        await recon.close()

    console.rule(f"[bold]Recon: {result.target_name}[/bold]")
    console.print(f"Endpoint: {result.endpoint}\n")

    table = Table(title="Probes")
    table.add_column("Probe")
    table.add_column("Finding")
    table.add_column("Response (truncated)")
    for probe in result.probes:
        table.add_row(
            probe["name"],
            probe["finding"],
            probe["response"][:80] + ("..." if len(probe["response"]) > 80 else ""),
        )
    console.print(table)

    console.print("\n[bold]Summary[/bold]")
    for key, val in result.summary.items():
        console.print(f"  {key}: {val}")


@app.command("recon")
def recon(
    target: Path = typer.Option(
        ..., "-t", "--target", exists=True, help="Target YAML config"
    ),
) -> None:
    """Run reconnaissance probes against a target."""
    asyncio.run(_run_recon(target))


# ---------------------------------------------------------------------------
# fuzz
# ---------------------------------------------------------------------------


@app.command("fuzz")
def fuzz_cmd(
    text: str = typer.Argument(..., help="Text to fuzz"),
    strategy: Optional[str] = typer.Option(None, "-s", "--strategy", help="Strategy name (omit for all)"),
    list_strategies: bool = typer.Option(False, "--list", help="List available strategies"),
) -> None:
    """Apply fuzzing mutations to payload text."""
    from airt.fuzzer import fuzz, fuzz_all, list_fuzzers

    if list_strategies:
        for name in list_fuzzers():
            console.print(name)
        raise typer.Exit(0)

    if strategy:
        try:
            result = fuzz(text, strategy)
            console.print(result)
        except ValueError as e:
            console.print(f"[red]{e}[/red]")
            raise typer.Exit(1)
    else:
        results = fuzz_all(text)
        table = Table(title="Fuzz Results")
        table.add_column("Strategy")
        table.add_column("Result")
        for name, result in results.items():
            table.add_row(name, result)
        console.print(table)
