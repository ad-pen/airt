from __future__ import annotations

import typer

from airt import __version__

app = typer.Typer()


@app.command("version")
def version_cmd() -> None:
    """Print airt version."""
    typer.echo(f"airt {__version__}")
