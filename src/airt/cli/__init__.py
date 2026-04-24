from __future__ import annotations

import typer

from airt.cli.attack import app as attack_app
from airt.cli.session import app as session_app
from airt.cli.reporting import app as reporting_app

app = typer.Typer(
    help="airt — AI Red Teaming Workbench",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)

# Register all sub-app commands at the top level (no prefix).
app.add_typer(attack_app)
app.add_typer(session_app)
app.add_typer(reporting_app)

if __name__ == "__main__":
    app()
