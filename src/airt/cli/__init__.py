from __future__ import annotations

import typer

from airt.cli.attack import app as attack_app
from airt.cli.delivery import app as delivery_app
from airt.cli.discovery import app as discovery_app
from airt.cli.meta import app as meta_app
from airt.cli.reporting import app as reporting_app
from airt.cli.scan import app as scan_app
from airt.cli.session import app as session_app

app = typer.Typer(
    help="airt — AI Red Teaming Workbench",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)

app.add_typer(attack_app)
app.add_typer(scan_app)
app.add_typer(session_app)
app.add_typer(reporting_app)
app.add_typer(discovery_app)
app.add_typer(delivery_app)
app.add_typer(meta_app)

if __name__ == "__main__":
    app()
