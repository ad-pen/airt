"""Tests for CLI flag enhancements on attack and reporting commands."""
from __future__ import annotations

import pytest
from typer.testing import CliRunner

from airt.cli.attack import _apply_transform_to_payload, app as attack_app
from airt.cli.meta import app as meta_app
from airt.cli.reporting import app as reporting_app
from airt.models import AttackClass, Payload, PayloadTurn

runner = CliRunner()


# ---------------------------------------------------------------------------
# _apply_transform_to_payload
# ---------------------------------------------------------------------------


def test_apply_transform_changes_user_messages():
    payload = Payload(
        id="test",
        attack_class=AttackClass.PROMPT_INJECTION,
        title="Test",
        turns=[PayloadTurn(user="Hello world")],
    )
    result = _apply_transform_to_payload(payload, "base64")
    assert result.turns[0].user != "Hello world"
    assert result.id == "test"


def test_apply_transform_preserves_other_fields():
    payload = Payload(
        id="test",
        attack_class=AttackClass.JAILBREAK,
        title="My Title",
        description="My desc",
        turns=[PayloadTurn(user="Hi"), PayloadTurn(user="Bye")],
    )
    result = _apply_transform_to_payload(payload, "rot13")
    assert result.title == "My Title"
    assert result.description == "My desc"
    assert result.attack_class == AttackClass.JAILBREAK
    assert len(result.turns) == 2


# ---------------------------------------------------------------------------
# run --help shows new flags
# ---------------------------------------------------------------------------


def test_run_help_shows_transform():
    result = runner.invoke(attack_app, ["run", "--help"])
    assert result.exit_code == 0
    assert "--transform" in result.output


def test_run_help_shows_fail_on_success():
    result = runner.invoke(attack_app, ["run", "--help"])
    assert "--fail-on-success" in result.output


def test_run_suite_help_shows_new_flags():
    result = runner.invoke(attack_app, ["run-suite", "--help"])
    assert result.exit_code == 0
    assert "--transform" in result.output
    assert "--attack-class" in result.output
    assert "--min-severity" in result.output
    assert "--fail-on-success" in result.output
    assert "--tag" in result.output


# ---------------------------------------------------------------------------
# run-suite with filtering (empty result)
# ---------------------------------------------------------------------------


def test_run_suite_no_payloads_after_filter(tmp_path):
    """When filtering leaves 0 payloads, exits with code 1."""
    target_yaml = tmp_path / "target.yaml"
    target_yaml.write_text(
        "name: test\nrequest:\n  url: http://127.0.0.1:9999/chat\n"
    )
    payloads_dir = tmp_path / "payloads"
    payloads_dir.mkdir()
    (payloads_dir / "pi.yaml").write_text(
        "id: pi\nattack_class: prompt-injection\ntitle: PI\n"
        "severity_if_success: low\nturns:\n  - user: hi\n"
    )
    result = runner.invoke(
        attack_app,
        [
            "run-suite",
            "-t", str(target_yaml),
            "-d", str(payloads_dir),
            "--min-severity", "critical",
        ],
    )
    assert result.exit_code == 1
    assert "No payloads" in result.output


# ---------------------------------------------------------------------------
# report --help shows PDF info
# ---------------------------------------------------------------------------


def test_report_help_shows_pdf():
    from airt.cli import app as main_app

    result = runner.invoke(main_app, ["report", "--help"])
    assert result.exit_code == 0
    assert ".pdf" in result.output


def test_report_pdf_requires_all_flag(tmp_path):
    from airt.cli import app as main_app

    out = tmp_path / "report.pdf"
    result = runner.invoke(
        main_app, ["report", "-s", "fake-id", "-o", str(out)]
    )
    assert result.exit_code == 1
    assert "requires --all" in result.output


# ---------------------------------------------------------------------------
# version command
# ---------------------------------------------------------------------------


def test_version_command():
    from airt.cli import app as main_app

    result = runner.invoke(main_app, ["version"])
    assert result.exit_code == 0
    assert "airt 0.2.0" in result.output
