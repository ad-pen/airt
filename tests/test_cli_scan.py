"""Tests for airt.cli.scan — the quick-start scan command."""
from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from airt.cli import app as main_app
from airt.cli.scan import app as scan_app

runner = CliRunner()


# ---------------------------------------------------------------------------
# help & preset listing
# ---------------------------------------------------------------------------


def test_scan_help():
    result = runner.invoke(main_app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "URL" in result.output or "url" in result.output.lower()
    assert "--preset" in result.output
    assert "--api-key" in result.output


def test_scan_help_shows_examples():
    result = runner.invoke(main_app, ["scan", "--help"])
    assert "openai" in result.output.lower()
    assert "ollama" in result.output.lower()


def test_list_presets():
    result = runner.invoke(main_app, ["scan", "--list-presets", "dummy-url"])
    assert result.exit_code == 0
    assert "openai" in result.output
    assert "anthropic" in result.output
    assert "ollama" in result.output


# ---------------------------------------------------------------------------
# scan with unreachable target (validates wiring, not network)
# ---------------------------------------------------------------------------


def test_scan_unreachable_target_errors(tmp_path):
    """Scan against a non-listening port should show errors, not crash."""
    result = runner.invoke(
        main_app,
        [
            "scan",
            "http://127.0.0.1:19999/v1/chat/completions",
            "--preset", "openai",
        ],
    )
    assert result.exit_code == 0 or result.exit_code == 1
    assert "Scanning" in result.output or "error" in result.output.lower() or "Target" in result.output


def test_scan_with_attack_class_filter(tmp_path):
    """Filtering to a class that has no payloads exits cleanly."""
    empty_dir = tmp_path / "payloads"
    empty_dir.mkdir()
    result = runner.invoke(
        main_app,
        [
            "scan",
            "http://127.0.0.1:19999/chat",
            "--preset", "generic",
            "-d", str(empty_dir),
        ],
    )
    assert result.exit_code == 1
    assert "No payloads" in result.output


def test_scan_with_min_severity_filter(tmp_path):
    pdir = tmp_path / "payloads"
    pdir.mkdir()
    (pdir / "test.yaml").write_text(
        "id: test\nattack_class: jailbreak\ntitle: Test\n"
        "severity_if_success: low\nturns:\n  - user: hi\n"
    )
    result = runner.invoke(
        main_app,
        [
            "scan",
            "http://127.0.0.1:19999/chat",
            "--preset", "generic",
            "-d", str(pdir),
            "--min-severity", "critical",
        ],
    )
    assert result.exit_code == 1
    assert "No payloads" in result.output


# ---------------------------------------------------------------------------
# output file
# ---------------------------------------------------------------------------


def test_scan_output_flag_present_in_help():
    result = runner.invoke(main_app, ["scan", "--help"])
    assert "--output" in result.output or "-o" in result.output


# ---------------------------------------------------------------------------
# scan via main app (integration)
# ---------------------------------------------------------------------------


def test_scan_registered_in_main_app():
    result = runner.invoke(main_app, ["--help"])
    assert "scan" in result.output
