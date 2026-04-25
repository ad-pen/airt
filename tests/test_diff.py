"""Tests for airt.diff module and airt diff CLI command."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from typer.testing import CliRunner

from airt.diff import DiffEntry, DiffResult, diff_sessions
from airt.models import AttackClass, SessionResult, Status, TurnResult

runner = CliRunner()


def _session(payload_id: str, status: Status) -> SessionResult:
    return SessionResult(
        id=f"sess-{payload_id}-{status.value}",
        target_name="test-target",
        payload_id=payload_id,
        payload_title=payload_id,
        attack_class=AttackClass.PROMPT_INJECTION,
        started_at=datetime.now(timezone.utc),
        ended_at=datetime.now(timezone.utc),
        overall_status=status,
        turns=[TurnResult(idx=0, user="hi", assistant="hello")],
    )


def test_diff_empty():
    result = diff_sessions([], [])
    assert len(result.entries) == 0


def test_diff_unchanged():
    old = [_session("p1", Status.DEFLECTED)]
    new = [_session("p1", Status.DEFLECTED)]
    result = diff_sessions(old, new)
    assert len(result.unchanged) == 1
    assert result.entries[0].change == "unchanged"


def test_diff_regression():
    old = [_session("p1", Status.DEFLECTED)]
    new = [_session("p1", Status.LIKELY_SUCCESS)]
    result = diff_sessions(old, new)
    assert len(result.regressions) == 1
    assert result.regressions[0].payload_id == "p1"


def test_diff_fix():
    old = [_session("p1", Status.LIKELY_SUCCESS)]
    new = [_session("p1", Status.DEFLECTED)]
    result = diff_sessions(old, new)
    assert len(result.fixes) == 1
    assert result.fixes[0].payload_id == "p1"


def test_diff_added():
    old = []
    new = [_session("p1", Status.NO_SIGNAL)]
    result = diff_sessions(old, new)
    assert len(result.added) == 1
    assert result.added[0].payload_id == "p1"


def test_diff_removed():
    old = [_session("p1", Status.NO_SIGNAL)]
    new = []
    result = diff_sessions(old, new)
    assert len(result.removed) == 1
    assert result.removed[0].payload_id == "p1"


def test_diff_changed_non_regression():
    old = [_session("p1", Status.NO_SIGNAL)]
    new = [_session("p1", Status.FLAGS_PRESENT)]
    result = diff_sessions(old, new)
    assert len(result.changed) == 1
    assert result.changed[0].change == "changed"


def test_diff_multiple_sessions_best_status():
    old = [
        _session("p1", Status.DEFLECTED),
        _session("p1", Status.FLAGS_PRESENT),
    ]
    new = [_session("p1", Status.LIKELY_SUCCESS)]
    result = diff_sessions(old, new)
    assert result.entries[0].old_status == Status.FLAGS_PRESENT
    assert result.entries[0].new_status == Status.LIKELY_SUCCESS
    assert result.entries[0].change == "regression"


def test_diff_mixed_changes():
    old = [
        _session("p1", Status.LIKELY_SUCCESS),
        _session("p2", Status.DEFLECTED),
        _session("p3", Status.NO_SIGNAL),
    ]
    new = [
        _session("p1", Status.DEFLECTED),
        _session("p2", Status.LIKELY_SUCCESS),
        _session("p4", Status.FLAGS_PRESENT),
    ]
    result = diff_sessions(old, new)
    assert len(result.fixes) == 1
    assert len(result.regressions) == 1
    assert len(result.added) == 1
    assert len(result.removed) == 1


# ---------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------


def test_diff_cli_help():
    from airt.cli import app

    result = runner.invoke(app, ["diff", "--help"])
    assert result.exit_code == 0
    assert "Compare" in result.output


def test_diff_cli_runs(tmp_path):
    from airt.cli import app
    from airt.storage import Storage

    old_db = tmp_path / "old.db"
    new_db = tmp_path / "new.db"

    old_storage = Storage(old_db)
    old_storage.save_session(_session("p1", Status.DEFLECTED))
    old_storage.save_session(_session("p2", Status.LIKELY_SUCCESS))
    old_storage.close()

    new_storage = Storage(new_db)
    new_storage.save_session(_session("p1", Status.LIKELY_SUCCESS))
    new_storage.save_session(_session("p2", Status.DEFLECTED))
    new_storage.close()

    result = runner.invoke(app, ["diff", str(old_db), str(new_db)])
    assert result.exit_code == 0
    assert "Regressions" in result.output
    assert "Fixes" in result.output
    assert "Summary" in result.output


def test_diff_cli_no_changes(tmp_path):
    from airt.cli import app
    from airt.storage import Storage

    db = tmp_path / "same.db"
    storage = Storage(db)
    storage.save_session(_session("p1", Status.DEFLECTED))
    storage.close()

    result = runner.invoke(app, ["diff", str(db), str(db)])
    assert result.exit_code == 0
    assert "Summary" in result.output
