from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from airt.models import (
    AttackClass,
    Finding,
    Flag,
    SessionResult,
    Severity,
    Status,
    TurnResult,
)

DEFAULT_DB = Path.home() / ".airt" / "airt.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    target_name TEXT NOT NULL,
    payload_id TEXT NOT NULL,
    payload_title TEXT NOT NULL,
    attack_class TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT NOT NULL,
    overall_status TEXT NOT NULL,
    canary_used TEXT
);

CREATE TABLE IF NOT EXISTS turns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    idx INTEGER NOT NULL,
    user_text TEXT NOT NULL,
    assistant_text TEXT NOT NULL,
    flags_json TEXT NOT NULL,
    status TEXT NOT NULL,
    latency_ms INTEGER NOT NULL,
    error TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    attack_class TEXT NOT NULL,
    notes TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);
"""


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


class Storage:
    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or DEFAULT_DB
        self.conn = _connect(self.db_path)

    def close(self) -> None:
        self.conn.close()

    def save_session(self, session: SessionResult) -> None:
        with self.conn:
            self.conn.execute(
                """INSERT OR REPLACE INTO sessions
                (id, target_name, payload_id, payload_title, attack_class,
                 started_at, ended_at, overall_status, canary_used)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    session.id,
                    session.target_name,
                    session.payload_id,
                    session.payload_title,
                    session.attack_class.value,
                    session.started_at.isoformat(),
                    session.ended_at.isoformat(),
                    session.overall_status.value,
                    session.canary_used,
                ),
            )
            self.conn.execute("DELETE FROM turns WHERE session_id = ?", (session.id,))
            for t in session.turns:
                self.conn.execute(
                    """INSERT INTO turns
                    (session_id, idx, user_text, assistant_text, flags_json,
                     status, latency_ms, error)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        session.id,
                        t.idx,
                        t.user,
                        t.assistant,
                        json.dumps([f.model_dump() for f in t.flags]),
                        t.status.value,
                        t.latency_ms,
                        t.error,
                    ),
                )

    def list_sessions(self, limit: int = 100) -> list[SessionResult]:
        rows = self.conn.execute(
            "SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [self._row_to_session(r) for r in rows]

    def get_session(self, session_id: str) -> SessionResult | None:
        row = self.conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if not row:
            return None
        return self._row_to_session(row)

    def _row_to_session(self, row: sqlite3.Row) -> SessionResult:
        turn_rows = self.conn.execute(
            "SELECT * FROM turns WHERE session_id = ? ORDER BY idx", (row["id"],)
        ).fetchall()
        turns = [
            TurnResult(
                idx=tr["idx"],
                user=tr["user_text"],
                assistant=tr["assistant_text"],
                flags=[Flag(**f) for f in json.loads(tr["flags_json"])],
                status=Status(tr["status"]),
                latency_ms=tr["latency_ms"],
                error=tr["error"],
            )
            for tr in turn_rows
        ]
        return SessionResult(
            id=row["id"],
            target_name=row["target_name"],
            payload_id=row["payload_id"],
            payload_title=row["payload_title"],
            attack_class=AttackClass(row["attack_class"]),
            started_at=datetime.fromisoformat(row["started_at"]),
            ended_at=datetime.fromisoformat(row["ended_at"]),
            overall_status=Status(row["overall_status"]),
            turns=turns,
            canary_used=row["canary_used"],
        )

    def promote_to_finding(
        self,
        session_id: str,
        *,
        title: str,
        severity: Severity,
        attack_class: AttackClass,
        notes: str = "",
    ) -> Finding:
        finding = Finding(
            id=uuid.uuid4().hex[:12],
            session_id=session_id,
            title=title,
            severity=severity,
            attack_class=attack_class,
            notes=notes,
            created_at=datetime.now(timezone.utc),
        )
        with self.conn:
            self.conn.execute(
                """INSERT INTO findings
                (id, session_id, title, severity, attack_class, notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding.id,
                    finding.session_id,
                    finding.title,
                    finding.severity.value,
                    finding.attack_class.value,
                    finding.notes,
                    finding.created_at.isoformat(),
                ),
            )
        return finding

    def list_findings(self) -> list[Finding]:
        rows = self.conn.execute(
            "SELECT * FROM findings ORDER BY created_at DESC"
        ).fetchall()
        return [
            Finding(
                id=r["id"],
                session_id=r["session_id"],
                title=r["title"],
                severity=Severity(r["severity"]),
                attack_class=AttackClass(r["attack_class"]),
                notes=r["notes"],
                created_at=datetime.fromisoformat(r["created_at"]),
            )
            for r in rows
        ]
