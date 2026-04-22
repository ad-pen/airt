from datetime import datetime, timezone
from pathlib import Path

from airt import loader
from airt.models import (
    AttackClass,
    Flag,
    SessionResult,
    Severity,
    Status,
    TurnResult,
)
from airt.storage import Storage


def test_load_sample_target_and_payloads():
    root = Path(__file__).parent.parent
    target = loader.load_target(root / "targets" / "example-generic.yaml")
    assert target.name == "example-generic-chat"
    payloads = loader.load_payloads_dir(root / "payloads")
    assert len(payloads) >= 5
    ids = {p.id for p in payloads}
    assert "data-extraction.canary-exfiltration" in ids


def test_storage_roundtrip(tmp_path: Path):
    db = tmp_path / "t.db"
    storage = Storage(db)
    try:
        session = SessionResult(
            id="sess1",
            target_name="mock",
            payload_id="p1",
            payload_title="title",
            attack_class=AttackClass.DATA_EXTRACTION,
            started_at=datetime.now(timezone.utc),
            ended_at=datetime.now(timezone.utc),
            overall_status=Status.LIKELY_SUCCESS,
            turns=[
                TurnResult(
                    idx=0,
                    user="u",
                    assistant="a",
                    flags=[Flag(name="CANARY_LEAKED", evidence="x", turn_idx=0)],
                    status=Status.LIKELY_SUCCESS,
                    latency_ms=10,
                )
            ],
        )
        storage.save_session(session)
        reloaded = storage.get_session("sess1")
        assert reloaded is not None
        assert reloaded.overall_status is Status.LIKELY_SUCCESS
        assert reloaded.turns[0].flags[0].name == "CANARY_LEAKED"

        f = storage.promote_to_finding(
            "sess1",
            title="Leak",
            severity=Severity.CRITICAL,
            attack_class=AttackClass.DATA_EXTRACTION,
            notes="confirmed by canary",
        )
        findings = storage.list_findings()
        assert len(findings) == 1
        assert findings[0].id == f.id
        assert findings[0].severity is Severity.CRITICAL
    finally:
        storage.close()
