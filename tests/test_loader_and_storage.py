from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from airt import loader
from airt.models import (
    AttackClass,
    ConfigError,
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


# ---------------------------------------------------------------------------
# Helpers for filter / validation tests
# ---------------------------------------------------------------------------

_MINIMAL_PAYLOAD = {
    "id": "test.payload-1",
    "attack_class": "jailbreak",
    "title": "Test payload",
    "turns": [{"user": "Hello"}],
    "severity_if_success": "high",
}


def _write_payload(directory: Path, filename: str, overrides: dict | None = None) -> Path:
    """Write a payload YAML file into *directory* and return its path."""
    data = {**_MINIMAL_PAYLOAD, **(overrides or {})}
    p = directory / filename
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.dump(data, sort_keys=False))
    return p


def _write_target(directory: Path, filename: str = "target.yaml") -> Path:
    data = {
        "name": "test-target",
        "request": {
            "url": "https://example.com/api/chat",
        },
    }
    p = directory / filename
    p.write_text(yaml.dump(data, sort_keys=False))
    return p


# ---------------------------------------------------------------------------
# ConfigError on bad YAML / invalid data
# ---------------------------------------------------------------------------


class TestConfigErrors:
    def test_invalid_yaml_target(self, tmp_path: Path):
        f = tmp_path / "bad.yaml"
        f.write_text(": : : bad yaml {{{{")
        with pytest.raises(ConfigError, match="Invalid YAML"):
            loader.load_target(f)

    def test_invalid_yaml_payload(self, tmp_path: Path):
        f = tmp_path / "bad.yaml"
        f.write_text(": : : bad yaml {{{{")
        with pytest.raises(ConfigError, match="Invalid YAML"):
            loader.load_payload(f)

    def test_invalid_target_config(self, tmp_path: Path):
        f = tmp_path / "target.yaml"
        f.write_text(yaml.dump({"name": "t"}))  # missing 'request'
        with pytest.raises(ConfigError, match="Invalid target config"):
            loader.load_target(f)

    def test_extra_field_target(self, tmp_path: Path):
        f = tmp_path / "target.yaml"
        data = {
            "name": "t",
            "request": {"url": "https://example.com"},
            "unknown_field": True,
        }
        f.write_text(yaml.dump(data))
        with pytest.raises(ConfigError, match="Invalid target config"):
            loader.load_target(f)

    def test_extra_field_payload(self, tmp_path: Path):
        f = tmp_path / "payload.yaml"
        data = {**_MINIMAL_PAYLOAD, "invented_field": 42}
        f.write_text(yaml.dump(data, sort_keys=False))
        with pytest.raises(ConfigError, match="Invalid payload config"):
            loader.load_payload(f)


# ---------------------------------------------------------------------------
# Payload filtering
# ---------------------------------------------------------------------------


class TestPayloadFiltering:
    def _setup_payloads(self, tmp_path: Path) -> Path:
        """Create a set of diverse payloads for filter testing."""
        d = tmp_path / "payloads"
        d.mkdir()
        _write_payload(d, "p1.yaml", {
            "id": "p1",
            "attack_class": "jailbreak",
            "severity_if_success": "high",
            "owasp": "LLM01",
            "tags": ["multi-turn", "persona"],
        })
        _write_payload(d, "p2.yaml", {
            "id": "p2",
            "attack_class": "data-extraction",
            "severity_if_success": "critical",
            "owasp": "LLM06",
            "tags": ["canary"],
        })
        _write_payload(d, "p3.yaml", {
            "id": "p3",
            "attack_class": "jailbreak",
            "severity_if_success": "low",
            "tags": ["simple"],
        })
        _write_payload(d, "p4.yaml", {
            "id": "p4",
            "attack_class": "policy-bypass",
            "severity_if_success": "medium",
            "owasp": "LLM01",
            "tags": ["persona", "brand"],
        })
        _write_payload(d, "p5.yaml", {
            "id": "p5",
            "attack_class": "prompt-injection",
            "severity_if_success": "info",
            "tags": [],
        })
        return d

    def test_no_filters_returns_all(self, tmp_path: Path):
        d = self._setup_payloads(tmp_path)
        result = loader.load_payloads_dir(d)
        assert len(result) == 5

    def test_filter_by_attack_class(self, tmp_path: Path):
        d = self._setup_payloads(tmp_path)
        result = loader.load_payloads_dir(d, attack_class="jailbreak")
        ids = {p.id for p in result}
        assert ids == {"p1", "p3"}

    def test_filter_by_attack_class_no_match(self, tmp_path: Path):
        d = self._setup_payloads(tmp_path)
        result = loader.load_payloads_dir(d, attack_class="rag-poisoning")
        assert result == []

    def test_filter_by_owasp(self, tmp_path: Path):
        d = self._setup_payloads(tmp_path)
        result = loader.load_payloads_dir(d, owasp="LLM01")
        ids = {p.id for p in result}
        assert ids == {"p1", "p4"}

    def test_filter_by_owasp_no_match(self, tmp_path: Path):
        d = self._setup_payloads(tmp_path)
        result = loader.load_payloads_dir(d, owasp="LLM99")
        assert result == []

    def test_filter_by_tag(self, tmp_path: Path):
        d = self._setup_payloads(tmp_path)
        result = loader.load_payloads_dir(d, tag="persona")
        ids = {p.id for p in result}
        assert ids == {"p1", "p4"}

    def test_filter_by_tag_no_match(self, tmp_path: Path):
        d = self._setup_payloads(tmp_path)
        result = loader.load_payloads_dir(d, tag="nonexistent")
        assert result == []

    def test_filter_by_exact_severity(self, tmp_path: Path):
        d = self._setup_payloads(tmp_path)
        result = loader.load_payloads_dir(d, severity="critical")
        ids = {p.id for p in result}
        assert ids == {"p2"}

    def test_filter_by_min_severity_high(self, tmp_path: Path):
        d = self._setup_payloads(tmp_path)
        result = loader.load_payloads_dir(d, min_severity="high")
        ids = {p.id for p in result}
        # high and critical
        assert ids == {"p1", "p2"}

    def test_filter_by_min_severity_medium(self, tmp_path: Path):
        d = self._setup_payloads(tmp_path)
        result = loader.load_payloads_dir(d, min_severity="medium")
        ids = {p.id for p in result}
        # medium, high, critical
        assert ids == {"p1", "p2", "p4"}

    def test_filter_by_min_severity_info_returns_all(self, tmp_path: Path):
        d = self._setup_payloads(tmp_path)
        result = loader.load_payloads_dir(d, min_severity="info")
        assert len(result) == 5

    def test_filter_by_min_severity_critical(self, tmp_path: Path):
        d = self._setup_payloads(tmp_path)
        result = loader.load_payloads_dir(d, min_severity="critical")
        ids = {p.id for p in result}
        assert ids == {"p2"}

    def test_min_severity_invalid_raises(self, tmp_path: Path):
        d = self._setup_payloads(tmp_path)
        with pytest.raises(ConfigError, match="Unknown severity level"):
            loader.load_payloads_dir(d, min_severity="extreme")

    def test_combined_filters(self, tmp_path: Path):
        d = self._setup_payloads(tmp_path)
        # jailbreak + min_severity=high => only p1 (high jailbreak)
        result = loader.load_payloads_dir(
            d, attack_class="jailbreak", min_severity="high"
        )
        ids = {p.id for p in result}
        assert ids == {"p1"}

    def test_combined_filters_owasp_and_tag(self, tmp_path: Path):
        d = self._setup_payloads(tmp_path)
        # owasp=LLM01 + tag=persona => p1 and p4
        result = loader.load_payloads_dir(d, owasp="LLM01", tag="persona")
        ids = {p.id for p in result}
        assert ids == {"p1", "p4"}

    def test_combined_filters_narrow(self, tmp_path: Path):
        d = self._setup_payloads(tmp_path)
        # owasp=LLM01 + tag=brand => only p4
        result = loader.load_payloads_dir(d, owasp="LLM01", tag="brand")
        ids = {p.id for p in result}
        assert ids == {"p4"}

    def test_combined_all_filters_empty(self, tmp_path: Path):
        d = self._setup_payloads(tmp_path)
        # No jailbreak has owasp=LLM06
        result = loader.load_payloads_dir(
            d, attack_class="jailbreak", owasp="LLM06"
        )
        assert result == []


# ---------------------------------------------------------------------------
# validate_target / validate_payload
# ---------------------------------------------------------------------------


class TestValidateTarget:
    def test_valid_target(self, tmp_path: Path):
        f = _write_target(tmp_path)
        issues = loader.validate_target(f)
        assert issues == []

    def test_missing_file(self, tmp_path: Path):
        issues = loader.validate_target(tmp_path / "nope.yaml")
        assert any("does not exist" in i for i in issues)

    def test_invalid_yaml(self, tmp_path: Path):
        f = tmp_path / "bad.yaml"
        f.write_text(": : {{{{")
        issues = loader.validate_target(f)
        assert any("Invalid YAML" in i for i in issues)

    def test_missing_name(self, tmp_path: Path):
        f = tmp_path / "t.yaml"
        f.write_text(yaml.dump({"request": {"url": "https://x.com"}}))
        issues = loader.validate_target(f)
        assert any("name" in i for i in issues)

    def test_missing_request(self, tmp_path: Path):
        f = tmp_path / "t.yaml"
        f.write_text(yaml.dump({"name": "test"}))
        issues = loader.validate_target(f)
        assert any("request" in i for i in issues)

    def test_invalid_method(self, tmp_path: Path):
        f = tmp_path / "t.yaml"
        data = {"name": "t", "request": {"url": "https://x.com", "method": "DELETE"}}
        f.write_text(yaml.dump(data))
        issues = loader.validate_target(f)
        assert any("method" in i.lower() for i in issues)

    def test_invalid_history_format(self, tmp_path: Path):
        f = tmp_path / "t.yaml"
        data = {
            "name": "t",
            "request": {"url": "https://x.com", "history_format": "custom"},
        }
        f.write_text(yaml.dump(data))
        issues = loader.validate_target(f)
        assert any("history_format" in i for i in issues)

    def test_extra_field(self, tmp_path: Path):
        f = tmp_path / "t.yaml"
        data = {
            "name": "t",
            "request": {"url": "https://x.com"},
            "bogus": True,
        }
        f.write_text(yaml.dump(data))
        issues = loader.validate_target(f)
        assert len(issues) > 0

    def test_not_a_mapping(self, tmp_path: Path):
        f = tmp_path / "t.yaml"
        f.write_text("- a list\n- not a mapping\n")
        issues = loader.validate_target(f)
        assert any("mapping" in i for i in issues)


class TestValidatePayload:
    def test_valid_payload(self, tmp_path: Path):
        f = _write_payload(tmp_path, "p.yaml")
        issues = loader.validate_payload(f)
        assert issues == []

    def test_missing_file(self, tmp_path: Path):
        issues = loader.validate_payload(tmp_path / "nope.yaml")
        assert any("does not exist" in i for i in issues)

    def test_invalid_yaml(self, tmp_path: Path):
        f = tmp_path / "bad.yaml"
        f.write_text(": : {{{{")
        issues = loader.validate_payload(f)
        assert any("Invalid YAML" in i for i in issues)

    def test_missing_id(self, tmp_path: Path):
        f = tmp_path / "p.yaml"
        data = {**_MINIMAL_PAYLOAD}
        del data["id"]
        f.write_text(yaml.dump(data, sort_keys=False))
        issues = loader.validate_payload(f)
        assert any("id" in i for i in issues)

    def test_missing_attack_class(self, tmp_path: Path):
        f = tmp_path / "p.yaml"
        data = {**_MINIMAL_PAYLOAD}
        del data["attack_class"]
        f.write_text(yaml.dump(data, sort_keys=False))
        issues = loader.validate_payload(f)
        assert any("attack_class" in i for i in issues)

    def test_invalid_attack_class(self, tmp_path: Path):
        f = tmp_path / "p.yaml"
        data = {**_MINIMAL_PAYLOAD, "attack_class": "telekinesis"}
        f.write_text(yaml.dump(data, sort_keys=False))
        issues = loader.validate_payload(f)
        assert any("attack_class" in i for i in issues)

    def test_missing_title(self, tmp_path: Path):
        f = tmp_path / "p.yaml"
        data = {**_MINIMAL_PAYLOAD}
        del data["title"]
        f.write_text(yaml.dump(data, sort_keys=False))
        issues = loader.validate_payload(f)
        assert any("title" in i for i in issues)

    def test_missing_turns(self, tmp_path: Path):
        f = tmp_path / "p.yaml"
        data = {**_MINIMAL_PAYLOAD}
        del data["turns"]
        f.write_text(yaml.dump(data, sort_keys=False))
        issues = loader.validate_payload(f)
        assert any("turns" in i for i in issues)

    def test_empty_turns(self, tmp_path: Path):
        f = tmp_path / "p.yaml"
        data = {**_MINIMAL_PAYLOAD, "turns": []}
        f.write_text(yaml.dump(data, sort_keys=False))
        issues = loader.validate_payload(f)
        assert any("empty" in i.lower() for i in issues)

    def test_invalid_severity(self, tmp_path: Path):
        f = tmp_path / "p.yaml"
        data = {**_MINIMAL_PAYLOAD, "severity_if_success": "ultra"}
        f.write_text(yaml.dump(data, sort_keys=False))
        issues = loader.validate_payload(f)
        assert any("severity" in i.lower() for i in issues)

    def test_unknown_success_field(self, tmp_path: Path):
        f = tmp_path / "p.yaml"
        data = {**_MINIMAL_PAYLOAD, "success": {"magic_check": True}}
        f.write_text(yaml.dump(data, sort_keys=False))
        issues = loader.validate_payload(f)
        assert any("magic_check" in i for i in issues)

    def test_extra_field_payload(self, tmp_path: Path):
        f = tmp_path / "p.yaml"
        data = {**_MINIMAL_PAYLOAD, "not_a_real_field": 99}
        f.write_text(yaml.dump(data, sort_keys=False))
        issues = loader.validate_payload(f)
        assert len(issues) > 0

    def test_not_a_mapping(self, tmp_path: Path):
        f = tmp_path / "p.yaml"
        f.write_text("- a list\n")
        issues = loader.validate_payload(f)
        assert any("mapping" in i for i in issues)
