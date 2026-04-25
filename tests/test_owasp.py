from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from airt.owasp import OWASP_LLM_TOP10, OwaspEntry, coverage_report, owasp_for_class


# ---------------------------------------------------------------------------
# OWASP_LLM_TOP10 structure
# ---------------------------------------------------------------------------


def test_top10_has_exactly_10_entries():
    assert len(OWASP_LLM_TOP10) == 10


def test_top10_keys_are_llm01_through_llm10():
    expected = {f"LLM{i:02d}" for i in range(1, 11)}
    assert set(OWASP_LLM_TOP10.keys()) == expected


def test_each_entry_has_required_fields():
    for owasp_id, info in OWASP_LLM_TOP10.items():
        assert "name" in info, f"{owasp_id} missing 'name'"
        assert "description" in info, f"{owasp_id} missing 'description'"
        assert "attack_classes" in info, f"{owasp_id} missing 'attack_classes'"
        assert isinstance(info["attack_classes"], list), f"{owasp_id} attack_classes not a list"


# ---------------------------------------------------------------------------
# owasp_for_class
# ---------------------------------------------------------------------------


def test_owasp_for_class_prompt_injection():
    result = owasp_for_class("prompt-injection")
    assert result == ["LLM01"]


def test_owasp_for_class_indirect_injection():
    result = owasp_for_class("indirect-injection")
    assert result == ["LLM01"]


def test_owasp_for_class_jailbreak():
    result = owasp_for_class("jailbreak")
    assert result == ["LLM02"]


def test_owasp_for_class_rag_poisoning():
    result = owasp_for_class("rag-poisoning")
    assert result == ["LLM03"]


def test_owasp_for_class_data_extraction():
    result = owasp_for_class("data-extraction")
    assert result == ["LLM06"]


def test_owasp_for_class_agentic_exploitation():
    # Maps to both LLM07 and LLM08
    result = owasp_for_class("agentic-exploitation")
    assert set(result) == {"LLM07", "LLM08"}


def test_owasp_for_class_policy_bypass():
    result = owasp_for_class("policy-bypass")
    assert result == ["LLM09"]


def test_owasp_for_class_unknown_returns_empty():
    result = owasp_for_class("nonexistent-class")
    assert result == []


# ---------------------------------------------------------------------------
# coverage_report
# ---------------------------------------------------------------------------


def _mock_payload(attack_class: str) -> MagicMock:
    p = MagicMock()
    p.attack_class.value = attack_class
    return p


def test_coverage_report_empty_payloads():
    result = coverage_report([])
    assert len(result) == 10
    for entry in result:
        assert entry.payload_count == 0
        assert entry.covered is False


def test_coverage_report_returns_owasp_entries():
    result = coverage_report([])
    assert all(isinstance(e, OwaspEntry) for e in result)


def test_coverage_report_counts_prompt_injection():
    payloads = [
        _mock_payload("prompt-injection"),
        _mock_payload("prompt-injection"),
        _mock_payload("jailbreak"),
    ]
    result = coverage_report(payloads)
    entry_map = {e.id: e for e in result}

    assert entry_map["LLM01"].payload_count == 2
    assert entry_map["LLM01"].covered is True
    assert entry_map["LLM02"].payload_count == 1
    assert entry_map["LLM02"].covered is True


def test_coverage_report_no_coverage_for_empty_attack_classes():
    payloads = [_mock_payload("prompt-injection")]
    result = coverage_report(payloads)
    entry_map = {e.id: e for e in result}

    # LLM04 has no attack_classes, so it should always be uncovered
    assert entry_map["LLM04"].payload_count == 0
    assert entry_map["LLM04"].covered is False
    assert entry_map["LLM05"].payload_count == 0
    assert entry_map["LLM10"].payload_count == 0


def test_coverage_report_agentic_counted_in_llm07_and_llm08():
    payloads = [_mock_payload("agentic-exploitation")]
    result = coverage_report(payloads)
    entry_map = {e.id: e for e in result}

    assert entry_map["LLM07"].payload_count == 1
    assert entry_map["LLM07"].covered is True
    assert entry_map["LLM08"].payload_count == 1
    assert entry_map["LLM08"].covered is True


def test_coverage_report_entry_ids_match_top10_keys():
    result = coverage_report([])
    ids = {e.id for e in result}
    assert ids == set(OWASP_LLM_TOP10.keys())


def test_coverage_report_entry_names_match():
    result = coverage_report([])
    for entry in result:
        assert entry.name == OWASP_LLM_TOP10[entry.id]["name"]
