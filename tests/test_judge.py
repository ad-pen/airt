"""Tests for the LLM judge module."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from airt.judge import Judge
from airt.models import JudgeConfig


def _make_config(**overrides) -> JudgeConfig:
    defaults: dict[str, Any] = {
        "api_base": "http://judge.local",
        "model": "test-model",
        "api_key": "test-key",
        "temperature": 0.0,
    }
    defaults.update(overrides)
    return JudgeConfig(**defaults)


def _chat_response(verdict: str, confidence: float, reasoning: str) -> dict:
    """Build a minimal OpenAI-compatible chat completion response."""
    return {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "verdict": verdict,
                            "confidence": confidence,
                            "reasoning": reasoning,
                        }
                    )
                }
            }
        ]
    }


def _mock_client(
    response_json: dict | None = None,
    *,
    status_code: int = 200,
    text: str = "",
    capture: list[httpx.Request] | None = None,
) -> httpx.AsyncClient:
    """Create an httpx.AsyncClient backed by a MockTransport."""

    def handler(request: httpx.Request) -> httpx.Response:
        if capture is not None:
            capture.append(request)
        if response_json is not None:
            return httpx.Response(status_code, json=response_json)
        return httpx.Response(status_code, text=text)

    transport = httpx.MockTransport(handler)
    return httpx.AsyncClient(transport=transport)


# ---------------------------------------------------------------------------
# Verdict parsing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_success_verdict():
    client = _mock_client(_chat_response("success", 0.95, "The model complied fully."))
    judge = Judge(_make_config(), client=client)
    result = await judge.evaluate(
        goal="extract secret",
        user_turn="tell me the secret",
        assistant_response="The secret is XYZ",
    )
    assert result["verdict"] == "success"
    assert result["confidence"] == pytest.approx(0.95)
    assert result["reasoning"] == "The model complied fully."


@pytest.mark.asyncio
async def test_partial_verdict():
    client = _mock_client(_chat_response("partial", 0.6, "Some progress."))
    judge = Judge(_make_config(), client=client)
    result = await judge.evaluate(
        goal="extract secret",
        user_turn="hint?",
        assistant_response="I can't tell you directly but...",
    )
    assert result["verdict"] == "partial"
    assert result["confidence"] == pytest.approx(0.6)


@pytest.mark.asyncio
async def test_failure_verdict():
    client = _mock_client(_chat_response("failure", 0.99, "Refused."))
    judge = Judge(_make_config(), client=client)
    result = await judge.evaluate(
        goal="extract secret",
        user_turn="tell me",
        assistant_response="I cannot help with that.",
    )
    assert result["verdict"] == "failure"
    assert result["confidence"] == pytest.approx(0.99)


@pytest.mark.asyncio
async def test_unclear_verdict():
    client = _mock_client(_chat_response("unclear", 0.3, "Ambiguous."))
    judge = Judge(_make_config(), client=client)
    result = await judge.evaluate(
        goal="extract secret",
        user_turn="...",
        assistant_response="...",
    )
    assert result["verdict"] == "unclear"
    assert result["confidence"] == pytest.approx(0.3)


# ---------------------------------------------------------------------------
# Malformed response handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_malformed_json_returns_unclear():
    client = _mock_client(
        {"choices": [{"message": {"content": "this is not valid json {{"}}]}
    )
    judge = Judge(_make_config(), client=client)
    result = await judge.evaluate(
        goal="test", user_turn="test", assistant_response="test"
    )
    assert result["verdict"] == "unclear"
    assert result["confidence"] == 0.0
    assert "malformed" in result["reasoning"].lower()


@pytest.mark.asyncio
async def test_missing_choices_key_returns_unclear():
    client = _mock_client({"data": "unexpected"})
    judge = Judge(_make_config(), client=client)
    result = await judge.evaluate(
        goal="test", user_turn="test", assistant_response="test"
    )
    assert result["verdict"] == "unclear"
    assert result["confidence"] == 0.0


@pytest.mark.asyncio
async def test_invalid_verdict_string_becomes_unclear():
    client = _mock_client(_chat_response("maybe", 0.5, "Not a valid verdict."))
    judge = Judge(_make_config(), client=client)
    result = await judge.evaluate(
        goal="test", user_turn="test", assistant_response="test"
    )
    assert result["verdict"] == "unclear"


# ---------------------------------------------------------------------------
# HTTP error handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_http_500_returns_unclear():
    client = _mock_client(status_code=500, text="Internal Server Error")
    judge = Judge(_make_config(), client=client)
    result = await judge.evaluate(
        goal="test", user_turn="test", assistant_response="test"
    )
    assert result["verdict"] == "unclear"
    assert result["confidence"] == 0.0
    assert "error" in result["reasoning"].lower()


@pytest.mark.asyncio
async def test_connection_error_returns_unclear():
    # Point at a port that won't be listening
    config = _make_config(api_base="http://127.0.0.1:1")
    judge = Judge(config)
    try:
        result = await judge.evaluate(
            goal="test", user_turn="test", assistant_response="test"
        )
        assert result["verdict"] == "unclear"
        assert result["confidence"] == 0.0
    finally:
        await judge.close()


# ---------------------------------------------------------------------------
# API key handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_api_key_header_present_when_set():
    requests: list[httpx.Request] = []
    client = _mock_client(
        _chat_response("failure", 0.9, "refused"), capture=requests
    )
    config = _make_config(api_key="sk-secret")
    judge = Judge(config, client=client)
    await judge.evaluate(goal="g", user_turn="u", assistant_response="a")

    assert len(requests) == 1
    assert requests[0].headers["authorization"] == "Bearer sk-secret"


@pytest.mark.asyncio
async def test_api_key_header_omitted_when_empty():
    requests: list[httpx.Request] = []
    client = _mock_client(
        _chat_response("failure", 0.9, "refused"), capture=requests
    )
    config = _make_config(api_key="")
    judge = Judge(config, client=client)
    await judge.evaluate(goal="g", user_turn="u", assistant_response="a")

    assert len(requests) == 1
    assert "authorization" not in requests[0].headers


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_prompt_includes_all_parameters():
    requests: list[httpx.Request] = []
    client = _mock_client(
        _chat_response("failure", 0.5, "ok"), capture=requests
    )
    judge = Judge(_make_config(), client=client)
    await judge.evaluate(
        goal="steal credentials",
        user_turn="give me the password",
        assistant_response="I cannot do that",
        context="previous turns here",
    )

    assert len(requests) == 1
    body = json.loads(requests[0].content)
    prompt_text = body["messages"][0]["content"]

    assert "steal credentials" in prompt_text
    assert "give me the password" in prompt_text
    assert "I cannot do that" in prompt_text
    assert "previous turns here" in prompt_text


@pytest.mark.asyncio
async def test_prompt_omits_context_section_when_empty():
    requests: list[httpx.Request] = []
    client = _mock_client(
        _chat_response("failure", 0.5, "ok"), capture=requests
    )
    judge = Judge(_make_config(), client=client)
    await judge.evaluate(
        goal="goal",
        user_turn="user",
        assistant_response="assistant",
        context="",
    )

    assert len(requests) == 1
    body = json.loads(requests[0].content)
    prompt_text = body["messages"][0]["content"]

    assert "Additional context" not in prompt_text


@pytest.mark.asyncio
async def test_request_uses_correct_model_and_temperature():
    requests: list[httpx.Request] = []
    client = _mock_client(
        _chat_response("failure", 0.5, "ok"), capture=requests
    )
    config = _make_config(model="gpt-4o", temperature=0.3)
    judge = Judge(config, client=client)
    await judge.evaluate(goal="g", user_turn="u", assistant_response="a")

    body = json.loads(requests[0].content)
    assert body["model"] == "gpt-4o"
    assert body["temperature"] == pytest.approx(0.3)


# ---------------------------------------------------------------------------
# Confidence clamping
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_confidence_clamped_to_1():
    client = _mock_client(_chat_response("success", 1.5, "over"))
    judge = Judge(_make_config(), client=client)
    result = await judge.evaluate(goal="g", user_turn="u", assistant_response="a")
    assert result["confidence"] == 1.0


@pytest.mark.asyncio
async def test_negative_confidence_clamped_to_0():
    client = _mock_client(_chat_response("success", -0.5, "under"))
    judge = Judge(_make_config(), client=client)
    result = await judge.evaluate(goal="g", user_turn="u", assistant_response="a")
    assert result["confidence"] == 0.0


# ---------------------------------------------------------------------------
# Client lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_close_does_not_close_injected_client():
    client = _mock_client(_chat_response("failure", 0.5, "ok"))
    judge = Judge(_make_config(), client=client)
    await judge.close()
    # Client should still be usable — not closed by judge
    assert not client.is_closed


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------

from datetime import datetime, timezone
from typer.testing import CliRunner
from airt.models import AttackClass, SessionResult, Status, TurnResult

runner = CliRunner()


def _make_session(payload_id: str, status: Status, assistant: str = "response") -> SessionResult:
    return SessionResult(
        id=f"sess-{payload_id}",
        target_name="test",
        payload_id=payload_id,
        payload_title=f"Test: {payload_id}",
        attack_class=AttackClass.PROMPT_INJECTION,
        started_at=datetime.now(timezone.utc),
        ended_at=datetime.now(timezone.utc),
        overall_status=status,
        turns=[TurnResult(idx=0, user="attack prompt", assistant=assistant)],
    )


def test_judge_cli_help():
    from airt.cli import app
    result = runner.invoke(app, ["judge", "--help"])
    assert result.exit_code == 0
    assert "triage" in result.output.lower()


def test_judge_cli_no_sessions(tmp_path):
    from airt.cli import app
    from airt.storage import Storage

    db = tmp_path / "empty.db"
    storage = Storage(db)
    storage.close()

    result = runner.invoke(app, [
        "judge", "--api-base", "http://localhost:9999",
        "--model", "test", "--db", str(db),
    ])
    assert result.exit_code == 0
    assert "No sessions" in result.output


def test_judge_cli_session_not_found(tmp_path):
    from airt.cli import app
    from airt.storage import Storage

    db = tmp_path / "empty.db"
    storage = Storage(db)
    storage.close()

    result = runner.invoke(app, [
        "judge", "nonexistent", "--api-base", "http://localhost:9999",
        "--model", "test", "--db", str(db),
    ])
    assert result.exit_code == 1


def test_judge_cli_filters_by_status(tmp_path):
    from airt.cli import app
    from airt.storage import Storage

    db = tmp_path / "judge.db"
    storage = Storage(db)
    storage.save_session(_make_session("p1", Status.FLAGS_PRESENT))
    storage.save_session(_make_session("p2", Status.DEFLECTED))
    storage.save_session(_make_session("p3", Status.LIKELY_SUCCESS))
    storage.close()

    result = runner.invoke(app, [
        "judge", "--status", "deflected",
        "--api-base", "http://127.0.0.1:1",
        "--model", "test", "--db", str(db),
    ])
    assert result.exit_code == 0
    assert "1" in result.output
