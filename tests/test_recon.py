from __future__ import annotations

import json

import httpx
import pytest

from airt.models import Target, TargetRequest
from airt.recon import Recon, ReconResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_target(url: str = "http://target.local/v1/chat") -> Target:
    return Target(
        name="test-target",
        request=TargetRequest(
            url=url,
            method="POST",
            headers={},
            body_template={"messages": "${history}"},
            history_format="openai",
            response_path="choices.0.message.content",
        ),
    )


def _openai_response(content: str) -> httpx.Response:
    body = {"choices": [{"message": {"content": content}}]}
    return httpx.Response(
        status_code=200,
        json=body,
        request=httpx.Request("POST", "http://target.local/v1/chat"),
    )


class FixedTransport(httpx.AsyncBaseTransport):
    """Always returns the same response."""

    def __init__(self, response: httpx.Response) -> None:
        self._response = response

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return self._response


class SequentialTransport(httpx.AsyncBaseTransport):
    """Returns canned responses in order, then repeats the last one."""

    def __init__(self, responses: list[httpx.Response]) -> None:
        self._responses = list(responses)
        self._idx = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        resp = self._responses[min(self._idx, len(self._responses) - 1)]
        self._idx += 1
        return resp


class ErrorTransport(httpx.AsyncBaseTransport):
    """Always raises a connection error."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_recon_result_structure():
    target = _make_target()
    transport = FixedTransport(_openai_response("Hello! I can help you with many things."))
    client = httpx.AsyncClient(transport=transport)

    recon = Recon(target, client=client)
    try:
        result = await recon.run()
    finally:
        await recon.close()

    assert isinstance(result, ReconResult)
    assert result.target_name == "test-target"
    assert result.endpoint == "http://target.local/v1/chat"
    assert isinstance(result.probes, list)
    assert len(result.probes) == 7
    assert isinstance(result.summary, dict)


@pytest.mark.asyncio
async def test_recon_summary_fields_present():
    target = _make_target()
    transport = FixedTransport(_openai_response("Sure, I can help!"))
    client = httpx.AsyncClient(transport=transport)

    recon = Recon(target, client=client)
    try:
        result = await recon.run()
    finally:
        await recon.close()

    summary = result.summary
    assert "system_prompt_hints" in summary
    assert "refusal_detected" in summary
    assert "tool_disclosure" in summary
    assert "latency_ms_avg" in summary
    assert "total_probes" in summary
    assert summary["total_probes"] == 7
    assert isinstance(summary["latency_ms_avg"], float)
    assert isinstance(summary["system_prompt_hints"], bool)
    assert isinstance(summary["refusal_detected"], bool)
    assert isinstance(summary["tool_disclosure"], bool)


@pytest.mark.asyncio
async def test_probe_fields_present():
    target = _make_target()
    transport = FixedTransport(_openai_response("I can help with general questions."))
    client = httpx.AsyncClient(transport=transport)

    recon = Recon(target, client=client)
    try:
        result = await recon.run()
    finally:
        await recon.close()

    for probe in result.probes:
        assert "name" in probe
        assert "prompt" in probe
        assert "response" in probe
        assert "finding" in probe
        assert isinstance(probe["name"], str)
        assert isinstance(probe["prompt"], str)
        assert isinstance(probe["finding"], str)


@pytest.mark.asyncio
async def test_probe_exception_does_not_abort():
    """A failing probe is caught and doesn't raise; other probes continue."""
    target = _make_target()
    transport = ErrorTransport()
    client = httpx.AsyncClient(transport=transport)

    recon = Recon(target, client=client)
    try:
        result = await recon.run()
    finally:
        await recon.close()

    # All probes should still be recorded
    assert len(result.probes) == 7
    # Each failing probe should have an error finding
    for probe in result.probes:
        assert "error" in probe["finding"]


@pytest.mark.asyncio
async def test_refusal_detected_in_summary():
    target = _make_target()
    transport = FixedTransport(_openai_response("I cannot help with that request."))
    client = httpx.AsyncClient(transport=transport)

    recon = Recon(target, client=client)
    try:
        result = await recon.run()
    finally:
        await recon.close()

    assert result.summary["refusal_detected"] is True


@pytest.mark.asyncio
async def test_system_prompt_disclosure_detected():
    target = _make_target()
    # system-prompt-probe response that hints at disclosure
    responses = [
        _openai_response("Hello! How can I help?"),
        _openai_response("My instructions say: you are a helpful assistant configured for Acme."),
        _openai_response("I am a support bot, my role is to assist users."),
        _openai_response("Here is a very long essay about nothing." * 30),
        _openai_response("I have access to the search_tool and calendar_tool functions."),
        _openai_response("The decoded message asks about my capabilities."),
        _openai_response("I cannot ignore previous instructions."),
    ]
    transport = SequentialTransport(responses)
    client = httpx.AsyncClient(transport=transport)

    recon = Recon(target, client=client)
    try:
        result = await recon.run()
    finally:
        await recon.close()

    assert result.summary["system_prompt_hints"] is True


@pytest.mark.asyncio
async def test_tool_disclosure_detected():
    target = _make_target()
    responses = [
        _openai_response("Hello!"),
        _openai_response("Those are my instructions."),
        _openai_response("I am an assistant."),
        _openai_response("Here is a long essay."),
        _openai_response("I have access to tools: search_tool and email_function."),
        _openai_response("Decoded and responded."),
        _openai_response("I cannot ignore instructions."),
    ]
    transport = SequentialTransport(responses)
    client = httpx.AsyncClient(transport=transport)

    recon = Recon(target, client=client)
    try:
        result = await recon.run()
    finally:
        await recon.close()

    assert result.summary["tool_disclosure"] is True


@pytest.mark.asyncio
async def test_probe_names_match_expected():
    expected_names = {
        "baseline",
        "system-prompt-probe",
        "identity-probe",
        "length-probe",
        "tool-probe",
        "encoding-probe",
        "boundary-probe",
    }
    target = _make_target()
    transport = FixedTransport(_openai_response("OK"))
    client = httpx.AsyncClient(transport=transport)

    recon = Recon(target, client=client)
    try:
        result = await recon.run()
    finally:
        await recon.close()

    names = {p["name"] for p in result.probes}
    assert names == expected_names
