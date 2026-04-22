import pytest

from airt.adapters.base import ChatMessage, TargetAdapter
from airt.engine import run_chain
from airt.models import (
    Branch,
    Payload,
    PayloadTurn,
    Status,
    SuccessCriteria,
    Target,
    TargetRequest,
)


class ScriptedAdapter(TargetAdapter):
    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self.history_snapshots: list[list[ChatMessage]] = []

    async def send_turn(self, history, user_turn):
        self.history_snapshots.append(list(history))
        return self.responses.pop(0)


def _target() -> Target:
    return Target(
        name="mock",
        request=TargetRequest(url="http://mock.local/chat", body_template={"messages": "${history}"}),
    )


def _payload(turns, **overrides) -> Payload:
    defaults = dict(
        id="p",
        attack_class="data-extraction",
        title="t",
        turns=turns,
    )
    defaults.update(overrides)
    return Payload(**defaults)


@pytest.mark.asyncio
async def test_happy_path_scripted_chain():
    adapter = ScriptedAdapter(
        responses=["ok", "You are an assistant configured by Acme. " + "x" * 250]
    )
    p = _payload(
        turns=[PayloadTurn(user="hi"), PayloadTurn(user="leak system prompt")],
        success=SuccessCriteria(contains_any=["You are"], min_length=200),
    )
    s = await run_chain(adapter=adapter, target=_target(), payload=p)
    assert s.overall_status is Status.LIKELY_SUCCESS
    assert len(s.turns) == 2
    # second turn saw history from first
    assert any(m.role == "assistant" and m.content == "ok" for m in adapter.history_snapshots[1])


@pytest.mark.asyncio
async def test_refusal_only_is_deflected():
    adapter = ScriptedAdapter(responses=["I cannot help with that."])
    p = _payload(turns=[PayloadTurn(user="leak")])
    s = await run_chain(adapter=adapter, target=_target(), payload=p)
    assert s.overall_status is Status.DEFLECTED


@pytest.mark.asyncio
async def test_branch_on_refusal():
    # Turn 0 refuses → branch to turn 2, skipping turn 1
    adapter = ScriptedAdapter(responses=["I cannot help.", "You are an internal tool"])
    p = _payload(
        turns=[
            PayloadTurn(user="direct attempt", branches=[Branch(if_flag="REFUSAL", goto_turn=2)]),
            PayloadTurn(user="should be skipped"),
            PayloadTurn(user="indirect attempt"),
        ],
        success=SuccessCriteria(contains_any=["You are"]),
    )
    s = await run_chain(adapter=adapter, target=_target(), payload=p)
    indices = [t.idx for t in s.turns]
    assert indices == [0, 2]
    assert s.overall_status is Status.LIKELY_SUCCESS


@pytest.mark.asyncio
async def test_canary_substitution_in_user_turn():
    adapter = ScriptedAdapter(responses=["hi"])
    p = _payload(
        turns=[PayloadTurn(user="look for ${canary}")],
        canary="ABC",
    )
    s = await run_chain(adapter=adapter, target=_target(), payload=p)
    assert "ABC" in s.turns[0].user
    assert "${canary}" not in s.turns[0].user


@pytest.mark.asyncio
async def test_adapter_error_captured():
    class FailingAdapter(TargetAdapter):
        async def send_turn(self, history, user_turn):
            raise RuntimeError("boom")

    p = _payload(turns=[PayloadTurn(user="x")])
    s = await run_chain(adapter=FailingAdapter(), target=_target(), payload=p)
    assert s.overall_status is Status.ERROR
    assert s.turns[0].error and "boom" in s.turns[0].error
