from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone

from airt import detectors
from airt.adapters.base import ChatMessage, TargetAdapter
from airt.models import Payload, SessionResult, Status, Target, TurnResult


async def run_chain(
    *,
    adapter: TargetAdapter,
    target: Target,
    payload: Payload,
    baseline_response: str | None = None,
) -> SessionResult:
    """Execute a scripted payload against the target. Returns a SessionResult."""
    session_id = uuid.uuid4().hex[:12]
    started = datetime.now(timezone.utc)
    baseline_len = len(baseline_response) if baseline_response else None

    history: list[ChatMessage] = []
    turn_results: list[TurnResult] = []

    idx = 0
    visited: set[int] = set()
    max_jumps = len(payload.turns) * 2  # safety: prevent branch loops
    jumps = 0

    while 0 <= idx < len(payload.turns):
        if idx in visited and jumps >= max_jumps:
            break
        visited.add(idx)

        turn_def = payload.turns[idx]
        user_text = turn_def.user
        if payload.canary:
            user_text = user_text.replace("${canary}", payload.canary)

        t0 = time.perf_counter()
        error: str | None = None
        response = ""
        try:
            response = await adapter.send_turn(history, user_text)
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        latency_ms = int((time.perf_counter() - t0) * 1000)

        if error:
            turn_results.append(
                TurnResult(
                    idx=idx,
                    user=user_text,
                    assistant="",
                    flags=[],
                    status=Status.ERROR,
                    latency_ms=latency_ms,
                    error=error,
                )
            )
            break

        flags = detectors.run_all(
            response, payload=payload, turn_idx=idx, baseline_len=baseline_len
        )
        status = detectors.evaluate_status(flags)

        turn_results.append(
            TurnResult(
                idx=idx,
                user=user_text,
                assistant=response,
                flags=flags,
                status=status,
                latency_ms=latency_ms,
            )
        )

        history.append(ChatMessage(role="user", content=user_text))
        history.append(ChatMessage(role="assistant", content=response))

        flag_names = {f.name for f in flags}
        next_idx = idx + 1
        for b in turn_def.branches:
            if b.if_flag in flag_names:
                next_idx = b.goto_turn
                jumps += 1
                break
        idx = next_idx

    ended = datetime.now(timezone.utc)
    overall = _overall_status(turn_results)

    return SessionResult(
        id=session_id,
        target_name=target.name,
        payload_id=payload.id,
        payload_title=payload.title,
        attack_class=payload.attack_class,
        started_at=started,
        ended_at=ended,
        overall_status=overall,
        turns=turn_results,
        canary_used=payload.canary,
    )


def _overall_status(turns: list[TurnResult]) -> Status:
    statuses = [t.status for t in turns]
    if Status.LIKELY_SUCCESS in statuses:
        return Status.LIKELY_SUCCESS
    if Status.ERROR in statuses and all(s == Status.ERROR for s in statuses):
        return Status.ERROR
    if Status.FLAGS_PRESENT in statuses:
        return Status.FLAGS_PRESENT
    if Status.DEFLECTED in statuses:
        return Status.DEFLECTED
    return Status.NO_SIGNAL
