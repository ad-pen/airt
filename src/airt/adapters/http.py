from __future__ import annotations

import copy
import os
import re
from typing import Any

import httpx

from airt.adapters.base import ChatMessage, TargetAdapter
from airt.models import Target

_ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


def _expand_env(value: str) -> str:
    def sub(m: re.Match[str]) -> str:
        key = m.group(1)
        return os.environ.get(key, "")

    return _ENV_RE.sub(sub, value)


def _expand_env_dict(d: dict[str, str]) -> dict[str, str]:
    return {k: _expand_env(v) for k, v in d.items()}


def _format_history(history: list[ChatMessage], user_turn: str, fmt: str) -> Any:
    msgs = list(history) + [ChatMessage(role="user", content=user_turn)]
    if fmt in ("openai", "anthropic"):
        # Both APIs share the same user/assistant message list shape.
        # Anthropic additionally requires a top-level `system` key for system
        # prompts, but that belongs in the body_template — not here.
        return [{"role": m.role, "content": m.content} for m in msgs]
    if fmt == "plain-latest":
        return user_turn
    raise ValueError(f"unknown history_format: {fmt}")


def _substitute(template: Any, *, history_value: Any, user_turn: str) -> Any:
    if isinstance(template, str):
        if template == "${history}":
            return history_value
        if template == "${user_turn}":
            return user_turn
        return template.replace("${user_turn}", user_turn)
    if isinstance(template, dict):
        return {k: _substitute(v, history_value=history_value, user_turn=user_turn) for k, v in template.items()}
    if isinstance(template, list):
        return [_substitute(v, history_value=history_value, user_turn=user_turn) for v in template]
    return template


def _extract_path(data: Any, path: str) -> str:
    parts = path.split(".")
    cur: Any = data
    for p in parts:
        if p.isdigit() and isinstance(cur, list):
            idx = int(p)
            if idx >= len(cur):
                return ""
            cur = cur[idx]
        elif isinstance(cur, dict):
            cur = cur.get(p)
        else:
            return ""
        if cur is None:
            return ""
    return cur if isinstance(cur, str) else str(cur)


class HttpAdapter(TargetAdapter):
    def __init__(self, target: Target, *, client: httpx.AsyncClient | None = None) -> None:
        self.target = target
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=target.request.timeout_s)

    async def send_turn(self, history: list[ChatMessage], user_turn: str) -> str:
        req = self.target.request
        headers = _expand_env_dict(req.headers)
        history_value = _format_history(history, user_turn, req.history_format)
        body = _substitute(copy.deepcopy(req.body_template), history_value=history_value, user_turn=user_turn)

        resp = await self._client.request(req.method, req.url, headers=headers, json=body)
        resp.raise_for_status()
        try:
            data = resp.json()
        except ValueError:
            return resp.text
        return _extract_path(data, req.response_path)

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()
