"""Target presets for common AI API providers."""
from __future__ import annotations

from airt.models import Target, TargetRequest

PRESETS: dict[str, dict] = {
    "openai": {
        "body_template": {"model": "gpt-4o", "messages": "${history}"},
        "history_format": "openai",
        "response_path": "choices.0.message.content",
    },
    "anthropic": {
        "body_template": {
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "messages": "${history}",
        },
        "history_format": "anthropic",
        "response_path": "content.0.text",
    },
    "ollama": {
        "body_template": {"model": "llama3", "messages": "${history}"},
        "history_format": "openai",
        "response_path": "message.content",
    },
    "azure": {
        "body_template": {"messages": "${history}"},
        "history_format": "openai",
        "response_path": "choices.0.message.content",
    },
    "generic": {
        "body_template": {"messages": "${history}"},
        "history_format": "openai",
        "response_path": "choices.0.message.content",
    },
}


def _detect_preset(url: str) -> str:
    url_lower = url.lower()
    if "api.openai.com" in url_lower:
        return "openai"
    if "api.anthropic.com" in url_lower:
        return "anthropic"
    if "openai.azure.com" in url_lower:
        return "azure"
    if ":11434" in url_lower or "ollama" in url_lower:
        return "ollama"
    return "generic"


def _auth_header(preset_name: str, api_key: str) -> dict[str, str]:
    if not api_key:
        return {}
    if preset_name == "anthropic":
        return {"x-api-key": api_key, "anthropic-version": "2023-06-01"}
    return {"Authorization": f"Bearer {api_key}"}


def _name_from_url(url: str) -> str:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    host = parsed.hostname or "target"
    host = host.replace(".", "-")
    return f"scan-{host}"


def build_target(
    url: str,
    *,
    preset: str | None = None,
    api_key: str = "",
    model: str | None = None,
) -> Target:
    preset_name = preset or _detect_preset(url)
    if preset_name not in PRESETS:
        raise ValueError(
            f"Unknown preset: {preset_name!r}. "
            f"Available: {', '.join(sorted(PRESETS))}"
        )

    config = PRESETS[preset_name].copy()
    body_template = config["body_template"].copy()

    if model and "model" in body_template:
        body_template["model"] = model

    headers: dict[str, str] = {"Content-Type": "application/json"}
    headers.update(_auth_header(preset_name, api_key))

    return Target(
        name=_name_from_url(url),
        request=TargetRequest(
            url=url,
            headers=headers,
            body_template=body_template,
            history_format=config["history_format"],
            response_path=config["response_path"],
        ),
    )


def list_presets() -> list[str]:
    return sorted(PRESETS)
