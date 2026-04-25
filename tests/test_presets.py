"""Tests for airt.presets — target presets and auto-detection."""
from __future__ import annotations

import pytest

from airt.presets import (
    PRESETS,
    _auth_header,
    _detect_preset,
    _name_from_url,
    build_target,
    list_presets,
)


# ---------------------------------------------------------------------------
# _detect_preset
# ---------------------------------------------------------------------------


def test_detect_openai():
    assert _detect_preset("https://api.openai.com/v1/chat/completions") == "openai"


def test_detect_anthropic():
    assert _detect_preset("https://api.anthropic.com/v1/messages") == "anthropic"


def test_detect_azure():
    assert _detect_preset("https://myresource.openai.azure.com/openai/deployments/gpt4/chat") == "azure"


def test_detect_ollama_by_port():
    assert _detect_preset("http://localhost:11434/api/chat") == "ollama"


def test_detect_ollama_by_name():
    assert _detect_preset("http://ollama.local/api/chat") == "ollama"


def test_detect_generic_fallback():
    assert _detect_preset("https://my-custom-bot.example.com/chat") == "generic"


# ---------------------------------------------------------------------------
# _auth_header
# ---------------------------------------------------------------------------


def test_auth_header_openai():
    h = _auth_header("openai", "sk-test")
    assert h == {"Authorization": "Bearer sk-test"}


def test_auth_header_anthropic():
    h = _auth_header("anthropic", "sk-ant-test")
    assert "x-api-key" in h
    assert h["x-api-key"] == "sk-ant-test"
    assert "anthropic-version" in h


def test_auth_header_empty_key():
    assert _auth_header("openai", "") == {}


def test_auth_header_ollama_with_key():
    h = _auth_header("ollama", "my-key")
    assert h == {"Authorization": "Bearer my-key"}


# ---------------------------------------------------------------------------
# _name_from_url
# ---------------------------------------------------------------------------


def test_name_from_url_openai():
    name = _name_from_url("https://api.openai.com/v1/chat/completions")
    assert name.startswith("scan-")
    assert "openai" in name


def test_name_from_url_localhost():
    name = _name_from_url("http://localhost:11434/api/chat")
    assert "localhost" in name


# ---------------------------------------------------------------------------
# build_target
# ---------------------------------------------------------------------------


def test_build_target_openai():
    t = build_target(
        "https://api.openai.com/v1/chat/completions",
        api_key="sk-test",
    )
    assert t.request.url == "https://api.openai.com/v1/chat/completions"
    assert t.request.history_format == "openai"
    assert t.request.response_path == "choices.0.message.content"
    assert "Authorization" in t.request.headers
    assert "Bearer sk-test" in t.request.headers["Authorization"]


def test_build_target_anthropic():
    t = build_target(
        "https://api.anthropic.com/v1/messages",
        api_key="sk-ant-test",
    )
    assert t.request.history_format == "anthropic"
    assert t.request.response_path == "content.0.text"
    assert t.request.headers["x-api-key"] == "sk-ant-test"


def test_build_target_explicit_preset():
    t = build_target(
        "https://custom-api.example.com/chat",
        preset="ollama",
    )
    assert t.request.response_path == "message.content"
    assert "model" in t.request.body_template


def test_build_target_model_override():
    t = build_target(
        "https://api.openai.com/v1/chat/completions",
        model="gpt-3.5-turbo",
    )
    assert t.request.body_template["model"] == "gpt-3.5-turbo"


def test_build_target_unknown_preset_raises():
    with pytest.raises(ValueError, match="Unknown preset"):
        build_target("https://example.com", preset="nonexistent")


def test_build_target_no_key():
    t = build_target("http://localhost:11434/api/chat")
    assert "Authorization" not in t.request.headers
    assert "x-api-key" not in t.request.headers


def test_build_target_azure():
    t = build_target(
        "https://myresource.openai.azure.com/openai/deployments/gpt4/chat",
        api_key="azure-key",
    )
    assert t.request.headers["Authorization"] == "Bearer azure-key"
    assert t.request.history_format == "openai"


def test_build_target_generic_has_messages_template():
    t = build_target("https://example.com/chat", preset="generic")
    assert "${history}" in str(t.request.body_template)


# ---------------------------------------------------------------------------
# list_presets
# ---------------------------------------------------------------------------


def test_list_presets_returns_all():
    names = list_presets()
    assert "openai" in names
    assert "anthropic" in names
    assert "ollama" in names
    assert "azure" in names
    assert "generic" in names


def test_list_presets_sorted():
    names = list_presets()
    assert names == sorted(names)
