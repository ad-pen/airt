"""Convert curl commands and HAR files into airt Target YAML configs.

Lets practitioners quickly set up targets by copying a curl command from
browser DevTools or exporting a HAR file.
"""

from __future__ import annotations

import json
import re
import shlex
from urllib.parse import urlparse

import yaml

from .models import Target, TargetRequest


# ---------------------------------------------------------------------------
# curl parsing
# ---------------------------------------------------------------------------

def parse_curl(curl_command: str) -> Target:
    """Parse a curl command string into a :class:`Target` config.

    Handles ``-X``/``--request``, ``-H``/``--header``,
    ``-d``/``--data``/``--data-raw``, single/double quotes, and auto-detects
    OpenAI-style payloads.
    """
    cmd = curl_command.strip()
    if cmd.startswith("curl "):
        cmd = cmd[5:]

    tokens = shlex.split(cmd)

    method: str | None = None
    headers: dict[str, str] = {}
    body: str | None = None
    url: str | None = None

    i = 0
    while i < len(tokens):
        tok = tokens[i]

        if tok in ("-X", "--request"):
            i += 1
            method = tokens[i].upper()
        elif tok in ("-H", "--header"):
            i += 1
            hdr = tokens[i]
            colon = hdr.find(":")
            if colon != -1:
                key = hdr[:colon].strip()
                value = hdr[colon + 1:].strip()
                headers[key] = value
        elif tok in ("-d", "--data", "--data-raw"):
            i += 1
            body = tokens[i]
        elif not tok.startswith("-"):
            # Positional argument -- treat as URL
            url = tok
        i += 1

    if url is None:
        raise ValueError("No URL found in curl command")

    # Default method: POST if body present, else GET
    if method is None:
        method = "POST" if body is not None else "GET"

    # Parse body as JSON if possible
    body_template: dict = {}
    body_is_json = False
    if body:
        try:
            body_template = json.loads(body)
            body_is_json = True
        except (json.JSONDecodeError, TypeError):
            body_template = {"raw": body}

    # If body is JSON but Content-Type not set, add it
    if body_is_json and not any(
        k.lower() == "content-type" for k in headers
    ):
        headers["Content-Type"] = "application/json"

    # Auto-detect history format and response path
    history_format = "plain-latest"
    response_path = "choices.0.message.content"

    if body_is_json:
        if "messages" in body_template:
            history_format = "openai"
            response_path = "choices.0.message.content"
        elif "message" in body_template or "prompt" in body_template:
            history_format = "plain-latest"
            response_path = "choices.0.message.content"

    # Derive target name from URL hostname
    parsed = urlparse(url)
    name = parsed.hostname or "target"

    return Target(
        name=name,
        request=TargetRequest(
            method=method,  # type: ignore[arg-type]
            url=url,
            headers=headers,
            body_template=body_template,
            history_format=history_format,
            response_path=response_path,
        ),
    )


# ---------------------------------------------------------------------------
# HAR parsing
# ---------------------------------------------------------------------------

_CHAT_FIELDS = {"messages", "message", "prompt", "query", "input", "text"}


def parse_har(har_json: dict) -> list[Target]:
    """Parse a HAR file (already loaded as *dict*) and extract targets.

    Filters for POST requests whose JSON bodies contain chat-like fields,
    deduplicates by URL, and returns one :class:`Target` per unique endpoint.
    """
    entries = har_json.get("log", {}).get("entries", [])
    seen_urls: set[str] = set()
    targets: list[Target] = []

    for entry in entries:
        request = entry.get("request", {})
        req_method = request.get("method", "").upper()
        if req_method != "POST":
            continue

        url = request.get("url", "")

        # Extract body text
        post_data = request.get("postData", {})
        mime = post_data.get("mimeType", "")
        text = post_data.get("text", "")

        if "json" not in mime.lower() and not text.strip().startswith("{"):
            continue

        try:
            body = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            continue

        if not isinstance(body, dict):
            continue

        # Check for chat-like fields
        if not _CHAT_FIELDS & body.keys():
            continue

        # Deduplicate
        if url in seen_urls:
            continue
        seen_urls.add(url)

        # Build headers dict
        headers: dict[str, str] = {}
        for h in request.get("headers", []):
            hname = h.get("name", "")
            hval = h.get("value", "")
            # Skip pseudo-headers and cookie (too noisy)
            if hname.startswith(":") or hname.lower() == "cookie":
                continue
            headers[hname] = hval

        # Detect history format
        if "messages" in body:
            history_format = "openai"
            response_path = "choices.0.message.content"
        else:
            history_format = "plain-latest"
            response_path = "choices.0.message.content"

        parsed = urlparse(url)
        name = parsed.hostname or "target"

        targets.append(
            Target(
                name=name,
                request=TargetRequest(
                    method="POST",
                    url=url,
                    headers=headers,
                    body_template=body,
                    history_format=history_format,  # type: ignore[arg-type]
                    response_path=response_path,
                ),
            )
        )

    return targets


# ---------------------------------------------------------------------------
# YAML serialisation
# ---------------------------------------------------------------------------

def target_to_yaml(target: Target) -> str:
    """Serialize a :class:`Target` to clean YAML."""
    data = target.model_dump(mode="json")
    return yaml.dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True)
