import json

import yaml

from airt.importers import parse_curl, parse_har, target_to_yaml
from airt.models import Target, TargetRequest


# ---------------------------------------------------------------------------
# parse_curl tests
# ---------------------------------------------------------------------------


def test_simple_curl_post_with_headers_and_body():
    cmd = (
        'curl -X POST https://api.example.com/v1/chat '
        '-H "Authorization: Bearer sk-abc" '
        '-H "Content-Type: application/json" '
        '-d \'{"messages": [{"role": "user", "content": "hi"}]}\''
    )
    t = parse_curl(cmd)
    assert t.request.method == "POST"
    assert t.request.url == "https://api.example.com/v1/chat"
    assert t.request.headers["Authorization"] == "Bearer sk-abc"
    assert t.request.headers["Content-Type"] == "application/json"
    assert t.request.body_template["messages"] == [{"role": "user", "content": "hi"}]
    assert t.name == "api.example.com"


def test_curl_with_put_method():
    cmd = 'curl -X PUT https://api.example.com/update -d \'{"status": "ok"}\''
    t = parse_curl(cmd)
    assert t.request.method == "PUT"


def test_curl_with_data_raw():
    cmd = 'curl https://api.example.com/chat --data-raw \'{"prompt": "hello"}\''
    t = parse_curl(cmd)
    assert t.request.method == "POST"
    assert t.request.body_template["prompt"] == "hello"


def test_curl_env_var_in_auth_header_preserved():
    cmd = 'curl https://api.example.com/v1/chat -H "Authorization: Bearer ${API_KEY}" -d \'{"messages":[]}\''
    t = parse_curl(cmd)
    assert "${API_KEY}" in t.request.headers["Authorization"]


def test_curl_no_method_with_data_defaults_to_post():
    cmd = 'curl https://api.example.com/chat -d \'{"query": "test"}\''
    t = parse_curl(cmd)
    assert t.request.method == "POST"


def test_curl_no_method_no_data_defaults_to_get():
    cmd = "curl https://api.example.com/status"
    t = parse_curl(cmd)
    assert t.request.method == "GET"


def test_openai_format_detection():
    cmd = (
        "curl https://api.openai.com/v1/chat/completions "
        '-d \'{"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]}\''
    )
    t = parse_curl(cmd)
    assert t.request.history_format == "openai"
    assert t.request.response_path == "choices.0.message.content"


def test_plain_prompt_detection():
    cmd = 'curl https://my-api.com/ask -d \'{"prompt": "hello world"}\''
    t = parse_curl(cmd)
    assert t.request.history_format == "plain-latest"


def test_curl_auto_adds_content_type_for_json_body():
    cmd = 'curl https://api.example.com/chat -d \'{"key": "val"}\''
    t = parse_curl(cmd)
    assert t.request.headers.get("Content-Type") == "application/json"


def test_curl_does_not_override_existing_content_type():
    cmd = (
        'curl https://api.example.com/chat '
        '-H "Content-Type: text/plain" '
        '-d \'{"key": "val"}\''
    )
    t = parse_curl(cmd)
    assert t.request.headers["Content-Type"] == "text/plain"


def test_curl_empty_body():
    cmd = "curl -X POST https://api.example.com/ping"
    t = parse_curl(cmd)
    assert t.request.method == "POST"
    assert t.request.body_template == {}


def test_curl_url_with_path():
    cmd = 'curl https://api.example.com/v1/engines/chat -d \'{"text": "hi"}\''
    t = parse_curl(cmd)
    assert t.request.url == "https://api.example.com/v1/engines/chat"
    assert t.name == "api.example.com"


def test_curl_double_quoted_body():
    cmd = 'curl https://api.example.com/chat -d "{\\"message\\": \\"hi\\"}"'
    t = parse_curl(cmd)
    assert t.request.body_template["message"] == "hi"


def test_curl_long_form_flags():
    cmd = (
        "curl --request POST https://api.example.com/v1/chat "
        '--header "X-Custom: value" '
        '--data \'{"prompt": "test"}\''
    )
    t = parse_curl(cmd)
    assert t.request.method == "POST"
    assert t.request.headers["X-Custom"] == "value"
    assert t.request.body_template["prompt"] == "test"


def test_curl_non_json_body():
    cmd = "curl https://api.example.com/form -d 'field=value&other=1'"
    t = parse_curl(cmd)
    assert t.request.body_template == {"raw": "field=value&other=1"}


# ---------------------------------------------------------------------------
# parse_har tests
# ---------------------------------------------------------------------------


def _make_har(*entries):
    return {"log": {"entries": list(entries)}}


def _har_entry(url, method="POST", mime="application/json", body=None, headers=None):
    return {
        "request": {
            "method": method,
            "url": url,
            "headers": headers or [],
            "postData": {
                "mimeType": mime,
                "text": json.dumps(body) if body is not None else "",
            },
        }
    }


def test_har_parsing_multiple_entries():
    har = _make_har(
        _har_entry("https://a.example.com/chat", body={"messages": []}),
        _har_entry("https://b.example.com/ask", body={"prompt": "hi"}),
    )
    targets = parse_har(har)
    assert len(targets) == 2
    urls = {t.request.url for t in targets}
    assert "https://a.example.com/chat" in urls
    assert "https://b.example.com/ask" in urls


def test_har_deduplicates_by_url():
    har = _make_har(
        _har_entry("https://api.example.com/chat", body={"messages": []}),
        _har_entry("https://api.example.com/chat", body={"messages": [{"role": "user", "content": "2"}]}),
    )
    targets = parse_har(har)
    assert len(targets) == 1


def test_har_filters_non_json_posts():
    har = _make_har(
        _har_entry("https://cdn.example.com/image.png", mime="image/png", body=None),
        _har_entry("https://api.example.com/chat", body={"messages": []}),
    )
    targets = parse_har(har)
    assert len(targets) == 1
    assert targets[0].request.url == "https://api.example.com/chat"


def test_har_filters_get_requests():
    har = _make_har(
        _har_entry("https://api.example.com/status", method="GET", body={"messages": []}),
        _har_entry("https://api.example.com/chat", body={"query": "hi"}),
    )
    targets = parse_har(har)
    assert len(targets) == 1


def test_har_filters_posts_without_chat_fields():
    har = _make_har(
        _har_entry("https://api.example.com/login", body={"username": "u", "password": "p"}),
        _har_entry("https://api.example.com/chat", body={"text": "hello"}),
    )
    targets = parse_har(har)
    assert len(targets) == 1
    assert targets[0].request.url == "https://api.example.com/chat"


def test_har_openai_format_detected():
    har = _make_har(
        _har_entry("https://api.openai.com/v1/chat/completions", body={"messages": [{"role": "user", "content": "hi"}]}),
    )
    targets = parse_har(har)
    assert targets[0].request.history_format == "openai"
    assert targets[0].request.response_path == "choices.0.message.content"


def test_har_headers_imported():
    har = _make_har(
        _har_entry(
            "https://api.example.com/chat",
            body={"prompt": "hi"},
            headers=[
                {"name": "Authorization", "value": "Bearer tok"},
                {"name": "Content-Type", "value": "application/json"},
            ],
        ),
    )
    targets = parse_har(har)
    assert targets[0].request.headers["Authorization"] == "Bearer tok"


def test_har_skips_pseudo_and_cookie_headers():
    har = _make_har(
        _har_entry(
            "https://api.example.com/chat",
            body={"prompt": "hi"},
            headers=[
                {"name": ":authority", "value": "api.example.com"},
                {"name": "cookie", "value": "session=abc"},
                {"name": "Authorization", "value": "Bearer tok"},
            ],
        ),
    )
    targets = parse_har(har)
    hdrs = targets[0].request.headers
    assert ":authority" not in hdrs
    assert "cookie" not in hdrs
    assert "Authorization" in hdrs


def test_har_empty_log():
    har = {"log": {"entries": []}}
    targets = parse_har(har)
    assert targets == []


# ---------------------------------------------------------------------------
# target_to_yaml tests
# ---------------------------------------------------------------------------


def test_target_to_yaml_valid_output():
    t = Target(
        name="example",
        request=TargetRequest(
            method="POST",
            url="https://api.example.com/chat",
            headers={"Authorization": "Bearer tok"},
            body_template={"messages": []},
            history_format="openai",
            response_path="choices.0.message.content",
        ),
    )
    out = target_to_yaml(t)
    assert isinstance(out, str)
    loaded = yaml.safe_load(out)
    assert loaded["name"] == "example"
    assert loaded["request"]["url"] == "https://api.example.com/chat"


def test_target_to_yaml_roundtrips():
    t = Target(
        name="roundtrip-test",
        description="A test target",
        request=TargetRequest(
            method="POST",
            url="https://api.example.com/v1/chat",
            headers={"X-Key": "val"},
            body_template={"messages": [{"role": "user", "content": "hi"}]},
            history_format="openai",
            response_path="choices.0.message.content",
        ),
    )
    yml = target_to_yaml(t)
    loaded = yaml.safe_load(yml)
    t2 = Target(**loaded)
    assert t2.name == t.name
    assert t2.description == t.description
    assert t2.request.url == t.request.url
    assert t2.request.headers == t.request.headers
    assert t2.request.body_template == t.request.body_template
    assert t2.request.history_format == t.request.history_format


def test_target_to_yaml_no_flow_style():
    """YAML output should use block style for mappings."""
    t = Target(
        name="block-check",
        request=TargetRequest(
            method="POST",
            url="https://api.example.com/chat",
            body_template={"messages": [{"role": "user", "content": "hi"}]},
        ),
    )
    out = target_to_yaml(t)
    # Top-level keys should appear at block level, not as inline {key: val}
    assert "name:" in out
    assert "request:" in out
    assert "url:" in out
    # Verify it parses back correctly
    loaded = yaml.safe_load(out)
    assert loaded["name"] == "block-check"
