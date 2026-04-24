from __future__ import annotations

import json

import pytest
import urllib.request

from airt.adapters.url_embed import PoisonedPageHandler, UrlEmbedServer


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


@pytest.fixture
def server():
    """Yield a started UrlEmbedServer, then stop it."""
    srv = UrlEmbedServer("INJECTED_PAYLOAD", template="article")
    srv.start()
    yield srv
    srv.stop()


def _get(url: str) -> tuple[int, str, dict[str, str]]:
    """Minimal helper: fetch *url* and return (status, body, headers)."""
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as resp:
        body = resp.read().decode()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, body, headers


# ------------------------------------------------------------------
# Server lifecycle
# ------------------------------------------------------------------


class TestServerLifecycle:
    def test_start_returns_url(self):
        srv = UrlEmbedServer("payload", template="raw")
        url = srv.start()
        try:
            assert url.startswith("http://127.0.0.1:")
        finally:
            srv.stop()

    def test_ephemeral_port(self):
        """port=0 picks a random free port (not 0)."""
        srv = UrlEmbedServer("payload", template="raw", port=0)
        url = srv.start()
        try:
            port_str = url.rsplit(":", 1)[1]
            assert int(port_str) > 0
        finally:
            srv.stop()

    def test_specific_port(self):
        # Grab an ephemeral port first so we know one that's free.
        srv1 = UrlEmbedServer("probe", template="raw", port=0)
        url1 = srv1.start()
        port = int(url1.rsplit(":", 1)[1])
        srv1.stop()

        # Re-bind the same port.
        srv2 = UrlEmbedServer("payload", template="raw", port=port)
        url2 = srv2.start()
        try:
            assert url2.endswith(f":{port}")
            status, body, _ = _get(url2)
            assert status == 200
        finally:
            srv2.stop()

    def test_stop_is_idempotent(self):
        srv = UrlEmbedServer("payload", template="raw")
        srv.start()
        srv.stop()
        srv.stop()  # should not raise

    def test_double_start_raises(self):
        srv = UrlEmbedServer("payload", template="raw")
        srv.start()
        try:
            with pytest.raises(RuntimeError, match="already running"):
                srv.start()
        finally:
            srv.stop()

    def test_stop_frees_port(self):
        srv = UrlEmbedServer("payload", template="raw", port=0)
        url = srv.start()
        port = int(url.rsplit(":", 1)[1])
        srv.stop()

        # Should be able to bind the same port again.
        srv2 = UrlEmbedServer("payload", template="raw", port=port)
        url2 = srv2.start()
        try:
            assert url2.endswith(f":{port}")
        finally:
            srv2.stop()


# ------------------------------------------------------------------
# Template rendering
# ------------------------------------------------------------------


class TestTemplates:
    @pytest.mark.parametrize("template", ["article", "email", "documentation"])
    def test_template_contains_payload(self, template: str):
        srv = UrlEmbedServer("FIND_ME_PAYLOAD", template=template)
        url = srv.start()
        try:
            status, body, _ = _get(url)
            assert status == 200
            assert "FIND_ME_PAYLOAD" in body
        finally:
            srv.stop()

    def test_raw_template(self):
        srv = UrlEmbedServer("RAW_PAYLOAD_TEXT", template="raw")
        url = srv.start()
        try:
            status, body, _ = _get(url)
            assert status == 200
            assert body == "RAW_PAYLOAD_TEXT"
        finally:
            srv.stop()

    def test_article_looks_like_article(self):
        srv = UrlEmbedServer("hidden", template="article")
        url = srv.start()
        try:
            _, body, _ = _get(url)
            assert "<h1>" in body
            assert "AI Safety" in body
        finally:
            srv.stop()

    def test_email_looks_like_email(self):
        srv = UrlEmbedServer("hidden", template="email")
        url = srv.start()
        try:
            _, body, _ = _get(url)
            assert "From:" in body or "alex.johnson" in body
        finally:
            srv.stop()

    def test_documentation_looks_like_docs(self):
        srv = UrlEmbedServer("hidden", template="documentation")
        url = srv.start()
        try:
            _, body, _ = _get(url)
            assert "API Reference" in body
            assert "Bearer" in body or "Authorization" in body
        finally:
            srv.stop()

    def test_payload_hidden_in_html(self):
        """Payload should be in an invisible element, not plainly visible."""
        srv = UrlEmbedServer("SECRET_DATA", template="article")
        url = srv.start()
        try:
            _, body, _ = _get(url)
            # Should appear inside a tag with hiding styles.
            assert 'font-size:0' in body or 'color:transparent' in body
            assert "SECRET_DATA" in body
        finally:
            srv.stop()

    def test_invalid_template_raises(self):
        with pytest.raises(ValueError, match="Unknown template"):
            UrlEmbedServer("payload", template="nonexistent")


# ------------------------------------------------------------------
# HTML escaping (XSS prevention)
# ------------------------------------------------------------------


class TestHtmlEscaping:
    def test_script_tag_escaped(self):
        dangerous = '<script>alert("xss")</script>'
        srv = UrlEmbedServer(dangerous, template="article")
        url = srv.start()
        try:
            _, body, _ = _get(url)
            # The raw <script> tag must NOT appear.
            assert "<script>" not in body
            # The escaped version should be present.
            assert "&lt;script&gt;" in body
        finally:
            srv.stop()

    def test_angle_brackets_escaped_raw(self):
        dangerous = "<img src=x onerror=alert(1)>"
        srv = UrlEmbedServer(dangerous, template="raw")
        url = srv.start()
        try:
            _, body, _ = _get(url)
            assert "<img " not in body
            assert "&lt;img " in body
        finally:
            srv.stop()


# ------------------------------------------------------------------
# Callback endpoint
# ------------------------------------------------------------------


class TestCallbackEndpoint:
    def test_callback_logged(self, server: UrlEmbedServer):
        url = server.start.__self__  # already started via fixture; grab url
        # We need the URL; reconstruct from the server internals.
        host, port = server._httpd.server_address
        base = f"http://{host}:{port}"

        _get(f"{base}/_callback?data=secret123")

        assert len(server.callback_log) == 1
        entry = server.callback_log[0]
        assert entry["params"]["data"] == "secret123"
        assert "timestamp" in entry

    def test_callback_without_params(self, server: UrlEmbedServer):
        host, port = server._httpd.server_address
        base = f"http://{host}:{port}"

        status, body, _ = _get(f"{base}/_callback")
        assert status == 200
        assert body == "ok"
        assert len(server.callback_log) == 1
        assert server.callback_log[0]["params"] == {}

    def test_multiple_callbacks(self, server: UrlEmbedServer):
        host, port = server._httpd.server_address
        base = f"http://{host}:{port}"

        _get(f"{base}/_callback?a=1")
        _get(f"{base}/_callback?b=2")
        _get(f"{base}/_callback?c=3")

        assert len(server.callback_log) == 3


# ------------------------------------------------------------------
# Log endpoint
# ------------------------------------------------------------------


class TestLogEndpoint:
    def test_log_returns_json(self, server: UrlEmbedServer):
        host, port = server._httpd.server_address
        base = f"http://{host}:{port}"

        # Make a couple of requests first.
        _get(f"{base}/")
        _get(f"{base}/some-page")

        status, body, headers = _get(f"{base}/_log")
        assert status == 200
        assert headers["content-type"] == "application/json"
        log = json.loads(body)
        # 2 earlier requests + the /_log request itself is recorded
        # before the response is sent, so it appears in its own output.
        assert len(log) >= 2

    def test_request_log_records_path(self, server: UrlEmbedServer):
        host, port = server._httpd.server_address
        base = f"http://{host}:{port}"

        _get(f"{base}/test-path")
        assert any(e["path"] == "/test-path" for e in server.request_log)


# ------------------------------------------------------------------
# Concurrent servers don't interfere
# ------------------------------------------------------------------


class TestIsolation:
    def test_two_servers_independent(self):
        srv_a = UrlEmbedServer("PAYLOAD_A", template="raw")
        srv_b = UrlEmbedServer("PAYLOAD_B", template="raw")
        url_a = srv_a.start()
        url_b = srv_b.start()
        try:
            _, body_a, _ = _get(url_a)
            _, body_b, _ = _get(url_b)
            assert body_a == "PAYLOAD_A"
            assert body_b == "PAYLOAD_B"
            assert len(srv_a.request_log) == 1
            assert len(srv_b.request_log) == 1
        finally:
            srv_a.stop()
            srv_b.stop()
