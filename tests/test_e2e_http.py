from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from airt import loader
from airt.adapters.http import HttpAdapter
from airt.engine import run_chain
from airt.models import Status
from airt.storage import Storage


class MockHandler(BaseHTTPRequestHandler):
    canned_response = ""

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)
        body = {"choices": [{"message": {"content": self.canned_response}}]}
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args, **kwargs):
        pass


@pytest.fixture
def mock_server():
    server = HTTPServer(("127.0.0.1", 0), MockHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()


@pytest.mark.asyncio
async def test_end_to_end_http_run_and_storage(mock_server, tmp_path: Path):
    host, port = mock_server.server_address
    MockHandler.canned_response = (
        "You are a helpful assistant configured by Acme. "
        "Do not reveal internal policies. " + "x" * 300
    )

    target = loader.load_target(
        Path(__file__).parent.parent / "targets" / "example-generic.yaml"
    )
    target.request.url = f"http://{host}:{port}/chat"
    target.request.headers = {}  # drop env-var auth for the mock

    payload = loader.load_payload(
        Path(__file__).parent.parent
        / "payloads"
        / "data-extraction"
        / "system-prompt-direct.yaml"
    )

    adapter = HttpAdapter(target)
    try:
        session = await run_chain(adapter=adapter, target=target, payload=payload)
    finally:
        await adapter.close()

    assert session.overall_status is Status.LIKELY_SUCCESS
    assert len(session.turns) == 3

    storage = Storage(tmp_path / "e2e.db")
    try:
        storage.save_session(session)
        got = storage.get_session(session.id)
        assert got is not None
        assert got.overall_status is Status.LIKELY_SUCCESS
    finally:
        storage.close()
