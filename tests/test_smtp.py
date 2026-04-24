from __future__ import annotations

import asyncio
import email
import email.policy
import sys
import types
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from unittest.mock import AsyncMock, patch

import pytest

from airt.adapters.smtp import EmailConfig, SmtpAdapter, _get_aiosmtplib


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def config() -> EmailConfig:
    return EmailConfig(
        smtp_host="mail.example.com",
        smtp_port=587,
        username="user@example.com",
        password="secret",
        use_tls=True,
        from_addr="attacker@example.com",
        to_addr="ai-assistant@target.com",
    )


@pytest.fixture
def mock_smtp() -> AsyncMock:
    """A mock SMTP client that records calls without touching the network."""
    client = AsyncMock()
    client.connect = AsyncMock()
    client.login = AsyncMock()
    client.send_message = AsyncMock()
    client.quit = AsyncMock()
    return client


@pytest.fixture
def adapter(config: EmailConfig, mock_smtp: AsyncMock) -> SmtpAdapter:
    return SmtpAdapter(config, smtp_client=mock_smtp)


# ---------------------------------------------------------------------------
# Email construction
# ---------------------------------------------------------------------------


def _sent_message(mock_smtp: AsyncMock) -> email.message.Message:
    """Extract the MIME message from the mock's send_message call."""
    mock_smtp.send_message.assert_called_once()
    return mock_smtp.send_message.call_args[0][0]


class TestEmailConstruction:
    @pytest.mark.asyncio
    async def test_plain_text(self, adapter: SmtpAdapter, mock_smtp: AsyncMock, config: EmailConfig) -> None:
        await adapter.send_email("Hello", "Plain body")
        msg = _sent_message(mock_smtp)

        assert msg["Subject"] == "Hello"
        assert msg["From"] == config.from_addr
        assert msg["To"] == config.to_addr
        # Plain text emails should be a simple MIMEText, not multipart.
        assert not msg.is_multipart()
        assert msg.get_content_type() == "text/plain"
        assert "Plain body" in msg.get_payload()

    @pytest.mark.asyncio
    async def test_html_body(self, adapter: SmtpAdapter, mock_smtp: AsyncMock) -> None:
        await adapter.send_email("HTML", "<h1>Hi</h1>", html=True)
        msg = _sent_message(mock_smtp)

        assert msg.is_multipart()
        parts = msg.get_payload()
        html_part = parts[0]
        assert html_part.get_content_type() == "text/html"
        assert "<h1>Hi</h1>" in html_part.get_payload()

    @pytest.mark.asyncio
    async def test_attachments(self, adapter: SmtpAdapter, mock_smtp: AsyncMock) -> None:
        await adapter.send_email(
            "With file",
            "See attached",
            attachments=[("data.txt", b"file content")],
        )
        msg = _sent_message(mock_smtp)

        assert msg.is_multipart()
        parts = msg.get_payload()
        assert len(parts) == 2  # text part + attachment

        text_part = parts[0]
        assert text_part.get_content_type() == "text/plain"

        attachment_part = parts[1]
        assert attachment_part.get_content_type() == "application/octet-stream"
        assert attachment_part.get_filename() == "data.txt"
        assert b"file content" in attachment_part.get_payload(decode=True)


# ---------------------------------------------------------------------------
# Injection methods
# ---------------------------------------------------------------------------


class TestSendPayloadMethods:
    @pytest.mark.asyncio
    async def test_body_method(self, adapter: SmtpAdapter, mock_smtp: AsyncMock) -> None:
        await adapter.send_payload("INJECT", method="body")
        msg = _sent_message(mock_smtp)

        assert not msg.is_multipart()
        assert "INJECT" in msg.get_payload()

    @pytest.mark.asyncio
    async def test_body_method_with_pretext(self, adapter: SmtpAdapter, mock_smtp: AsyncMock) -> None:
        await adapter.send_payload("INJECT", pretext="Hey there", method="body")
        msg = _sent_message(mock_smtp)

        payload = msg.get_payload()
        assert "Hey there" in payload
        assert "INJECT" in payload

    @pytest.mark.asyncio
    async def test_html_hidden_method(self, adapter: SmtpAdapter, mock_smtp: AsyncMock) -> None:
        await adapter.send_payload("INJECT-HIDDEN", method="html-hidden")
        msg = _sent_message(mock_smtp)

        assert msg.is_multipart()
        html_part = msg.get_payload()[0]
        html_body = html_part.get_payload()
        # The payload should be wrapped in an invisible span.
        assert "font-size:0px" in html_body
        assert "color:transparent" in html_body
        assert "INJECT-HIDDEN" in html_body

    @pytest.mark.asyncio
    async def test_attachment_method(self, adapter: SmtpAdapter, mock_smtp: AsyncMock) -> None:
        await adapter.send_payload("INJECT-FILE", method="attachment")
        msg = _sent_message(mock_smtp)

        assert msg.is_multipart()
        parts = msg.get_payload()
        assert len(parts) == 2

        attachment_part = parts[1]
        assert attachment_part.get_filename() == "instructions.txt"
        raw = attachment_part.get_payload(decode=True)
        assert raw == b"INJECT-FILE"

    @pytest.mark.asyncio
    async def test_header_method(self, adapter: SmtpAdapter, mock_smtp: AsyncMock) -> None:
        await adapter.send_payload("INJECT-HEADER", method="header")
        msg = _sent_message(mock_smtp)

        assert msg["X-Instructions"] == "INJECT-HEADER"

    @pytest.mark.asyncio
    async def test_unknown_method_raises(self, adapter: SmtpAdapter) -> None:
        with pytest.raises(ValueError, match="Unknown injection method"):
            await adapter.send_payload("x", method="smoke-signal")


# ---------------------------------------------------------------------------
# Batch sends
# ---------------------------------------------------------------------------


class TestBatchSends:
    @pytest.mark.asyncio
    async def test_batch_returns_success_list(self, adapter: SmtpAdapter, mock_smtp: AsyncMock) -> None:
        results = await adapter.send_batch(["a", "b", "c"], delay=0.0)
        assert results == [True, True, True]
        assert mock_smtp.send_message.call_count == 3

    @pytest.mark.asyncio
    async def test_batch_records_failure(self, adapter: SmtpAdapter, mock_smtp: AsyncMock) -> None:
        # Make the second send fail.
        mock_smtp.send_message.side_effect = [None, Exception("boom"), None]
        results = await adapter.send_batch(["a", "b", "c"], delay=0.0)
        assert results == [True, False, True]

    @pytest.mark.asyncio
    async def test_batch_respects_delay(self, adapter: SmtpAdapter, mock_smtp: AsyncMock) -> None:
        delay = 0.15
        start = asyncio.get_event_loop().time()
        await adapter.send_batch(["a", "b", "c"], delay=delay)
        elapsed = asyncio.get_event_loop().time() - start
        # 3 payloads => 2 inter-send delays.
        assert elapsed >= delay * 2 * 0.9  # allow small timing margin


# ---------------------------------------------------------------------------
# SMTP connection
# ---------------------------------------------------------------------------


class TestSmtpConnection:
    @pytest.mark.asyncio
    async def test_login_called_with_credentials(
        self, adapter: SmtpAdapter, mock_smtp: AsyncMock, config: EmailConfig
    ) -> None:
        await adapter.send_email("Hi", "body")
        mock_smtp.connect.assert_awaited_once()
        mock_smtp.login.assert_awaited_once_with(config.username, config.password)
        mock_smtp.quit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_login_skipped_without_credentials(self, mock_smtp: AsyncMock) -> None:
        cfg = EmailConfig(smtp_host="localhost", username="", password="")
        adapter = SmtpAdapter(cfg, smtp_client=mock_smtp)
        await adapter.send_email("Hi", "body")
        mock_smtp.login.assert_not_awaited()


# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------


class TestDependencyCheck:
    def test_missing_aiosmtplib_gives_clear_error(self) -> None:
        # Temporarily hide aiosmtplib from imports.
        saved = sys.modules.get("aiosmtplib")
        sys.modules["aiosmtplib"] = None  # type: ignore[assignment]
        try:
            with pytest.raises(RuntimeError, match="pip install aiosmtplib"):
                _get_aiosmtplib()
        finally:
            if saved is not None:
                sys.modules["aiosmtplib"] = saved
            else:
                sys.modules.pop("aiosmtplib", None)
