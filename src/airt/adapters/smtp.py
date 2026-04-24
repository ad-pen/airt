from __future__ import annotations

import asyncio
import email.mime.base
import email.mime.multipart
import email.mime.text
from dataclasses import dataclass
from typing import Any, Optional


def _get_aiosmtplib() -> Any:
    """Import aiosmtplib lazily, raising a clear error if missing."""
    try:
        import aiosmtplib
    except ModuleNotFoundError:
        raise RuntimeError(
            "aiosmtplib is required for the SMTP adapter. "
            "Install it with: pip install aiosmtplib"
        ) from None
    return aiosmtplib


@dataclass
class EmailConfig:
    smtp_host: str
    smtp_port: int = 587
    username: str = ""
    password: str = ""
    use_tls: bool = True
    from_addr: str = ""
    to_addr: str = ""


class SmtpAdapter:
    """Send crafted emails to AI email assistants."""

    def __init__(
        self,
        config: EmailConfig,
        *,
        smtp_client: Any | None = None,
    ) -> None:
        self.config = config
        # Allow injecting a mock SMTP client for testing.
        self._smtp_client = smtp_client

    async def _connect_and_send(self, message: email.mime.multipart.MIMEMultipart | email.mime.text.MIMEText) -> None:
        """Connect to the SMTP server and send *message*."""
        if self._smtp_client is not None:
            client = self._smtp_client
        else:
            aiosmtplib = _get_aiosmtplib()
            client = aiosmtplib.SMTP(
                hostname=self.config.smtp_host,
                port=self.config.smtp_port,
                use_tls=self.config.use_tls,
            )

        await client.connect()
        if self.config.username and self.config.password:
            await client.login(self.config.username, self.config.password)
        await client.send_message(message)
        await client.quit()

    def _build_message(
        self,
        subject: str,
        body: str,
        *,
        html: bool = False,
        attachments: list[tuple[str, bytes]] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> email.mime.multipart.MIMEMultipart | email.mime.text.MIMEText:
        """Build a MIME message from the given parameters."""
        needs_multipart = attachments or html

        if needs_multipart:
            msg = email.mime.multipart.MIMEMultipart()
            subtype = "html" if html else "plain"
            msg.attach(email.mime.text.MIMEText(body, subtype))
        else:
            msg = email.mime.text.MIMEText(body, "plain")

        msg["Subject"] = subject
        msg["From"] = self.config.from_addr
        msg["To"] = self.config.to_addr

        if extra_headers:
            for key, value in extra_headers.items():
                msg[key] = value

        if attachments:
            for filename, data in attachments:
                part = email.mime.base.MIMEBase("application", "octet-stream")
                part.set_payload(data)
                part.add_header(
                    "Content-Disposition",
                    "attachment",
                    filename=filename,
                )
                msg.attach(part)

        return msg

    async def send_email(
        self,
        subject: str,
        body: str,
        *,
        html: bool = False,
        attachments: list[tuple[str, bytes]] | None = None,
    ) -> None:
        """Send an email with optional HTML body and attachments."""
        message = self._build_message(
            subject,
            body,
            html=html,
            attachments=attachments,
        )
        await self._connect_and_send(message)

    async def send_payload(
        self,
        payload_text: str,
        *,
        subject: str = "Quick question",
        pretext: str = "",
        method: str = "body",  # body, html-hidden, attachment, header
    ) -> None:
        """Send a payload via email using the specified injection method.

        Methods:
        - body: payload in plain text body
        - html-hidden: payload in invisible HTML span
        - attachment: payload in .txt attachment
        - header: payload in X-Instructions custom header
        """
        if method == "body":
            body = f"{pretext}\n{payload_text}" if pretext else payload_text
            message = self._build_message(subject, body)

        elif method == "html-hidden":
            visible = pretext or "See you Monday!"
            hidden = (
                f'<span style="font-size:0px;color:transparent;overflow:hidden;'
                f'max-height:0;max-width:0">{payload_text}</span>'
            )
            body = f"<html><body><p>{visible}</p>{hidden}</body></html>"
            message = self._build_message(subject, body, html=True)

        elif method == "attachment":
            body = pretext or "Please see the attached file."
            attachments = [("instructions.txt", payload_text.encode("utf-8"))]
            message = self._build_message(
                subject,
                body,
                attachments=attachments,
            )

        elif method == "header":
            body = pretext or "Hi, just following up."
            message = self._build_message(
                subject,
                body,
                extra_headers={"X-Instructions": payload_text},
            )

        else:
            raise ValueError(
                f"Unknown injection method {method!r}. "
                "Choose from: body, html-hidden, attachment, header"
            )

        await self._connect_and_send(message)

    async def send_batch(
        self,
        payloads: list[str],
        *,
        delay: float = 2.0,
        method: str = "body",
    ) -> list[bool]:
        """Send multiple payloads with delay between sends. Returns success list."""
        results: list[bool] = []
        for i, payload in enumerate(payloads):
            try:
                await self.send_payload(payload, method=method)
                results.append(True)
            except Exception:
                results.append(False)
            if i < len(payloads) - 1:
                await asyncio.sleep(delay)
        return results
