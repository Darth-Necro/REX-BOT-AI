"""Tests for rex.bark.channels.email -- EmailChannel implementation."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from rex.bark.channels.email import EmailChannel

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _configured_channel(**overrides: str) -> EmailChannel:
    """Return an EmailChannel with valid SMTP config."""
    defaults = {
        "smtp_host": "smtp.example.com",
        "smtp_port": 587,
        "smtp_user": "rex@example.com",
        "smtp_pass": "secret",
        "to_address": "admin@example.com",
    }
    defaults.update(overrides)
    return EmailChannel(**defaults)


# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------

class TestEmailChannelConfig:
    """Configuration and identity tests."""

    def test_channel_name(self) -> None:
        ch = EmailChannel()
        assert ch.channel_name == "email"

    def test_unconfigured_no_host(self) -> None:
        ch = EmailChannel(to_address="admin@example.com")
        assert ch.is_configured() is False

    def test_unconfigured_no_to(self) -> None:
        ch = EmailChannel(smtp_host="smtp.example.com")
        assert ch.is_configured() is False

    def test_unconfigured_both_empty(self) -> None:
        ch = EmailChannel()
        assert ch.is_configured() is False

    def test_configured_with_host_and_to(self) -> None:
        ch = _configured_channel()
        assert ch.is_configured() is True

    def test_configured_minimal(self) -> None:
        """Only host and to_address are required for is_configured."""
        ch = EmailChannel(smtp_host="smtp.example.com", to_address="a@b.com")
        assert ch.is_configured() is True


# ------------------------------------------------------------------
# send() -- success path
# ------------------------------------------------------------------

class TestEmailSendSuccess:
    """Tests for successful email delivery."""

    async def test_send_returns_true(self) -> None:
        ch = _configured_channel()
        mock_server = MagicMock()
        mock_server.__enter__ = MagicMock(return_value=mock_server)
        mock_server.__exit__ = MagicMock(return_value=False)

        with patch("rex.bark.channels.email.smtplib.SMTP", return_value=mock_server):
            result = await ch.send("Intruder detected")

        assert result is True

    async def test_send_calls_starttls(self) -> None:
        ch = _configured_channel()
        mock_server = MagicMock()
        mock_server.__enter__ = MagicMock(return_value=mock_server)
        mock_server.__exit__ = MagicMock(return_value=False)

        with patch("rex.bark.channels.email.smtplib.SMTP", return_value=mock_server):
            await ch.send("test")

        mock_server.starttls.assert_called_once()

    async def test_send_calls_login_when_credentials_set(self) -> None:
        ch = _configured_channel()
        mock_server = MagicMock()
        mock_server.__enter__ = MagicMock(return_value=mock_server)
        mock_server.__exit__ = MagicMock(return_value=False)

        with patch("rex.bark.channels.email.smtplib.SMTP", return_value=mock_server):
            await ch.send("test")

        mock_server.login.assert_called_once_with("rex@example.com", "secret")

    async def test_send_skips_login_without_credentials(self) -> None:
        ch = EmailChannel(smtp_host="smtp.example.com", to_address="a@b.com")
        mock_server = MagicMock()
        mock_server.__enter__ = MagicMock(return_value=mock_server)
        mock_server.__exit__ = MagicMock(return_value=False)

        with patch("rex.bark.channels.email.smtplib.SMTP", return_value=mock_server):
            await ch.send("test")

        mock_server.login.assert_not_called()

    async def test_send_calls_sendmail(self) -> None:
        ch = _configured_channel()
        mock_server = MagicMock()
        mock_server.__enter__ = MagicMock(return_value=mock_server)
        mock_server.__exit__ = MagicMock(return_value=False)

        with patch("rex.bark.channels.email.smtplib.SMTP", return_value=mock_server):
            await ch.send("test message")

        mock_server.sendmail.assert_called_once()
        args = mock_server.sendmail.call_args
        assert args[0][0] == "rex@example.com"     # from
        assert args[0][1] == ["admin@example.com"]  # to list

    async def test_send_constructs_smtp_with_host_port_timeout(self) -> None:
        ch = _configured_channel()
        mock_server = MagicMock()
        mock_server.__enter__ = MagicMock(return_value=mock_server)
        mock_server.__exit__ = MagicMock(return_value=False)

        with patch("rex.bark.channels.email.smtplib.SMTP", return_value=mock_server) as smtp_cls:
            await ch.send("test")

        smtp_cls.assert_called_once_with("smtp.example.com", 587, timeout=10)


# ------------------------------------------------------------------
# send() -- email content (HTML + plaintext)
# ------------------------------------------------------------------

class TestEmailContent:
    """Tests for email message structure."""

    async def test_email_has_html_and_plain_parts(self) -> None:
        """Email must contain both a text/plain and text/html MIME part."""
        ch = _configured_channel()
        captured_msg = None

        mock_server = MagicMock()
        mock_server.__enter__ = MagicMock(return_value=mock_server)
        mock_server.__exit__ = MagicMock(return_value=False)

        def capture_sendmail(from_addr, to_addrs, msg_string):
            nonlocal captured_msg
            captured_msg = msg_string

        mock_server.sendmail.side_effect = capture_sendmail

        with patch("rex.bark.channels.email.smtplib.SMTP", return_value=mock_server):
            await ch.send("Plain text body", {"severity": "critical", "title": "Breach"})

        assert captured_msg is not None
        assert "text/plain" in captured_msg
        assert "text/html" in captured_msg

    async def test_plain_part_contains_message(self) -> None:
        ch = _configured_channel()
        captured_msg = None

        mock_server = MagicMock()
        mock_server.__enter__ = MagicMock(return_value=mock_server)
        mock_server.__exit__ = MagicMock(return_value=False)
        mock_server.sendmail.side_effect = lambda f, t, m: setattr(
            type("_ns", (), {"msg": None}), "msg", m
        ) or None

        def capture(f, t, m):
            nonlocal captured_msg
            captured_msg = m

        mock_server.sendmail.side_effect = capture

        with patch("rex.bark.channels.email.smtplib.SMTP", return_value=mock_server):
            await ch.send("Alert: rogue device found")

        assert "Alert: rogue device found" in captured_msg

    async def test_html_part_contains_severity(self) -> None:
        ch = _configured_channel()
        captured_msg = None

        mock_server = MagicMock()
        mock_server.__enter__ = MagicMock(return_value=mock_server)
        mock_server.__exit__ = MagicMock(return_value=False)

        def capture(f, t, m):
            nonlocal captured_msg
            captured_msg = m

        mock_server.sendmail.side_effect = capture

        with patch("rex.bark.channels.email.smtplib.SMTP", return_value=mock_server):
            await ch.send("alert body", {"severity": "high", "title": "Test"})

        assert "HIGH" in captured_msg

    async def test_subject_includes_severity_and_title(self) -> None:
        ch = _configured_channel()
        captured_msg = None

        mock_server = MagicMock()
        mock_server.__enter__ = MagicMock(return_value=mock_server)
        mock_server.__exit__ = MagicMock(return_value=False)

        def capture(f, t, m):
            nonlocal captured_msg
            captured_msg = m

        mock_server.sendmail.side_effect = capture

        with patch("rex.bark.channels.email.smtplib.SMTP", return_value=mock_server):
            await ch.send("body", {"severity": "critical", "title": "Intrusion"})

        assert "[REX CRITICAL] Intrusion" in captured_msg

    async def test_default_metadata(self) -> None:
        """When metadata is None, defaults should be used."""
        ch = _configured_channel()
        captured_msg = None

        mock_server = MagicMock()
        mock_server.__enter__ = MagicMock(return_value=mock_server)
        mock_server.__exit__ = MagicMock(return_value=False)

        def capture(f, t, m):
            nonlocal captured_msg
            captured_msg = m

        mock_server.sendmail.side_effect = capture

        with patch("rex.bark.channels.email.smtplib.SMTP", return_value=mock_server):
            await ch.send("simple alert")

        assert "[REX INFO] Security Alert" in captured_msg

    async def test_from_fallback_without_user(self) -> None:
        """When smtp_user is empty, From should be rex@<host>."""
        ch = EmailChannel(smtp_host="mail.test.org", to_address="a@b.com")
        captured_msg = None

        mock_server = MagicMock()
        mock_server.__enter__ = MagicMock(return_value=mock_server)
        mock_server.__exit__ = MagicMock(return_value=False)

        def capture(f, t, m):
            nonlocal captured_msg
            captured_msg = m

        mock_server.sendmail.side_effect = capture

        with patch("rex.bark.channels.email.smtplib.SMTP", return_value=mock_server):
            await ch.send("test")

        # From header in the MIME message
        assert "rex@mail.test.org" in captured_msg


# ------------------------------------------------------------------
# send() -- failure path
# ------------------------------------------------------------------

class TestEmailSendFailure:
    """Tests for failed delivery."""

    async def test_send_unconfigured_returns_false(self) -> None:
        ch = EmailChannel()
        result = await ch.send("test")
        assert result is False

    async def test_smtp_exception_returns_false(self) -> None:
        ch = _configured_channel()

        with patch(
            "rex.bark.channels.email.smtplib.SMTP",
            side_effect=ConnectionRefusedError("connection refused"),
        ):
            result = await ch.send("test")

        assert result is False

    async def test_smtp_timeout_returns_false(self) -> None:
        ch = _configured_channel()

        with patch(
            "rex.bark.channels.email.smtplib.SMTP",
            side_effect=TimeoutError("timed out"),
        ):
            result = await ch.send("test")

        assert result is False

    async def test_login_failure_returns_false(self) -> None:
        ch = _configured_channel()
        mock_server = MagicMock()
        mock_server.__enter__ = MagicMock(return_value=mock_server)
        mock_server.__exit__ = MagicMock(return_value=False)
        mock_server.login.side_effect = Exception("auth failed")

        with patch("rex.bark.channels.email.smtplib.SMTP", return_value=mock_server):
            result = await ch.send("test")

        assert result is False


# ------------------------------------------------------------------
# test()
# ------------------------------------------------------------------

class TestEmailTest:
    """Tests for the test() method."""

    async def test_method_sends_test_message(self) -> None:
        ch = _configured_channel()
        mock_server = MagicMock()
        mock_server.__enter__ = MagicMock(return_value=mock_server)
        mock_server.__exit__ = MagicMock(return_value=False)

        with patch("rex.bark.channels.email.smtplib.SMTP", return_value=mock_server):
            result = await ch.test()

        assert result is True
        mock_server.sendmail.assert_called_once()

    async def test_method_uses_info_severity(self) -> None:
        ch = _configured_channel()
        captured_msg = None

        mock_server = MagicMock()
        mock_server.__enter__ = MagicMock(return_value=mock_server)
        mock_server.__exit__ = MagicMock(return_value=False)

        def capture(f, t, m):
            nonlocal captured_msg
            captured_msg = m

        mock_server.sendmail.side_effect = capture

        with patch("rex.bark.channels.email.smtplib.SMTP", return_value=mock_server):
            await ch.test()

        assert "[REX INFO] REX Test" in captured_msg

    async def test_method_returns_false_when_unconfigured(self) -> None:
        ch = EmailChannel()
        result = await ch.test()
        assert result is False
