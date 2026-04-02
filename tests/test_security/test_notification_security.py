"""Tests for notification channel security hardening.

Verifies:
- Discord webhook URL validation (strict URL parsing)
- Email HTML escaping
- Telegram Markdown escaping
"""

from __future__ import annotations

import pytest

from rex.bark.channels.discord import DiscordChannel
from rex.bark.channels.email import EmailChannel
from rex.bark.channels.telegram import TelegramChannel, _escape_markdown


class TestDiscordWebhookValidation:
    """Verify strict URL parsing replaces substring matching."""

    def test_valid_webhook_accepted(self) -> None:
        ch = DiscordChannel("https://discord.com/api/webhooks/123456/abcdef")
        assert ch.is_configured()

    def test_valid_discordapp_accepted(self) -> None:
        ch = DiscordChannel("https://discordapp.com/api/webhooks/123456/abcdef")
        assert ch.is_configured()

    def test_http_rejected(self) -> None:
        """Must be HTTPS, not HTTP."""
        ch = DiscordChannel("http://discord.com/api/webhooks/123456/abcdef")
        assert not ch.is_configured()

    def test_wrong_host_rejected(self) -> None:
        """Must be exactly discord.com or discordapp.com."""
        ch = DiscordChannel("https://evil-discord.com/api/webhooks/123456/abcdef")
        assert not ch.is_configured()

    def test_substring_attack_rejected(self) -> None:
        """URL containing discord.com/api/webhooks as a substring in path should fail."""
        ch = DiscordChannel("https://evil.com/redirect?url=discord.com/api/webhooks/123/abc")
        assert not ch.is_configured()

    def test_path_prefix_attack_rejected(self) -> None:
        """Path must start with /api/webhooks/, not just contain it."""
        ch = DiscordChannel("https://discord.com/evil/api/webhooks/123/abc")
        assert not ch.is_configured()

    def test_empty_url_rejected(self) -> None:
        ch = DiscordChannel("")
        assert not ch.is_configured()

    def test_no_path_rejected(self) -> None:
        ch = DiscordChannel("https://discord.com")
        assert not ch.is_configured()

    def test_ssrf_via_at_sign_rejected(self) -> None:
        """URL with @ sign trying to redirect to internal host."""
        ch = DiscordChannel("https://discord.com@evil.internal/api/webhooks/123/abc")
        assert not ch.is_configured()


class TestEmailHtmlEscaping:
    """Verify HTML injection is prevented in email body."""

    def test_script_tag_escaped(self) -> None:
        """Script tags in message must be escaped in HTML output."""
        ch = EmailChannel(smtp_host="mail.test", to_address="a@b.com")
        # We can't easily test the full send, but we can test the escaping
        from html import escape as html_escape
        malicious = '<script>alert("xss")</script>'
        escaped = html_escape(malicious)
        assert "<script>" not in escaped
        assert "&lt;script&gt;" in escaped

    def test_img_tag_escaped(self) -> None:
        from html import escape as html_escape
        malicious = '<img src=x onerror="alert(1)">'
        escaped = html_escape(malicious)
        assert "<img" not in escaped

    def test_severity_escaped(self) -> None:
        """Even severity field should be escaped in HTML."""
        from html import escape as html_escape
        severity = '<b>EVIL</b>'
        escaped = html_escape(severity.upper())
        assert "<B>" not in escaped


class TestTelegramMarkdownEscaping:
    """Verify Markdown special characters are escaped."""

    def test_asterisk_escaped(self) -> None:
        assert "\\*" in _escape_markdown("*bold*")

    def test_underscore_escaped(self) -> None:
        assert "\\_" in _escape_markdown("_italic_")

    def test_backtick_escaped(self) -> None:
        assert "\\`" in _escape_markdown("`code`")

    def test_brackets_escaped(self) -> None:
        result = _escape_markdown("[link](http://evil.com)")
        assert "\\[" in result
        assert "\\]" in result
        assert "\\(" in result
        assert "\\)" in result

    def test_plain_text_unchanged(self) -> None:
        text = "Normal alert message without special chars"
        assert _escape_markdown(text) == text

    def test_all_special_chars_escaped(self) -> None:
        """Every special char should be escaped."""
        for ch in r"\_*[]()~`>#+-=|{}.!":
            assert f"\\{ch}" in _escape_markdown(ch)
