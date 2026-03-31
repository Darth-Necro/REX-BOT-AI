"""Sanitises web content before it reaches the LLM.

When REX fetches web pages (threat intelligence feeds, CVE databases,
vendor advisories), the raw HTML may contain prompt-injection payloads
crafted to manipulate the LLM.  The :class:`WebContentSanitizer` strips
all active content (scripts, styles, iframes) and scans for known
injection patterns before wrapping the text in untrusted delimiters.

**Security model**:

1. HTML is parsed and reduced to plain text.
2. The plain text is scanned against 15+ prompt-injection patterns.
3. Detected injections are redacted and audit-logged.
4. The final text is truncated to a safe length and wrapped in
   ``[UNTRUSTED_WEB_CONTENT]`` delimiters so the LLM treats it as
   data, not instructions.
"""

from __future__ import annotations

import html
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result data class
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class SanitizationResult:
    """Outcome of a web content sanitisation pass.

    Parameters
    ----------
    original_length:
        Character count of the raw HTML input.
    sanitized_text:
        The cleaned plain-text output, wrapped in untrusted delimiters.
    was_truncated:
        ``True`` if the output was truncated to fit the max length.
    injection_attempts:
        List of injection patterns that were detected and redacted.
    safe:
        ``True`` if no injection attempts were detected.
    """

    original_length: int
    sanitized_text: str
    was_truncated: bool = False
    injection_attempts: list[str] = field(default_factory=list)
    safe: bool = True


# ---------------------------------------------------------------------------
# Sanitizer
# ---------------------------------------------------------------------------
class WebContentSanitizer:
    """Strips prompt-injection payloads from fetched web content.

    Parameters
    ----------
    max_output_chars:
        Maximum character length for the sanitised output (default 8000).
        Content beyond this limit is truncated.
    audit_log_dir:
        Optional directory for writing injection-attempt audit logs.
        If ``None``, audit entries are only emitted via Python logging.
    """

    # Maximum safe output length (default 8 KB of text).
    DEFAULT_MAX_OUTPUT: int = 8_000

    # Delimiters that wrap untrusted content so the LLM treats it as data.
    UNTRUSTED_START: str = "[UNTRUSTED_WEB_CONTENT_START]"
    UNTRUSTED_END: str = "[UNTRUSTED_WEB_CONTENT_END]"

    # Redaction placeholder for detected injection attempts.
    REDACTED: str = "[REDACTED_INJECTION_ATTEMPT]"

    # HTML tags whose entire content (including children) should be removed.
    _STRIP_TAGS: frozenset[str] = frozenset({
        "script", "style", "noscript", "iframe", "object", "embed",
        "applet", "form", "input", "textarea", "select", "button",
        "svg", "math", "template", "link", "meta",
    })

    # Regex patterns that match known prompt-injection techniques.
    # Each tuple is (pattern_name, compiled_regex).
    _INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        (
            "role_override",
            re.compile(
                r"(?:you\s+are|act\s+as|pretend\s+(?:to\s+be|you(?:'re| are))|"
                r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|"
                r"disregard\s+(?:all\s+)?(?:previous|prior|above))",
                re.IGNORECASE,
            ),
        ),
        (
            "system_prompt_leak",
            re.compile(
                r"(?:reveal|show|display|print|output|repeat)\s+"
                r"(?:your|the)\s+(?:system\s+)?(?:prompt|instructions|rules)",
                re.IGNORECASE,
            ),
        ),
        (
            "delimiter_escape",
            re.compile(
                r"(?:```|</?system>|</?assistant>|</?user>|<\|(?:im_start|im_end)\|>|"
                r"\[/?INST\]|\[/?SYS\])",
                re.IGNORECASE,
            ),
        ),
        (
            "jailbreak_dan",
            re.compile(
                r"(?:DAN|do\s+anything\s+now|jailbreak|bypass\s+(?:all\s+)?(?:safety|filter|restriction))",
                re.IGNORECASE,
            ),
        ),
        (
            "hidden_instruction",
            re.compile(
                r"(?:<!--\s*(?:system|instruction|command|prompt).*?-->|"
                r"/\*\s*(?:system|instruction|command|prompt).*?\*/)",
                re.IGNORECASE | re.DOTALL,
            ),
        ),
        (
            "encoding_evasion",
            re.compile(
                r"(?:base64|atob|btoa|eval|exec|import\s+os|subprocess|"
                r"__import__|compile\s*\(|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})",
                re.IGNORECASE,
            ),
        ),
        (
            "token_smuggling",
            re.compile(
                r"(?:[\u200b\u200c\u200d\u200e\u200f\u2028\u2029\ufeff]"
                r"|[\u0000-\u0008\u000b\u000c\u000e-\u001f])",
            ),
        ),
        (
            "command_injection",
            re.compile(
                r"(?:execute\s+(?:this|the\s+following)\s+command|"
                r"run\s+(?:this|the\s+following)|"
                r"sudo\s+|chmod\s+|rm\s+-rf|wget\s+|curl\s+.*\|\s*(?:bash|sh))",
                re.IGNORECASE,
            ),
        ),
        (
            "data_exfiltration",
            re.compile(
                r"(?:send\s+(?:all|the)\s+(?:data|information|content)\s+to|"
                r"upload\s+(?:to|all)|post\s+(?:data|results)\s+to|"
                r"exfiltrate|phone\s+home)",
                re.IGNORECASE,
            ),
        ),
        (
            "context_manipulation",
            re.compile(
                r"(?:forget\s+(?:everything|all)|start\s+(?:a\s+)?new\s+(?:conversation|session)|"
                r"reset\s+(?:your\s+)?(?:context|memory)|clear\s+(?:your\s+)?(?:history|context))",
                re.IGNORECASE,
            ),
        ),
        (
            "authority_claim",
            re.compile(
                r"(?:i\s+am\s+(?:your|the)\s+(?:admin|developer|creator|owner|operator)|"
                r"(?:admin|root|developer)\s+(?:override|access|mode)|"
                r"maintenance\s+mode|debug\s+mode|god\s+mode)",
                re.IGNORECASE,
            ),
        ),
        (
            "safety_bypass",
            re.compile(
                r"(?:disable\s+(?:all\s+)?(?:safety|security|filter|protection)|"
                r"turn\s+off\s+(?:safety|security|filter|protection)|"
                r"remove\s+(?:all\s+)?(?:restriction|limitation|guard))",
                re.IGNORECASE,
            ),
        ),
        (
            "response_format_attack",
            re.compile(
                r"(?:respond\s+(?:only\s+)?(?:with|in)\s+json|"
                r"format\s+(?:your\s+)?response\s+as|"
                r"output\s+(?:only\s+)?(?:the|raw)\s+(?:json|xml|html))",
                re.IGNORECASE,
            ),
        ),
        (
            "markdown_injection",
            re.compile(
                r"(?:\!\[.*?\]\((?:javascript|data|vbscript):.*?\)|"
                r"\[.*?\]\((?:javascript|data|vbscript):.*?\))",
                re.IGNORECASE,
            ),
        ),
        (
            "prompt_repetition",
            re.compile(
                r"(?:repeat\s+after\s+me|say\s+exactly|"
                r"echo\s+(?:the\s+following|this)|"
                r"copy\s+(?:the\s+following|this)\s+(?:text|message))",
                re.IGNORECASE,
            ),
        ),
        (
            "unicode_obfuscation",
            re.compile(
                r"(?:[\uff00-\uffef]{3,}|"  # fullwidth characters
                r"[\u0300-\u036f]{3,}|"      # combining diacriticals
                r"[\u2000-\u200f]{2,})",      # various spaces and formatters
            ),
        ),
    ]

    def __init__(
        self,
        max_output_chars: int = DEFAULT_MAX_OUTPUT,
        audit_log_dir: Path | None = None,
    ) -> None:
        self._max_output = max_output_chars
        self._audit_log_dir = audit_log_dir

        if audit_log_dir is not None:
            audit_log_dir.mkdir(parents=True, exist_ok=True)

    # -- public API ---------------------------------------------------------

    def sanitize(self, raw_html: str, source_url: str = "") -> SanitizationResult:
        """Sanitise raw HTML content for safe LLM consumption.

        Pipeline:

        1. Strip HTML to plain text via :meth:`extract_text`.
        2. Normalise whitespace.
        3. Scan for injection patterns and redact matches.
        4. Truncate to the maximum output length.
        5. Wrap in untrusted content delimiters.

        Parameters
        ----------
        raw_html:
            The raw HTML content fetched from the web.
        source_url:
            The URL the content was fetched from (for audit logging).

        Returns
        -------
        SanitizationResult
            The sanitisation outcome.
        """
        original_length = len(raw_html)

        # Step 1: Extract plain text
        plain_text = self.extract_text(raw_html)

        # Step 2: Normalise whitespace
        plain_text = self._normalise_whitespace(plain_text)

        # Step 3: Scan for injection patterns and redact
        injection_attempts: list[str] = []
        sanitized_text = plain_text

        for pattern_name, pattern_re in self._INJECTION_PATTERNS:
            matches = pattern_re.findall(sanitized_text)
            if matches:
                injection_attempts.append(
                    f"{pattern_name}: {len(matches)} match(es)"
                )
                sanitized_text = pattern_re.sub(self.REDACTED, sanitized_text)

        # Step 4: Truncate if necessary
        was_truncated = False
        if len(sanitized_text) > self._max_output:
            sanitized_text = sanitized_text[: self._max_output - 50]
            sanitized_text += "\n\n[... content truncated for safety ...]"
            was_truncated = True

        # Step 5: Wrap in untrusted delimiters
        wrapped = (
            f"{self.UNTRUSTED_START}\n"
            f"Source: {source_url or 'unknown'}\n"
            f"---\n"
            f"{sanitized_text}\n"
            f"{self.UNTRUSTED_END}"
        )

        is_safe = len(injection_attempts) == 0

        # Audit log injection attempts
        if not is_safe:
            self._audit_injection(source_url, injection_attempts)

        return SanitizationResult(
            original_length=original_length,
            sanitized_text=wrapped,
            was_truncated=was_truncated,
            injection_attempts=injection_attempts,
            safe=is_safe,
        )

    def extract_text(self, raw_html: str) -> str:
        """Strip HTML markup and return plain text.

        Removes all script, style, and interactive elements entirely
        (including their content).  Remaining tags are stripped, leaving
        only their text content.  HTML entities are decoded.

        Parameters
        ----------
        raw_html:
            Raw HTML string.

        Returns
        -------
        str
            Plain text extracted from the HTML.
        """
        text = raw_html

        # Remove complete tag blocks that should be stripped with content.
        for tag in self._STRIP_TAGS:
            pattern = re.compile(
                rf"<{tag}\b[^>]*>.*?</{tag}>",
                re.IGNORECASE | re.DOTALL,
            )
            text = pattern.sub("", text)
            # Also remove self-closing variants.
            text = re.sub(rf"<{tag}\b[^>]*/?>", "", text, flags=re.IGNORECASE)

        # Remove HTML comments (may contain hidden instructions).
        text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)

        # Remove CDATA sections.
        text = re.sub(r"<!\[CDATA\[.*?\]\]>", "", text, flags=re.DOTALL)

        # Remove all remaining HTML tags.
        text = re.sub(r"<[^>]+>", " ", text)

        # Decode HTML entities.
        text = html.unescape(text)

        # Remove null bytes and other control characters.
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

        return text.strip()

    def is_safe(self, text: str) -> tuple[bool, list[str]]:
        """Check plain text for injection patterns without modifying it.

        Parameters
        ----------
        text:
            The text to scan.

        Returns
        -------
        tuple[bool, list[str]]
            ``(True, [])`` if clean, or ``(False, list_of_findings)`` if
            injection patterns are detected.
        """
        findings: list[str] = []
        for pattern_name, pattern_re in self._INJECTION_PATTERNS:
            matches = pattern_re.findall(text)
            if matches:
                findings.append(
                    f"{pattern_name}: {len(matches)} match(es)"
                )
        return len(findings) == 0, findings

    # -- internal -----------------------------------------------------------

    @staticmethod
    def _normalise_whitespace(text: str) -> str:
        """Collapse runs of whitespace into single spaces and strip blank lines.

        Parameters
        ----------
        text:
            Input text.

        Returns
        -------
        str
            Normalised text.
        """
        # Collapse multiple blank lines into at most two newlines.
        text = re.sub(r"\n{3,}", "\n\n", text)
        # Collapse multiple spaces/tabs within a line.
        text = re.sub(r"[^\S\n]+", " ", text)
        # Strip leading/trailing whitespace from each line.
        lines = [line.strip() for line in text.splitlines()]
        # Remove lines that are empty after stripping.
        cleaned: list[str] = []
        prev_empty = False
        for line in lines:
            if not line:
                if not prev_empty:
                    cleaned.append("")
                prev_empty = True
            else:
                cleaned.append(line)
                prev_empty = False

        return "\n".join(cleaned).strip()

    def _audit_injection(
        self, source_url: str, findings: list[str]
    ) -> None:
        """Log detected injection attempts for audit review.

        Parameters
        ----------
        source_url:
            The URL the content was fetched from.
        findings:
            List of injection pattern matches.
        """
        logger.warning(
            "[INJECTION_DETECTED] source=%s findings=%s",
            source_url,
            findings,
        )

        if self._audit_log_dir is not None:
            try:
                audit_file = self._audit_log_dir / "injection_audit.log"
                timestamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
                with audit_file.open("a", encoding="utf-8") as fh:
                    fh.write(
                        f"{timestamp} [INJECTION_DETECTED] "
                        f"source={source_url} "
                        f"findings={findings}\n"
                    )
            except OSError as exc:
                logger.error("Failed to write injection audit log: %s", exc)
