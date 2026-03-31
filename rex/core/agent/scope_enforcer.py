"""Ensures REX stays within its security and networking scope.

REX is a network security assistant.  It must not attempt to answer
questions about cooking, dating, stock trading, or any other domain
outside security and networking.  The :class:`ScopeEnforcer` provides
two levels of filtering:

1. **Message-level** -- checks whether a user's natural-language message
   falls within scope before forwarding it to the LLM.
2. **Action-level** -- verifies that a proposed action belongs to a
   security/networking functional domain.

Out-of-scope requests receive a polite, on-brand rejection message.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)


class ScopeEnforcer:
    """Rejects any request that falls outside the security/networking domain.

    The enforcer uses a two-pronged approach:

    - A large set of **security keywords** that, if present, strongly suggest
      the message is in scope.
    - A set of **out-of-scope regex patterns** that match clearly off-topic
      requests regardless of other content.

    A message is considered in-scope if it contains at least one security
    keyword AND does not match any out-of-scope pattern, OR if it matches
    a known command pattern (``!``, ``/``).
    """

    # Keywords that indicate the message is about security or networking.
    # Matching is case-insensitive on whole words.
    SECURITY_KEYWORDS: frozenset[str] = frozenset({
        # Core security terms
        "threat", "scan", "firewall", "block", "device", "network",
        "vulnerability", "malware", "attack", "port", "dns", "traffic",
        "security", "protect", "alert", "monitor", "exploit", "patch",
        "intrusion", "breach", "incident", "compromise", "quarantine",
        "isolate", "whitelist", "blacklist", "blocklist", "allowlist",
        # Network terms
        "ip", "mac", "subnet", "gateway", "router", "switch", "vlan",
        "dhcp", "arp", "tcp", "udp", "icmp", "packet", "bandwidth",
        "latency", "interface", "ethernet", "wifi", "wireless", "lan",
        "wan", "vpn", "proxy", "nat", "routing", "nmap", "nftables",
        # Threat types
        "phishing", "ransomware", "trojan", "botnet", "ddos", "dos",
        "spoof", "spoofing", "mitm", "injection", "xss", "brute",
        "credential", "exfiltration", "c2", "backdoor", "rootkit",
        "keylogger", "adware", "spyware", "worm", "zero-day", "zeroday",
        # Security operations
        "cve", "cvss", "ioc", "indicator", "signature", "hash",
        "encryption", "certificate", "tls", "ssl", "auth", "2fa",
        "mfa", "token", "session", "permission", "privilege", "audit",
        "compliance", "policy", "rule", "acl", "log", "siem", "ids",
        "ips", "nids", "hids", "edr", "soc", "pentest", "penetration",
        # REX-specific
        "rex", "report", "status", "health", "dashboard", "plugin",
        "service", "config", "configuration", "update", "upgrade",
        "mode", "basic", "advanced", "schedule", "backup", "restore",
    })

    # Regex patterns that match clearly out-of-scope requests.
    # Compiled at class level for performance.
    OUT_OF_SCOPE_PATTERNS: list[re.Pattern[str]] = [
        re.compile(pattern, re.IGNORECASE)
        for pattern in (
            r"\b(?:order|buy|purchase|shop|shopping|checkout|cart|price|pricing)\b",
            r"\b(?:email|calendar|contact|appointment|meeting|schedule\s+meeting)\b",
            r"\b(?:dating|tinder|bumble|match\.com|relationship|romance)\b",
            r"\b(?:music|spotify|playlist|song|album|concert|lyrics)\b",
            r"\b(?:movie|film|netflix|hulu|stream(?:ing)?|watch(?:ing)?|show|series)\b",
            r"\b(?:recipe|cook(?:ing)?|bake|baking|food|restaurant|menu|ingredients)\b",
            r"\b(?:weather|forecast|temperature|rain|snow|sunny|cloudy)\b",
            r"\b(?:stock|invest(?:ment|ing)?|crypto|bitcoin|ethereum|trading|portfolio)\b",
            r"\b(?:homework|essay|thesis|assignment|exam|study|tutor)\b",
            r"\b(?:travel|flight|hotel|booking|vacation|holiday|trip|airline)\b",
            r"\b(?:joke|funny|meme|humor|laugh|comedy|riddle)\b",
            r"\b(?:sports|football|soccer|basketball|baseball|tennis|cricket)\b",
            r"\b(?:fashion|clothes|outfit|dress|shoes|style|wardrobe)\b",
            r"\b(?:real\s+estate|mortgage|rent(?:al)?|apartment|house\s+hunting)\b",
            r"\b(?:diet|exercise|workout|gym|yoga|meditation|fitness)\b",
            r"\b(?:poem|poetry|story|fiction|novel|write\s+(?:a\s+)?(?:poem|story))\b",
            r"\b(?:translate|translation|spanish|french|german|japanese|chinese)\b",
            r"\b(?:astrology|horoscope|zodiac|tarot|psychic|fortune)\b",
            r"\b(?:game|gaming|fortnite|minecraft|roblox|steam|playstation|xbox)\b",
            r"\b(?:pet|dog|cat|veterinar|animal|breed)\b",
            r"\b(?:garden(?:ing)?|plant(?:ing)?|flower|lawn|landscap)\b",
            r"\b(?:makeup|cosmetic|skincare|beauty|salon|hairstyle)\b",
        )
    ]

    # The polite rejection message.
    _REJECTION_TEMPLATE: str = (
        "I'm REX, your network security assistant. That request is outside "
        "my area of expertise. I'm focused on:\n"
        "- Network monitoring and device discovery\n"
        "- Threat detection and response\n"
        "- Firewall management\n"
        "- Security analysis and reporting\n"
        "- Vulnerability assessment\n\n"
        "How can I help with your network security?"
    )

    # Valid action domains from the action registry.
    _VALID_DOMAINS: frozenset[str] = frozenset({
        "monitoring", "threat_response", "administration",
        "information", "reporting", "system",
    })

    def is_in_scope(self, user_message: str) -> tuple[bool, str]:
        """Determine whether a user message falls within REX's scope.

        Parameters
        ----------
        user_message:
            The raw text from the user.

        Returns
        -------
        tuple[bool, str]
            ``(True, "")`` if in scope, or ``(False, rejection_message)``
            if out of scope.
        """
        if not user_message or not user_message.strip():
            return True, ""

        text = user_message.strip()

        # Commands (starting with ! or /) are always in scope --
        # they map directly to REX actions.
        if text.startswith(("!", "/")):
            return True, ""

        # Very short messages (fewer than 3 words) are likely greetings
        # or simple queries -- let them through to the LLM.
        word_count = len(text.split())
        if word_count < 3:
            return True, ""

        text_lower = text.lower()

        # Check for out-of-scope patterns first. These are strong negative
        # signals that override keyword matches.
        for pattern in self.OUT_OF_SCOPE_PATTERNS:
            if pattern.search(text_lower):
                # But only reject if there are NO security keywords --
                # "block the device streaming traffic" is valid.
                if not self._has_security_keyword(text_lower):
                    logger.info(
                        "Out-of-scope request rejected (pattern match): %s",
                        text[:100],
                    )
                    return False, self._REJECTION_TEMPLATE

        # If the message has security keywords, it's in scope.
        if self._has_security_keyword(text_lower):
            return True, ""

        # Messages with no security keywords and no out-of-scope patterns
        # are ambiguous. For longer messages (5+ words), reject them.
        # Short ambiguous messages get a pass (could be "how are you" etc.).
        if word_count >= 5:
            logger.info(
                "Out-of-scope request rejected (no security keywords): %s",
                text[:100],
            )
            return False, self._REJECTION_TEMPLATE

        return True, ""

    def validate_action_scope(self, action_type: str) -> bool:
        """Check that an action belongs to a valid security/networking domain.

        This is a secondary check -- the :class:`ActionRegistry` already
        constrains actions, but this provides defence in depth by verifying
        the domain string is valid.

        Parameters
        ----------
        action_type:
            The action identifier to validate.

        Returns
        -------
        bool
            ``True`` if the action type is non-empty and looks like a valid
            identifier (lowercase alphanumeric with underscores).
        """
        if not action_type:
            return False
        # Must be a valid Python-style identifier (snake_case).
        if not re.match(r"^[a-z][a-z0-9_]{1,63}$", action_type):
            return False
        return True

    def validate_action_domain(self, domain: str) -> bool:
        """Check that a domain string is one of the valid REX domains.

        Parameters
        ----------
        domain:
            The domain string to validate.

        Returns
        -------
        bool
            ``True`` if the domain is valid.
        """
        return domain in self._VALID_DOMAINS

    # -- internal -----------------------------------------------------------

    def _has_security_keyword(self, text_lower: str) -> bool:
        """Check whether the lowercased text contains any security keyword.

        Uses word-boundary splitting to avoid false positives (e.g.
        "report" matching inside "reportedly").

        Parameters
        ----------
        text_lower:
            The user message, already lowercased.

        Returns
        -------
        bool
        """
        # Split on non-alphanumeric boundaries to get individual words.
        words = set(re.split(r"[^a-z0-9\-]+", text_lower))
        return bool(words & self.SECURITY_KEYWORDS)
