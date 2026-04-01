"""Question bank -- all predefined onboarding questions for the REX interview.

Each question is a typed dictionary with:
- id:         Stable identifier used as the answer key.
- text:       What REX says (dog persona -- conversational in basic mode).
- subtext:    Why REX asks this (shown as a tooltip / subtitle).
- options:    List of ``{value, label}`` dicts (empty for free-text questions).
- type:       ``single`` | ``multi`` | ``text`` | ``skip``.
- required:   Whether the question must be answered before proceeding.
- mode:       ``basic`` | ``advanced``.
- priority:   Sort order within a mode (lower = asked first).
- conditions: List of callables ``(network_data, previous_answers) -> bool``.
              All must return ``True`` for the question to be shown.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from rex.shared.enums import DeviceType, InterviewMode

# ---------------------------------------------------------------------------
# Type alias for condition predicates
# ---------------------------------------------------------------------------
ConditionFn = Callable[[dict[str, Any], dict[str, Any]], bool]
"""Signature: (network_data, previous_answers) -> bool"""


# ---------------------------------------------------------------------------
# Condition helpers -- reusable predicates for conditional questions
# ---------------------------------------------------------------------------

def _has_iot_devices(network_data: dict[str, Any], _answers: dict[str, Any]) -> bool:
    """Return True if the network scan detected any IoT-class devices."""
    devices: list[dict[str, Any]] = network_data.get("devices", [])
    iot_types = {
        DeviceType.IOT_CAMERA,
        DeviceType.IOT_CLIMATE,
        DeviceType.IOT_HUB,
        DeviceType.SMART_TV,
    }
    return any(
        d.get("device_type") in iot_types
        or str(d.get("device_type", "")) in {t.value for t in iot_types}
        for d in devices
    )


def _has_exposed_services(network_data: dict[str, Any], _answers: dict[str, Any]) -> bool:
    """Return True if any device has externally-reachable services."""
    return bool(network_data.get("exposed_services"))


def _always(_network_data: dict[str, Any], _answers: dict[str, Any]) -> bool:
    """Unconditional -- always show this question."""
    return True


# ---------------------------------------------------------------------------
# IoT device counter -- used for dynamic text interpolation
# ---------------------------------------------------------------------------

def count_iot_devices(network_data: dict[str, Any]) -> int:
    """Count how many IoT-class devices the scan found."""
    devices: list[dict[str, Any]] = network_data.get("devices", [])
    iot_types = {
        DeviceType.IOT_CAMERA,
        DeviceType.IOT_CLIMATE,
        DeviceType.IOT_HUB,
        DeviceType.SMART_TV,
    }
    iot_type_values = {t.value for t in iot_types}
    return sum(
        1 for d in devices
        if d.get("device_type") in iot_types
        or str(d.get("device_type", "")) in iot_type_values
    )


def get_exposed_service_name(network_data: dict[str, Any]) -> str:
    """Return a comma-joined list of exposed service names, or 'service'."""
    exposed = network_data.get("exposed_services", [])
    if not exposed:
        return "service"
    names = [svc.get("name", svc.get("service", "service")) for svc in exposed]
    return ", ".join(names[:3]) or "service"


# ---------------------------------------------------------------------------
# Question definitions
# ---------------------------------------------------------------------------

QuestionDict = dict[str, Any]
"""Type alias for a single question record."""


# ---- BASIC MODE (max 6, always asked unless conditional) ------------------

BASIC_QUESTIONS: list[QuestionDict] = [
    {
        "id": "environment_type",
        "text": (
            "*tail wag* Alright, first things first! "
            "Is this a home network, a business, or a bit of both?"
        ),
        "subtext": (
            "REX adapts its monitoring intensity and device expectations "
            "based on the environment type."
        ),
        "options": [
            {"value": "home", "label": "Home"},
            {"value": "business", "label": "Business"},
            {"value": "both", "label": "Both"},
        ],
        "type": "single",
        "required": True,
        "mode": InterviewMode.BASIC,
        "priority": 10,
        "conditions": [_always],
    },
    {
        "id": "protection_mode",
        "text": (
            "Now, how do you want me to handle the bad guys? "
            "I can bite first and ask questions later, or just bark to let you know."
        ),
        "subtext": (
            "This controls whether REX automatically blocks threats or "
            "only alerts you so you can decide."
        ),
        "options": [
            {"value": "auto_block_all", "label": "Auto-block everything"},
            {"value": "auto_block_critical", "label": "Auto-block critical + alert the rest"},
            {"value": "alert_only", "label": "Alert only (I decide what to block)"},
        ],
        "type": "single",
        "required": True,
        "mode": InterviewMode.BASIC,
        "priority": 20,
        "conditions": [_always],
    },
    {
        "id": "notification_channel",
        "text": (
            "How should I get your attention when something happens? "
            "Pick one -- or several if you want me to bark through multiple channels!"
        ),
        "subtext": (
            "REX sends threat alerts and status updates through "
            "the channels you choose here."
        ),
        "options": [
            {"value": "dashboard", "label": "Dashboard only"},
            {"value": "discord", "label": "Discord"},
            {"value": "telegram", "label": "Telegram"},
            {"value": "email", "label": "Email"},
            {"value": "multiple", "label": "Multiple channels"},
        ],
        "type": "single",
        "required": True,
        "mode": InterviewMode.BASIC,
        "priority": 30,
        "conditions": [_always],
    },
    {
        "id": "iot_scrutiny",
        "text": (
            "I sniffed out some IoT devices on your network. "
            "Should I keep an extra-close eye on them? "
            "IoT gadgets can be... a bit leaky."
        ),
        "subtext": (
            "IoT devices often have weak security. Extra scrutiny means "
            "REX monitors their traffic patterns more aggressively."
        ),
        "options": [
            {"value": "yes", "label": "Yes, watch them closely"},
            {"value": "no", "label": "No, treat them like everything else"},
        ],
        "type": "single",
        "required": True,
        "mode": InterviewMode.BASIC,
        "priority": 40,
        "conditions": [_has_iot_devices],
    },
    {
        "id": "exposed_service",
        "text": (
            "Heads up! I found a service that's accessible from the internet. "
            "Should I flag external access to it as suspicious?"
        ),
        "subtext": (
            "Externally-accessible services are a common attack vector. "
            "REX can monitor and alert on unexpected inbound connections."
        ),
        "options": [
            {"value": "yes", "label": "Yes, flag it"},
            {"value": "no", "label": "No, it's intentional"},
        ],
        "type": "single",
        "required": True,
        "mode": InterviewMode.BASIC,
        "priority": 50,
        "conditions": [_has_exposed_services],
    },
    {
        "id": "additional_notes",
        "text": (
            "Anything else I should know about your network? "
            "Special devices, weird setups, things I should ignore? "
            "Or just leave this blank and we'll get going!"
        ),
        "subtext": (
            "Free-text notes are stored in the knowledge base. "
            "REX's AI reads them before making decisions."
        ),
        "options": [],
        "type": "text",
        "required": False,
        "mode": InterviewMode.BASIC,
        "priority": 60,
        "conditions": [_always],
    },
]


# ---- ADVANCED MODE (all optional, shown after basic) ----------------------

ADVANCED_QUESTIONS: list[QuestionDict] = [
    {
        "id": "compliance_requirements",
        "text": (
            "Does your network need to meet any compliance standards? "
            "Pick all that apply, or skip if this is just a home setup."
        ),
        "subtext": (
            "REX adjusts logging verbosity, retention policies, and "
            "alerting thresholds to help meet compliance frameworks."
        ),
        "options": [
            {"value": "pci_dss", "label": "PCI-DSS"},
            {"value": "hipaa", "label": "HIPAA"},
            {"value": "soc2", "label": "SOC 2"},
            {"value": "gdpr", "label": "GDPR"},
            {"value": "iso27001", "label": "ISO 27001"},
            {"value": "none", "label": "None / Not sure"},
        ],
        "type": "multi",
        "required": False,
        "mode": InterviewMode.ADVANCED,
        "priority": 110,
        "conditions": [_always],
    },
    {
        "id": "authorized_pentest_ips",
        "text": (
            "Any IP addresses or ranges I should whitelist? "
            "For example, your pentesting box or a vulnerability scanner."
        ),
        "subtext": (
            "Whitelisted IPs will not trigger threat alerts. "
            "Enter as comma-separated CIDR ranges."
        ),
        "options": [],
        "type": "text",
        "required": False,
        "mode": InterviewMode.ADVANCED,
        "priority": 120,
        "conditions": [_always],
    },
    {
        "id": "scan_schedule",
        "text": (
            "How often should I do a deep scan of your network? "
            "More frequent scans catch things faster, but use more resources."
        ),
        "subtext": (
            "Deep scans include port scanning, service detection, "
            "and OS fingerprinting for all known devices."
        ),
        "options": [
            {"value": "every_hour", "label": "Every hour"},
            {"value": "every_6h", "label": "Every 6 hours"},
            {"value": "every_12h", "label": "Every 12 hours"},
            {"value": "daily", "label": "Once a day"},
            {"value": "weekly", "label": "Once a week"},
        ],
        "type": "single",
        "required": False,
        "mode": InterviewMode.ADVANCED,
        "priority": 130,
        "conditions": [_always],
    },
    {
        "id": "vpn_policy",
        "text": (
            "Do you use a VPN or allow remote access to this network? "
            "Tell me about it so I don't accidentally bark at your own tunnel."
        ),
        "subtext": (
            "REX can detect VPN tunnels and remote-access sessions. "
            "Letting it know what's expected prevents false positives."
        ),
        "options": [
            {"value": "no_vpn", "label": "No VPN / remote access"},
            {"value": "wireguard", "label": "WireGuard"},
            {"value": "openvpn", "label": "OpenVPN"},
            {"value": "ipsec", "label": "IPSec / L2TP"},
            {"value": "tailscale", "label": "Tailscale / ZeroTier"},
            {"value": "other", "label": "Other"},
        ],
        "type": "single",
        "required": False,
        "mode": InterviewMode.ADVANCED,
        "priority": 140,
        "conditions": [_always],
    },
    {
        "id": "guest_network",
        "text": (
            "Do you have a guest network? "
            "I can keep it isolated and watch it separately."
        ),
        "subtext": (
            "Guest networks get stricter monitoring by default. "
            "REX treats guest devices with lower trust."
        ),
        "options": [
            {"value": "yes", "label": "Yes, I have a guest network"},
            {"value": "no", "label": "No guest network"},
            {"value": "planning", "label": "Planning to set one up"},
        ],
        "type": "single",
        "required": False,
        "mode": InterviewMode.ADVANCED,
        "priority": 150,
        "conditions": [_always],
    },
    {
        "id": "user_count",
        "text": (
            "Roughly how many people use this network regularly? "
            "Helps me calibrate what 'normal' looks like."
        ),
        "subtext": (
            "REX uses this to set behavioral baselines. "
            "A household of 2 looks very different from an office of 50."
        ),
        "options": [
            {"value": "1-2", "label": "1-2 people"},
            {"value": "3-5", "label": "3-5 people"},
            {"value": "6-10", "label": "6-10 people"},
            {"value": "11-25", "label": "11-25 people"},
            {"value": "25+", "label": "More than 25"},
        ],
        "type": "single",
        "required": False,
        "mode": InterviewMode.ADVANCED,
        "priority": 160,
        "conditions": [_always],
    },
    {
        "id": "dns_preference",
        "text": (
            "Want me to use encrypted DNS? "
            "It keeps your lookups private from your ISP and anyone snooping on the wire."
        ),
        "subtext": (
            "DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) prevents DNS eavesdropping. "
            "REX can route queries through a privacy-respecting resolver."
        ),
        "options": [
            {"value": "system_default", "label": "Keep system default"},
            {"value": "doh_cloudflare", "label": "DNS-over-HTTPS (Cloudflare)"},
            {"value": "doh_quad9", "label": "DNS-over-HTTPS (Quad9 - malware blocking)"},
            {"value": "dot_google", "label": "DNS-over-TLS (Google)"},
            {"value": "custom", "label": "Custom resolver (I'll configure)"},
        ],
        "type": "single",
        "required": False,
        "mode": InterviewMode.ADVANCED,
        "priority": 170,
        "conditions": [_always],
    },
    {
        "id": "inspection_depth",
        "text": (
            "How deep should I inspect network traffic? "
            "Deeper inspection catches more, but needs more horsepower."
        ),
        "subtext": (
            "Controls whether REX looks at packet headers only, uses "
            "smart heuristics, or runs in minimal/passive mode."
        ),
        "options": [
            {"value": "headers_only", "label": "Headers only (lightweight)"},
            {"value": "smart", "label": "Smart heuristics (recommended)"},
            {"value": "minimal", "label": "Minimal / passive only"},
        ],
        "type": "single",
        "required": False,
        "mode": InterviewMode.ADVANCED,
        "priority": 180,
        "conditions": [_always],
    },
    {
        "id": "notification_detail_level",
        "text": (
            "How much detail do you want in my alerts? "
            "Full reports with packet traces, short summaries, or just the alarm bell?"
        ),
        "subtext": (
            "Full detail includes raw indicators and evidence. "
            "Summary mode gives actionable info without the noise."
        ),
        "options": [
            {"value": "full", "label": "Full detail (include evidence)"},
            {"value": "summary", "label": "Summary (key facts only)"},
            {"value": "alert_only", "label": "Alert only (just the bark)"},
        ],
        "type": "single",
        "required": False,
        "mode": InterviewMode.ADVANCED,
        "priority": 190,
        "conditions": [_always],
    },
    {
        "id": "messaging_platform",
        "text": (
            "Which messaging platform should I use for agent control? "
            "This is where you can send me commands and chat with me directly."
        ),
        "subtext": (
            "REX can receive commands and send interactive reports "
            "through your preferred messaging platform."
        ),
        "options": [
            {"value": "discord", "label": "Discord"},
            {"value": "telegram", "label": "Telegram"},
            {"value": "signal", "label": "Signal"},
            {"value": "matrix", "label": "Matrix"},
            {"value": "slack", "label": "Slack"},
            {"value": "none", "label": "Dashboard only (no messaging)"},
        ],
        "type": "single",
        "required": False,
        "mode": InterviewMode.ADVANCED,
        "priority": 200,
        "conditions": [_always],
    },
]


# ---------------------------------------------------------------------------
# Combined bank and accessor functions
# ---------------------------------------------------------------------------

ALL_QUESTIONS: list[QuestionDict] = BASIC_QUESTIONS + ADVANCED_QUESTIONS
"""Complete question bank -- basic first, then advanced."""

# Quick lookup by question ID
_QUESTION_INDEX: dict[str, QuestionDict] = {q["id"]: q for q in ALL_QUESTIONS}


def get_basic_questions() -> list[QuestionDict]:
    """Return the subset of questions for BASIC interview mode.

    Returns
    -------
    list[QuestionDict]
        Questions with ``mode == InterviewMode.BASIC``, sorted by priority.
    """
    return sorted(
        [q for q in ALL_QUESTIONS if q["mode"] == InterviewMode.BASIC],
        key=lambda q: q["priority"],
    )


def get_advanced_questions() -> list[QuestionDict]:
    """Return the full question set including advanced questions.

    Returns
    -------
    list[QuestionDict]
        All questions (basic + advanced), sorted by priority.
    """
    return sorted(ALL_QUESTIONS, key=lambda q: q["priority"])


def get_question_by_id(question_id: str) -> QuestionDict | None:
    """Look up a single question by its stable identifier.

    Parameters
    ----------
    question_id:
        The ``id`` field of the desired question.

    Returns
    -------
    QuestionDict | None
        The question dict, or ``None`` if no match.
    """
    return _QUESTION_INDEX.get(question_id)


def get_questions_for_mode(mode: InterviewMode) -> list[QuestionDict]:
    """Return questions available for a given interview mode, sorted by priority.

    Parameters
    ----------
    mode:
        ``InterviewMode.BASIC`` returns only basic questions.
        ``InterviewMode.ADVANCED`` returns all questions.

    Returns
    -------
    list[QuestionDict]
        Sorted question list.
    """
    if mode == InterviewMode.BASIC:
        return get_basic_questions()
    return get_advanced_questions()
