"""Message formatter -- renders alerts and reports in the REX dog persona."""

from __future__ import annotations

import logging
from typing import Any

from rex.shared.enums import ThreatSeverity
from rex.shared.utils import iso_timestamp

logger = logging.getLogger(__name__)

_PERSONA_PREFIXES = {
    ThreatSeverity.CRITICAL: "*GRRRRR WOOF WOOF!* REX detected a serious threat!",
    ThreatSeverity.HIGH: "*GRRRRR* REX is growling at something suspicious.",
    ThreatSeverity.MEDIUM: "*ruff ruff* REX noticed something unusual.",
    ThreatSeverity.LOW: "*woof* Just a heads up from REX:",
    ThreatSeverity.INFO: "*ruff* REX has a quick note for you:",
}


_JUNKYARD_PREFIXES = {
    ThreatSeverity.CRITICAL: "*WOOF WOOF WOOF GRRRRR!* JUNKYARD DOG ENGAGED! Threat ELIMINATED!",
    ThreatSeverity.HIGH: "*GRRRRR WOOF WOOF!* REX bit the intruder! Threat BLOCKED!",
    ThreatSeverity.MEDIUM: "*GRRRRR!* REX chased it off! Suspicious activity BLOCKED!",
    ThreatSeverity.LOW: "*WOOF!* REX snapped at something. Blocked just in case!",
    ThreatSeverity.INFO: "*ruff GRRRRR* REX is watching closely. Nothing gets past!",
}


class MessageFormatter:
    """Formats alert and report messages using the REX guard dog persona."""

    def format_alert(
        self,
        event: dict[str, Any],
        severity: str,
        detail_level: str = "summary",
    ) -> tuple[str, dict[str, Any]]:
        """Format a threat alert.

        Parameters
        ----------
        event:
            Threat event data.
        severity:
            Threat severity string.
        detail_level:
            One of 'full', 'summary', 'alert_only'.

        Returns
        -------
        tuple[str, dict[str, Any]]
            (formatted_message, metadata_dict)
        """
        sev = (
            ThreatSeverity(severity)
            if severity in [s.value for s in ThreatSeverity]
            else ThreatSeverity.MEDIUM
        )
        # Check if Junkyard Dog mode is active
        junkyard = event.get("protection_mode") == "junkyard_dog"
        prefixes = _JUNKYARD_PREFIXES if junkyard else _PERSONA_PREFIXES
        prefix = prefixes.get(sev, "REX update:")
        description = event.get("description", "Suspicious activity detected.")
        action = event.get("action_taken", "monitoring")

        if detail_level == "alert_only":
            message = f"{prefix} Check the REX dashboard for details."
        elif detail_level == "summary":
            source = event.get("source_ip", "unknown device")
            message = f"{prefix} {description} Source: {source}. REX action: {action}."
        else:  # full
            source = event.get("source_ip", "unknown")
            dest = event.get("destination_ip", "unknown")
            port = event.get("destination_port", "")
            threat_type = event.get("threat_type", "unknown")
            message = (
                f"{prefix}\n\n"
                f"Type: {threat_type}\n"
                f"Source: {source}\n"
                f"Destination: {dest}" + (f":{port}" if port else "") + "\n"
                f"Description: {description}\n"
                f"Action taken: {action}\n"
                f"Time: {iso_timestamp()}"
            )

        title = f"REX {sev.value.upper()} Alert"
        metadata = {
            "title": title,
            "severity": sev.value,
            "threat_type": event.get("threat_type", ""),
        }
        return message, metadata

    def format_daily_summary(self, events: list[dict], stats: dict[str, Any]) -> str:
        """Generate daily security summary in REX persona."""
        total = len(events)
        blocked = sum(1 for e in events if e.get("action_taken") == "block")
        device_count = stats.get("device_count", 0)
        return (
            f"REX's Daily Patrol Report\n"
            f"========================\n\n"
            f"Devices protected: {device_count}\n"
            f"Events today: {total}\n"
            f"Threats blocked: {blocked}\n"
            f"Network health: "
            f"{'Good' if total < 10 else 'Fair' if total < 50 else 'Needs attention'}\n\n"
            f"*woof* REX is keeping watch. Stay safe."
        )

    def format_weekly_report(self, events: list[dict], stats: dict[str, Any]) -> str:
        """Generate weekly security report."""
        total = len(events)
        by_severity = {}
        for e in events:
            sev = e.get("severity", "info")
            by_severity[sev] = by_severity.get(sev, 0) + 1
        lines = [
            "REX's Weekly Security Report",
            "=" * 30, "",
            f"Total events: {total}",
        ]
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in by_severity:
                lines.append(f"  {sev.upper()}: {by_severity[sev]}")
        lines.extend(["", "*ruff* REX continues to guard your network."])
        return "\n".join(lines)
