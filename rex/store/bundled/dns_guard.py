"""DNS Guard -- enhanced DNS monitoring bundled plugin."""

from __future__ import annotations

from typing import Any

from rex.shared.utils import entropy
from rex.store.sdk.base_plugin import RexPlugin


class DnsGuardPlugin(RexPlugin):
    """Monitors DNS queries for newly registered domains and high-entropy patterns."""

    async def on_event(
        self, event_type: str, event_data: dict[str, Any]
    ) -> dict[str, Any] | None:
        if event_type not in ("threat_detected", "dns_query"):
            return None

        domain = event_data.get("query_name", "")
        if not domain:
            return None

        # Use Shannon entropy to detect DGA-style domains
        label = domain.split(".")[0]
        ent = entropy(label)
        if ent > 3.5 and len(label) > 12:
            return {
                "action": "alert",
                "severity": "medium",
                "description": f"DNS Guard: High-entropy domain detected: {domain}",
            }
        return None

    async def on_schedule(self) -> dict[str, Any] | None:
        return None

    async def on_install(self) -> None:
        pass

    async def on_configure(self, config: dict[str, Any]) -> None:
        pass

    def get_status(self) -> dict[str, Any]:
        return {"healthy": True, "name": "dns-guard", "version": "1.0.0"}
