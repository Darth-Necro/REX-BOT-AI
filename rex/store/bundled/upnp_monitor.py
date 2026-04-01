"""UPnP Monitor -- detects UPnP services and open port mappings."""

from __future__ import annotations

from typing import Any

from rex.store.sdk.base_plugin import RexPlugin


class UpnpMonitorPlugin(RexPlugin):
    """Detects UPnP services advertising on the network and flags risky port mappings."""

    async def on_event(
        self, event_type: str, event_data: dict[str, Any]
    ) -> dict[str, Any] | None:
        if event_type not in ("device_discovered", "device_update", "upnp_discovery"):
            return None

        services = event_data.get("upnp_services", [])
        if not services:
            return None

        risky: list[str] = []
        for svc in services:
            port = svc.get("external_port")
            protocol = svc.get("protocol", "TCP")
            description = svc.get("description", "")
            # Flag well-known risky ports exposed via UPnP
            if port and int(port) in (21, 22, 23, 80, 443, 445, 3389, 8080):
                risky.append(f"{protocol}/{port} ({description})")

        if risky:
            device = event_data.get("mac_address", event_data.get("ip_address", "unknown"))
            return {
                "action": "alert",
                "severity": "high",
                "description": (
                    f"UPnP Monitor: Risky port mappings on {device}: "
                    + ", ".join(risky)
                ),
            }

        return None

    async def on_schedule(self) -> dict[str, Any] | None:
        return None

    async def on_install(self) -> None:
        pass

    async def on_configure(self, config: dict[str, Any]) -> None:
        pass

    def get_status(self) -> dict[str, Any]:
        return {"healthy": True, "name": "upnp-monitor", "version": "1.0.0"}
