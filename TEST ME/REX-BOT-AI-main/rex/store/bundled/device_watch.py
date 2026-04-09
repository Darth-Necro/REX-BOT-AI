"""Device Watch -- alerts on new or changed devices on the network."""

from __future__ import annotations

from typing import Any

from rex.store.sdk.base_plugin import RexPlugin


class DeviceWatchPlugin(RexPlugin):
    """Monitors the network for newly discovered or changed devices."""

    def __init__(self) -> None:
        super().__init__()
        self._known_macs: set[str] = set()

    async def on_event(
        self, event_type: str, event_data: dict[str, Any]
    ) -> dict[str, Any] | None:
        if event_type not in ("device_discovered", "device_update"):
            return None

        mac = event_data.get("mac_address", "")
        if not mac:
            return None

        if event_type == "device_discovered" and mac not in self._known_macs:
            self._known_macs.add(mac)
            hostname = event_data.get("hostname", "unknown")
            ip = event_data.get("ip_address", "unknown")
            return {
                "action": "alert",
                "severity": "low",
                "description": (
                    f"Device Watch: New device detected -- "
                    f"MAC={mac}, hostname={hostname}, IP={ip}"
                ),
            }

        if event_type == "device_update":
            change = event_data.get("change_type", "")
            if change in ("ip_changed", "hostname_changed", "vendor_changed"):
                return {
                    "action": "alert",
                    "severity": "info",
                    "description": (
                        f"Device Watch: Device {mac} changed -- {change}"
                    ),
                }

        return None

    async def on_schedule(self) -> dict[str, Any] | None:
        return None

    async def on_install(self) -> None:
        self._known_macs.clear()

    async def on_configure(self, config: dict[str, Any]) -> None:
        pass

    def get_status(self) -> dict[str, Any]:
        return {
            "healthy": True,
            "name": "device-watch",
            "version": "1.0.0",
            "tracked_devices": len(self._known_macs),
        }
