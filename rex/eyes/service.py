"""Eyes service -- long-running service wrapper for the Eyes layer.

Layer 1 -- imports from ``rex.shared``, ``rex.pal``, ``rex.eyes.*``,
and stdlib.

Orchestrates the full network monitoring pipeline:
- Periodic device discovery and fingerprinting.
- Passive DNS monitoring.
- Traffic anomaly detection.
- Port scanning on demand.
- Event publishing to the REX event bus.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any

from rex.eyes.device_store import DeviceStore
from rex.eyes.dns_monitor import DNSMonitor
from rex.eyes.fingerprinter import DeviceFingerprinter
from rex.eyes.port_scanner import PortScanner
from rex.eyes.scanner import NetworkScanner
from rex.eyes.traffic import TrafficMonitor
from rex.pal import get_adapter
from rex.shared.constants import (
    STREAM_CORE_COMMANDS,
    STREAM_EYES_DEVICE_UPDATES,
    STREAM_EYES_SCAN_RESULTS,
    STREAM_EYES_THREATS,
)
from rex.shared.enums import ServiceName
from rex.shared.errors import RexBusUnavailableError
from rex.shared.events import (
    DeviceDiscoveredEvent,
    DeviceUpdateEvent,
    ScanTriggeredEvent,
    ThreatDetectedEvent,
)
from rex.shared.service import BaseService

if TYPE_CHECKING:
    from rex.pal.base import PlatformAdapter
    from rex.shared.bus import EventBus
    from rex.shared.config import RexConfig
    from rex.shared.models import Device, ScanResult, ThreatEvent


class EyesService(BaseService):
    """Network monitoring service that orchestrates all Eyes components.

    Inherits from :class:`BaseService` for lifecycle management,
    heartbeat publishing, and event bus integration.

    On start:
    1. Acquires the platform adapter.
    2. Auto-detects the network interface.
    3. Runs an initial device scan.
    4. Spawns background tasks for periodic scanning, DNS capture,
       and traffic capture.

    Parameters
    ----------
    config:
        Process-wide REX configuration.
    bus:
        Pre-constructed event bus instance.
    """

    def __init__(self, config: RexConfig, bus: EventBus) -> None:
        super().__init__(config, bus)

        # Components (initialised in _on_start)
        self._pal: PlatformAdapter | None = None
        self._scanner: NetworkScanner | None = None
        self._fingerprinter: DeviceFingerprinter | None = None
        self._dns_monitor: DNSMonitor | None = None
        self._traffic_monitor: TrafficMonitor | None = None
        self._port_scanner: PortScanner | None = None
        self._device_store: DeviceStore | None = None

        # Resolved interface name
        self._interface: str | None = None

        # Background task handles
        self._bg_tasks: list[asyncio.Task[None]] = []

    # ------------------------------------------------------------------
    # BaseService abstract implementation
    # ------------------------------------------------------------------

    @property
    def service_name(self) -> ServiceName:
        """Return the canonical service name."""
        return ServiceName.EYES

    async def _on_start(self) -> None:
        """Initialise all sub-components and start background monitors.

        Steps:
        1. Get platform adapter.
        2. Create scanner, fingerprinter, DNS monitor, traffic monitor,
           port scanner, and device store instances.
        3. Auto-detect network interface.
        4. Load DNS threat feeds.
        5. Run initial device scan.
        6. Start periodic scan, DNS capture, and traffic capture
           as background tasks.
        """
        self._log.info("Initialising Eyes service components...")

        # Step 1: Platform adapter
        self._pal = get_adapter()
        self._log.info("Platform adapter: %s", type(self._pal).__name__)

        # Step 2: Create components
        self._scanner = NetworkScanner(self._pal, self.config)
        self._fingerprinter = DeviceFingerprinter(self.config)
        self._dns_monitor = DNSMonitor(self._pal, self.config)
        self._traffic_monitor = TrafficMonitor(self._pal)
        self._port_scanner = PortScanner()
        self._device_store = DeviceStore()

        # Step 3: Detect interface
        try:
            self._interface = await self._scanner.auto_detect_interface()
            self._log.info("Network interface: %s", self._interface)
        except Exception as exc:
            self._log.error(
                "Could not detect network interface: %s. "
                "Scanning will be limited.",
                exc,
            )
            self._interface = None

        # Step 4: Load DNS threat feeds
        try:
            await self._dns_monitor.load_threat_feeds()
        except Exception as exc:
            self._log.warning("Failed to load DNS threat feeds: %s", exc)

        # Step 5: Initial scan
        try:
            await self._run_scan_cycle()
        except Exception as exc:
            self._log.warning("Initial scan failed: %s", exc)

        # Step 6: Background tasks
        self._bg_tasks.append(
            asyncio.create_task(self._periodic_scan(), name="eyes:periodic_scan")
        )

        if self._interface:
            self._bg_tasks.append(
                asyncio.create_task(
                    self._dns_capture_loop(), name="eyes:dns_capture"
                )
            )
            self._bg_tasks.append(
                asyncio.create_task(
                    self._traffic_capture_loop(), name="eyes:traffic_capture"
                )
            )

        self._log.info(
            "Eyes service started with %d background tasks",
            len(self._bg_tasks),
        )

    async def _on_stop(self) -> None:
        """Stop all monitors and cancel background tasks."""
        self._log.info("Stopping Eyes service components...")

        # Signal monitors to stop
        if self._dns_monitor:
            self._dns_monitor.stop()
        if self._traffic_monitor:
            self._traffic_monitor.stop()

        # Cancel background tasks
        for task in self._bg_tasks:
            task.cancel()
        if self._bg_tasks:
            await asyncio.gather(*self._bg_tasks, return_exceptions=True)
        self._bg_tasks.clear()

        self._log.info("Eyes service components stopped.")

    # ==================================================================
    # Periodic scanning
    # ==================================================================

    async def _periodic_scan(self) -> None:
        """Run device discovery every ``config.scan_interval`` seconds.

        Each cycle:
        1. Publish a ScanTriggeredEvent.
        2. Discover devices via the scanner.
        3. Enrich each device with the fingerprinter.
        4. Quick port scan on new devices.
        5. Update the device store.
        6. Publish events for new, updated, and departed devices.
        7. Publish the full scan result to the bus.
        """
        while self._running:
            try:
                await asyncio.sleep(self.config.scan_interval)
                await self._run_scan_cycle()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self._log.exception("Error in periodic scan: %s", exc)
                # Wait a shorter interval before retrying
                await asyncio.sleep(min(30, self.config.scan_interval))

    async def _run_scan_cycle(self) -> None:
        """Execute a single scan-enrich-update-publish cycle."""
        assert self._scanner is not None
        assert self._fingerprinter is not None
        assert self._device_store is not None
        assert self._port_scanner is not None

        # Publish scan-triggered event
        await self._publish_safe(
            STREAM_EYES_SCAN_RESULTS,
            ScanTriggeredEvent(payload={"trigger": "periodic"}),
        )

        # Discover devices
        scan_result: ScanResult = await self._scanner.discover_devices()

        # Enrich each device with fingerprinting
        enrichment_tasks = [
            self._enrich_single_device(dev)
            for dev in scan_result.devices_found
        ]
        await asyncio.gather(*enrichment_tasks, return_exceptions=True)

        # Quick port scan on newly discovered devices
        for mac in scan_result.new_devices:
            for dev in scan_result.devices_found:
                if dev.mac_address.lower() == mac and dev.ip_address:
                    try:
                        ports = await self._port_scanner.quick_scan(dev.ip_address)
                        dev.open_ports = [p[0] for p in ports]
                        dev.services = [p[2] for p in ports if p[2] != "unknown"]
                    except Exception as exc:
                        self._log.debug(
                            "Port scan failed for %s: %s", dev.ip_address, exc,
                        )

        # Update device store
        new_devs, updated_devs, departed_devs = await self._device_store.update_from_scan(
            scan_result
        )

        # Publish new device events
        for dev in new_devs:
            await self._publish_safe(
                STREAM_EYES_DEVICE_UPDATES,
                DeviceDiscoveredEvent(
                    payload=dev.model_dump(mode="json"),
                ),
            )

        # Publish update events
        for dev in updated_devs:
            await self._publish_safe(
                STREAM_EYES_DEVICE_UPDATES,
                DeviceUpdateEvent(
                    payload=dev.model_dump(mode="json"),
                ),
            )

        # Publish scan result summary
        await self._publish_safe(
            STREAM_EYES_SCAN_RESULTS,
            ScanTriggeredEvent(
                payload={
                    "scan_id": scan_result.scan_id,
                    "scan_type": scan_result.scan_type,
                    "devices_found": len(scan_result.devices_found),
                    "new_devices": len(new_devs),
                    "updated_devices": len(updated_devs),
                    "departed_devices": len(departed_devs),
                    "duration_seconds": scan_result.duration_seconds,
                    "errors": scan_result.errors,
                },
            ),
        )

        self._log.info(
            "Scan cycle complete: %d found, %d new, %d updated, %d departed",
            len(scan_result.devices_found),
            len(new_devs),
            len(updated_devs),
            len(departed_devs),
        )

    async def _enrich_single_device(self, device: Device) -> None:
        """Enrich one device with fingerprinting data.

        Wrapped in its own method so exceptions from one device do not
        block the others.

        Parameters
        ----------
        device:
            Device to enrich.
        """
        assert self._fingerprinter is not None
        try:
            await self._fingerprinter.enrich_device(device)
        except Exception as exc:
            self._log.debug(
                "Fingerprinting failed for %s: %s",
                device.mac_address, exc,
            )

    # ==================================================================
    # DNS capture
    # ==================================================================

    async def _dns_capture_loop(self) -> None:
        """Run the DNS monitor in a background task.

        Automatically restarts on error with exponential backoff.
        """
        assert self._dns_monitor is not None
        assert self._interface is not None

        backoff = 5
        while self._running:
            try:
                self._log.info("Starting DNS capture on %s", self._interface)
                await self._dns_monitor.start_capture(self._interface)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self._log.warning(
                    "DNS capture failed: %s. Retrying in %ds", exc, backoff,
                )
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 120)

    # ==================================================================
    # Traffic capture
    # ==================================================================

    async def _traffic_capture_loop(self) -> None:
        """Run the traffic monitor in a background task.

        Automatically restarts on error with exponential backoff.
        Also periodically runs anomaly detection on all tracked devices.
        """
        assert self._traffic_monitor is not None
        assert self._interface is not None

        # Start a parallel anomaly detection sweep
        asyncio.create_task(
            self._anomaly_sweep_loop(), name="eyes:anomaly_sweep"
        )

        backoff = 5
        while self._running:
            try:
                self._log.info("Starting traffic capture on %s", self._interface)
                await self._traffic_monitor.start_passive_capture(self._interface)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self._log.warning(
                    "Traffic capture failed: %s. Retrying in %ds", exc, backoff,
                )
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 120)

    async def _anomaly_sweep_loop(self) -> None:
        """Periodically run anomaly detection on all tracked devices.

        Runs every scan_interval seconds (same cadence as device scans)
        but offset by half the interval.
        """
        assert self._traffic_monitor is not None

        await asyncio.sleep(self.config.scan_interval / 2)

        while self._running:
            try:
                summary = self._traffic_monitor.get_traffic_summary()
                device_ips = list(
                    summary.get("per_device_bytes", {}).keys()
                )

                total_threats = 0
                for ip in device_ips:
                    threats = self._traffic_monitor.detect_anomalies(ip)
                    for threat in threats:
                        total_threats += 1
                        await self._handle_threat(threat)

                if total_threats:
                    self._log.warning(
                        "Anomaly sweep detected %d threats across %d devices",
                        total_threats, len(device_ips),
                    )

            except asyncio.CancelledError:
                break
            except Exception as exc:
                self._log.exception("Anomaly sweep error: %s", exc)

            await asyncio.sleep(self.config.scan_interval)

    # ==================================================================
    # Threat handling
    # ==================================================================

    async def _handle_threat(self, threat: ThreatEvent) -> None:
        """Publish a threat event to the bus.

        Parameters
        ----------
        threat:
            The detected threat event.
        """
        self._log.warning(
            "THREAT: [%s/%s] %s",
            threat.threat_type,
            threat.severity,
            threat.description,
        )
        await self._publish_safe(
            STREAM_EYES_THREATS,
            ThreatDetectedEvent(
                payload=threat.model_dump(mode="json"),
                priority=self._severity_to_priority(threat.severity),
            ),
        )

    @staticmethod
    def _severity_to_priority(severity: str) -> int:
        """Map threat severity to event priority (1-10).

        Parameters
        ----------
        severity:
            Severity string.

        Returns
        -------
        int
            Priority value.
        """
        mapping = {
            "critical": 10,
            "high": 8,
            "medium": 5,
            "low": 3,
            "info": 1,
        }
        return mapping.get(severity, 5)

    # ==================================================================
    # Command consumption
    # ==================================================================

    async def _consume_loop(self) -> None:
        """Subscribe to STREAM_CORE_COMMANDS for manual scan requests.

        Handles commands:
        - ``scan_now``: trigger an immediate full scan.
        - ``deep_scan``: full 65535-port scan on a specific device.
        - ``check_exposed``: detect exposed services on the gateway.
        """
        if not self.bus or not await self.bus.health_check():
            # Bus not available -- fall back to idle loop
            while self._running:
                await asyncio.sleep(1)
            return

        async def handler(
            stream_name: str, msg_id: str, fields: dict[str, Any]
        ) -> None:
            data_raw = fields.get("data", "{}")
            try:
                data = json.loads(data_raw) if isinstance(data_raw, str) else data_raw
            except (json.JSONDecodeError, TypeError):
                data = {}

            payload = data.get("payload", {})
            data.get("event_type", "")
            target_service = payload.get("target_service", "")

            # Only handle commands directed at Eyes
            if target_service and target_service != ServiceName.EYES:
                return

            command = payload.get("command", "")
            self._log.info("Received command: %s", command)

            if command == "scan_now":
                await self._run_scan_cycle()

            elif command == "deep_scan":
                target_ip = payload.get("target_ip", "")
                if target_ip and self._port_scanner:
                    results = await self._port_scanner.deep_scan(target_ip)
                    self._log.info(
                        "Deep scan of %s: %d open ports",
                        target_ip, len(results),
                    )
                    # Update device store with new port info
                    if self._device_store:
                        dev = await self._device_store.find_by_ip(target_ip)
                        if dev:
                            await self._device_store.set_trust_level(
                                dev.mac_address, dev.trust_level
                            )

            elif command == "check_exposed":
                if self._scanner and self._port_scanner:
                    try:
                        net_info = await self._scanner.get_network_info()
                        threats = await self._port_scanner.detect_exposed_services(
                            net_info.gateway_ip, net_info.public_ip
                        )
                        for threat in threats:
                            await self._handle_threat(threat)
                    except Exception as exc:
                        self._log.warning(
                            "Exposed service check failed: %s", exc,
                        )

            elif command == "dns_stats":
                if self._dns_monitor:
                    stats = self._dns_monitor.get_dns_stats()
                    self._log.info("DNS stats: %s", stats)

            elif command == "traffic_stats" and self._traffic_monitor:
                stats = self._traffic_monitor.get_traffic_summary()
                self._log.info("Traffic stats: %s", stats)

        try:
            await self.bus.subscribe([STREAM_CORE_COMMANDS], handler)
        except Exception as exc:
            self._log.warning(
                "Could not subscribe to commands: %s. "
                "Manual scan requests will not be processed.",
                exc,
            )
            while self._running:
                await asyncio.sleep(1)

    # ==================================================================
    # Safe bus publishing
    # ==================================================================

    async def _publish_safe(self, stream: str, event: Any) -> None:
        """Publish an event to the bus, swallowing errors.

        Parameters
        ----------
        stream:
            Target Redis stream key.
        event:
            Event to publish.
        """
        try:
            await self.bus.publish(stream, event)
        except RexBusUnavailableError:
            self._log.debug(
                "Bus unavailable; event for %s written to WAL", stream,
            )
        except Exception as exc:
            self._log.warning("Failed to publish to %s: %s", stream, exc)

    # ==================================================================
    # Public accessors for other layers
    # ==================================================================

    @property
    def device_store(self) -> DeviceStore | None:
        """Return the device store instance.

        Returns
        -------
        DeviceStore or None
        """
        return self._device_store

    @property
    def dns_monitor(self) -> DNSMonitor | None:
        """Return the DNS monitor instance.

        Returns
        -------
        DNSMonitor or None
        """
        return self._dns_monitor

    @property
    def traffic_monitor(self) -> TrafficMonitor | None:
        """Return the traffic monitor instance.

        Returns
        -------
        TrafficMonitor or None
        """
        return self._traffic_monitor

    @property
    def port_scanner(self) -> PortScanner | None:
        """Return the port scanner instance.

        Returns
        -------
        PortScanner or None
        """
        return self._port_scanner
