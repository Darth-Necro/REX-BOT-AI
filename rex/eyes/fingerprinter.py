"""Device fingerprinter -- identifies device type, vendor, and OS.

Layer 1 -- imports from ``rex.shared``, ``rex.pal``, and stdlib.

Builds rich identity profiles by combining OUI vendor lookups, OS
fingerprinting (nmap -O or TCP stack heuristics), port signatures,
hostname patterns, and mDNS service type detection.
"""

from __future__ import annotations

import asyncio
import csv
import io
import logging

import re
import shutil
import sqlite3

import defusedxml.ElementTree as DefusedET
from pathlib import Path
from typing import TYPE_CHECKING

from rex.shared.constants import DEFAULT_NETWORK_TIMEOUT, DEFAULT_SCAN_TIMEOUT
from rex.shared.enums import DeviceType
from rex.shared.utils import is_private_ip, is_valid_ipv4, mac_normalize

if TYPE_CHECKING:
    from rex.shared.config import RexConfig
    from rex.shared.models import Device

logger = logging.getLogger("rex.eyes.fingerprinter")

from rex.shared.subprocess_util import run_subprocess_async


class DeviceFingerprinter:
    """Identifies device type, vendor, and OS from network signatures.

    Uses a layered heuristic approach:
    1. MAC OUI vendor lookup (cached in a local SQLite database).
    2. OS fingerprinting via nmap -O (requires root) or TCP stack analysis.
    3. Decision-tree classification combining vendor, ports, hostname,
       and mDNS service types.

    Parameters
    ----------
    config:
        Process-wide REX configuration (used for cache paths).
    """

    OUI_DB_URL: str = "https://standards-oui.ieee.org/oui/oui.csv"
    OUI_CACHE_PATH: Path = Path("/etc/rex-bot-ai/cache/oui.db")

    # -----------------------------------------------------------------
    # Vendor -> device type mapping (lowercased partial match)
    # -----------------------------------------------------------------
    KNOWN_VENDORS: dict[str, DeviceType] = {
        # IoT cameras
        "ring": DeviceType.IOT_CAMERA,
        "arlo": DeviceType.IOT_CAMERA,
        "wyze": DeviceType.IOT_CAMERA,
        "hikvision": DeviceType.IOT_CAMERA,
        "dahua": DeviceType.IOT_CAMERA,
        "reolink": DeviceType.IOT_CAMERA,
        "amcrest": DeviceType.IOT_CAMERA,
        # Climate / thermostats
        "nest": DeviceType.IOT_CLIMATE,
        "ecobee": DeviceType.IOT_CLIMATE,
        "honeywell": DeviceType.IOT_CLIMATE,
        # IoT hubs
        "philips hue": DeviceType.IOT_HUB,
        "signify": DeviceType.IOT_HUB,
        "smartthings": DeviceType.IOT_HUB,
        "wink": DeviceType.IOT_HUB,
        "tuya": DeviceType.IOT_HUB,
        # Smart TVs
        "roku": DeviceType.SMART_TV,
        "samsung electronics": DeviceType.SMART_TV,
        "lg electronics": DeviceType.SMART_TV,
        "vizio": DeviceType.SMART_TV,
        "tcl": DeviceType.SMART_TV,
        "hisense": DeviceType.SMART_TV,
        # Gaming consoles
        "sony interactive": DeviceType.GAMING_CONSOLE,
        "nintendo": DeviceType.GAMING_CONSOLE,
        # Printers
        "hp inc": DeviceType.PRINTER,
        "hewlett packard": DeviceType.PRINTER,
        "brother": DeviceType.PRINTER,
        "canon": DeviceType.PRINTER,
        "epson": DeviceType.PRINTER,
        "xerox": DeviceType.PRINTER,
        "lexmark": DeviceType.PRINTER,
        # Network equipment
        "cisco": DeviceType.NETWORK_EQUIPMENT,
        "ubiquiti": DeviceType.NETWORK_EQUIPMENT,
        "netgear": DeviceType.NETWORK_EQUIPMENT,
        "tp-link": DeviceType.NETWORK_EQUIPMENT,
        "linksys": DeviceType.NETWORK_EQUIPMENT,
        "aruba": DeviceType.NETWORK_EQUIPMENT,
        "mikrotik": DeviceType.NETWORK_EQUIPMENT,
        "zyxel": DeviceType.NETWORK_EQUIPMENT,
        "dlink": DeviceType.NETWORK_EQUIPMENT,
        "d-link": DeviceType.NETWORK_EQUIPMENT,
        "asus": DeviceType.NETWORK_EQUIPMENT,
        # Phones (default -- disambiguated further below)
        "apple": DeviceType.PHONE,
        "google": DeviceType.IOT_HUB,
        "microsoft": DeviceType.GAMING_CONSOLE,
        "amazon": DeviceType.IOT_HUB,
    }

    # Port-signature patterns: port -> likely device type
    PORT_SIGNATURES: dict[int, DeviceType] = {
        9100: DeviceType.PRINTER,     # HP JetDirect / raw printing
        631: DeviceType.PRINTER,      # IPP / CUPS
        515: DeviceType.PRINTER,      # LPD
        548: DeviceType.DESKTOP,      # AFP (macOS)
        3689: DeviceType.DESKTOP,     # DAAP (iTunes)
        32400: DeviceType.SERVER,     # Plex Media Server
        8096: DeviceType.SERVER,      # Jellyfin
        8008: DeviceType.SMART_TV,    # Chromecast HTTP
        8443: DeviceType.SMART_TV,    # Chromecast HTTPS
        5353: DeviceType.IOT_HUB,    # mDNS (common on IoT hubs)
        1883: DeviceType.IOT_HUB,    # MQTT
        8883: DeviceType.IOT_HUB,    # MQTT over TLS
        3389: DeviceType.DESKTOP,    # RDP
        5900: DeviceType.DESKTOP,    # VNC
        5901: DeviceType.DESKTOP,    # VNC alt
    }

    # mDNS service type -> device type
    MDNS_SIGNATURES: dict[str, DeviceType] = {
        "_airplay._tcp": DeviceType.SMART_TV,
        "_raop._tcp": DeviceType.SMART_TV,
        "_googlecast._tcp": DeviceType.SMART_TV,
        "_printer._tcp": DeviceType.PRINTER,
        "_ipp._tcp": DeviceType.PRINTER,
        "_pdl-datastream._tcp": DeviceType.PRINTER,
        "_smb._tcp": DeviceType.DESKTOP,
        "_afpovertcp._tcp": DeviceType.DESKTOP,
        "_ssh._tcp": DeviceType.SERVER,
        "_http._tcp": DeviceType.SERVER,
        "_hap._tcp": DeviceType.IOT_HUB,  # HomeKit
        "_homekit._tcp": DeviceType.IOT_HUB,
        "_mqtt._tcp": DeviceType.IOT_HUB,
    }

    # Hostname regex patterns
    HOSTNAME_PATTERNS: list[tuple[str, DeviceType]] = [
        (r"(?i)iphone", DeviceType.PHONE),
        (r"(?i)ipad", DeviceType.TABLET),
        (r"(?i)macbook", DeviceType.LAPTOP),
        (r"(?i)imac", DeviceType.DESKTOP),
        (r"(?i)mac-?pro", DeviceType.DESKTOP),
        (r"(?i)mac-?mini", DeviceType.DESKTOP),
        (r"(?i)android", DeviceType.PHONE),
        (r"(?i)pixel", DeviceType.PHONE),
        (r"(?i)galaxy", DeviceType.PHONE),
        (r"(?i)oneplus", DeviceType.PHONE),
        (r"(?i)desktop", DeviceType.DESKTOP),
        (r"(?i)laptop", DeviceType.LAPTOP),
        (r"(?i)surface", DeviceType.LAPTOP),
        (r"(?i)thinkpad", DeviceType.LAPTOP),
        (r"(?i)printer|laserjet|deskjet|officejet", DeviceType.PRINTER),
        (r"(?i)roku|firestick|fire-?tv|chromecast|appletv|apple-?tv", DeviceType.SMART_TV),
        (r"(?i)playstation|ps[45]", DeviceType.GAMING_CONSOLE),
        (r"(?i)xbox", DeviceType.GAMING_CONSOLE),
        (r"(?i)switch|nintendo", DeviceType.GAMING_CONSOLE),
        (r"(?i)nest|ecobee|thermostat", DeviceType.IOT_CLIMATE),
        (r"(?i)camera|cam\d|doorbell", DeviceType.IOT_CAMERA),
        (r"(?i)server|nas|synology|qnap|truenas", DeviceType.SERVER),
        (r"(?i)router|gateway|mesh|extender|repeater|ap\d", DeviceType.NETWORK_EQUIPMENT),
    ]

    def __init__(self, config: RexConfig | None = None) -> None:
        self._config = config
        self._logger = logging.getLogger("rex.eyes.fingerprinter")
        self._oui_db_ready = False
        self._nmap_available: bool | None = None

        if config:
            self.OUI_CACHE_PATH = config.data_dir / "cache" / "oui.db"

    # ==================================================================
    # MAC OUI vendor lookup
    # ==================================================================

    async def fingerprint_mac(self, mac: str) -> str | None:
        """Look up the vendor for a MAC address using the OUI database.

        On first invocation, the OUI database is initialised from a
        bundled CSV or downloaded from IEEE.  Results are cached in a
        local SQLite database for fast subsequent lookups.

        Parameters
        ----------
        mac:
            MAC address in any common format.

        Returns
        -------
        str or None
            Vendor/organisation name, or ``None`` if not found.
        """
        try:
            normalised = mac_normalize(mac)
        except ValueError:
            self._logger.debug("Invalid MAC for OUI lookup: %s", mac)
            return None

        oui_prefix = normalised.replace(":", "")[:6].upper()

        if not self._oui_db_ready:
            await self._ensure_oui_db()

        try:
            with sqlite3.connect(str(self.OUI_CACHE_PATH)) as conn:
                cursor = conn.execute(
                    "SELECT vendor FROM oui WHERE prefix = ?", (oui_prefix,)
                )
                row = cursor.fetchone()
            if row:
                return row[0]
        except sqlite3.Error as exc:
            self._logger.debug("OUI DB query error: %s", exc)

        return None

    async def _ensure_oui_db(self) -> None:
        """Create and populate the OUI SQLite cache if it does not exist.

        Attempts to download the IEEE OUI CSV.  If the download fails
        (no internet, timeout), a minimal built-in table is seeded
        instead so lookups always work.
        """
        if self.OUI_CACHE_PATH.exists():
            try:
                conn = sqlite3.connect(str(self.OUI_CACHE_PATH))
                row = conn.execute("SELECT COUNT(*) FROM oui").fetchone()
                conn.close()
                if row and row[0] > 0:
                    self._oui_db_ready = True
                    self._logger.debug("OUI DB ready with %d entries", row[0])
                    return
            except sqlite3.Error:
                pass

        self.OUI_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(str(self.OUI_CACHE_PATH))
        conn.execute(
            "CREATE TABLE IF NOT EXISTS oui "
            "(prefix TEXT PRIMARY KEY, vendor TEXT NOT NULL)"
        )
        conn.commit()

        # Try downloading the IEEE CSV
        csv_data = await self._download_oui_csv()
        if csv_data:
            self._load_oui_csv(conn, csv_data)
        else:
            self._seed_builtin_oui(conn)

        conn.close()
        self._oui_db_ready = True

    async def _download_oui_csv(self) -> str | None:
        """Download the IEEE OUI CSV file.

        Returns
        -------
        str or None
            Raw CSV text, or ``None`` on failure.
        """
        curl = shutil.which("curl")
        if not curl:
            self._logger.debug("curl not available for OUI download")
            return None

        rc, stdout, _ = await run_subprocess_async(
            "curl", "-sL", "--max-time", "30", self.OUI_DB_URL,
            timeout=45, label="curl-oui-csv",
        )
        if rc == 0 and stdout and len(stdout) > 1000:
            self._logger.info("Downloaded OUI CSV: %d bytes", len(stdout))
            return stdout

        return None

    def _load_oui_csv(self, conn: sqlite3.Connection, csv_data: str) -> None:
        """Parse the IEEE CSV and insert records into SQLite.

        Parameters
        ----------
        conn:
            Open SQLite connection.
        csv_data:
            Raw CSV text.
        """
        count = 0
        reader = csv.reader(io.StringIO(csv_data))
        for row in reader:
            # IEEE CSV format: Registry,Assignment,Organization Name,...
            if len(row) >= 3:
                prefix = row[1].strip().upper()
                vendor = row[2].strip()
                if len(prefix) == 6 and prefix.isalnum() and vendor:
                    try:
                        conn.execute(
                            "INSERT OR REPLACE INTO oui (prefix, vendor) VALUES (?, ?)",
                            (prefix, vendor),
                        )
                        count += 1
                    except sqlite3.Error:
                        continue
        conn.commit()
        self._logger.info("Loaded %d OUI entries from IEEE CSV", count)

    def _seed_builtin_oui(self, conn: sqlite3.Connection) -> None:
        """Insert a minimal set of well-known OUI prefixes.

        This fallback ensures vendor lookup works even without internet
        access on first run.

        Parameters
        ----------
        conn:
            Open SQLite connection.
        """
        builtin: list[tuple[str, str]] = [
            # Apple
            ("3C22FB", "Apple, Inc."), ("A4B197", "Apple, Inc."),
            ("F0D1A9", "Apple, Inc."), ("F8FF0A", "Apple, Inc."),
            ("D0817A", "Apple, Inc."), ("B0BE76", "Apple, Inc."),
            # Google / Nest
            ("F4F5D8", "Google, Inc."), ("54609A", "Google, Inc."),
            ("18B430", "Google LLC"), ("A47733", "Google LLC"),
            # Samsung
            ("B47443", "Samsung Electronics"), ("8C71F8", "Samsung Electronics"),
            ("AC5F3E", "Samsung Electronics"),
            # Amazon
            ("F0D2F1", "Amazon Technologies Inc."), ("68372B", "Amazon Technologies Inc."),
            ("B47C9C", "Amazon Technologies Inc."),
            # Microsoft / Xbox
            ("7C1E52", "Microsoft Corporation"), ("28185C", "Microsoft Corporation"),
            # Sony PlayStation
            ("F8D0AC", "Sony Interactive Entertainment"),
            ("000422", "Sony Interactive Entertainment"),
            # Roku
            ("D83134", "Roku, Inc."), ("B0A737", "Roku, Inc."),
            # Intel (common in PCs)
            ("3C6AA7", "Intel Corporate"), ("48A472", "Intel Corporate"),
            ("1C6973", "Intel Corporate"), ("A0369F", "Intel Corporate"),
            # Cisco
            ("00265A", "Cisco Systems"), ("0023BE", "Cisco Systems"),
            # Ubiquiti
            ("802AA8", "Ubiquiti Inc"), ("F09FC2", "Ubiquiti Inc"),
            # HP
            ("3C4A92", "HP Inc."), ("308D99", "HP Inc."),
            # Brother
            ("001BA9", "Brother Industries"),
            # TP-Link
            ("50C7BF", "TP-Link Technologies"), ("F4EC38", "TP-Link Technologies"),
            # Netgear
            ("2CB05D", "Netgear"), ("A42B8C", "Netgear"),
            # Raspberry Pi
            ("B827EB", "Raspberry Pi Foundation"),
            ("DC26D4", "Raspberry Pi Foundation"),
            ("E45F01", "Raspberry Pi Foundation"),
            # Espressif (ESP32 / IoT)
            ("240AC4", "Espressif Inc."), ("A4CF12", "Espressif Inc."),
            # Ring
            ("346892", "Ring LLC"),
            # Philips / Signify (Hue)
            ("001788", "Signify B.V."), ("ECB5FA", "Signify B.V."),
            # Nintendo
            ("002659", "Nintendo Co., Ltd."), ("34AF2C", "Nintendo Co., Ltd."),
        ]
        conn.executemany(
            "INSERT OR REPLACE INTO oui (prefix, vendor) VALUES (?, ?)",
            builtin,
        )
        conn.commit()
        self._logger.info("Seeded %d built-in OUI entries", len(builtin))

    # ==================================================================
    # OS fingerprinting
    # ==================================================================

    async def fingerprint_os(self, ip: str) -> str | None:
        """Attempt OS fingerprinting for the given IP.

        Tries ``nmap -O`` first (requires root), falls back to TTL-based
        TCP stack heuristics.

        Parameters
        ----------
        ip:
            Target IPv4 address.

        Returns
        -------
        str or None
            Best-guess OS string, or ``None`` if unknown.
        """
        if not is_valid_ipv4(ip):
            return None

        if not is_private_ip(ip):
            self._logger.warning("Refusing OS fingerprint on non-private IP: %s", ip)
            return None

        # Try nmap -O (privileged)
        os_guess = await self._nmap_os_detect(ip)
        if os_guess:
            return os_guess

        # Fallback: TTL-based heuristic from a ping
        return await self._ttl_os_guess(ip)

    async def _nmap_os_detect(self, ip: str) -> str | None:
        """Run ``nmap -O`` and extract the OS guess.

        Parameters
        ----------
        ip:
            Target IPv4 address.

        Returns
        -------
        str or None
            OS string from nmap, or ``None`` on failure.
        """
        if not self._is_nmap_available():
            return None

        rc, stdout, _ = await run_subprocess_async(
            "nmap", "-O", "--osscan-guess", "-oX", "-", ip,
            timeout=DEFAULT_SCAN_TIMEOUT, label="nmap-os-fingerprint",
        )
        if rc != 0:
            return None

        try:
            root = DefusedET.fromstring(stdout)
            for host in root.findall("host"):
                os_elem = host.find("os")
                if os_elem is not None:
                    osmatch = os_elem.find("osmatch")
                    if osmatch is not None:
                        name = osmatch.get("name", "")
                        accuracy = osmatch.get("accuracy", "")
                        if name:
                            return f"{name} ({accuracy}% confidence)" if accuracy else name
        except DefusedET.ParseError:
            pass

        return None

    async def _ttl_os_guess(self, ip: str) -> str | None:
        """Guess the OS from the TTL value in a ping response.

        Common TTL defaults:
        - Linux/Unix: 64
        - Windows: 128
        - macOS: 64
        - Network equipment (Cisco, etc.): 255

        Parameters
        ----------
        ip:
            Target IPv4 address.

        Returns
        -------
        str or None
            OS family guess, or ``None`` if unreachable.
        """
        rc, stdout, _ = await run_subprocess_async(
            "ping", "-c", "1", "-W", str(DEFAULT_NETWORK_TIMEOUT), ip,
            timeout=DEFAULT_NETWORK_TIMEOUT + 2, label="ping-ttl-guess",
        )
        if rc != 0:
            return None

        output = stdout
        ttl_match = re.search(r"ttl[=:](\d+)", output, re.IGNORECASE)
        if not ttl_match:
            return None

        ttl = int(ttl_match.group(1))

        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "Network Equipment"

        return None

    # ==================================================================
    # Device type classification
    # ==================================================================

    def identify_device_type(
        self,
        vendor: str | None,
        os_guess: str | None,
        open_ports: list[int],
        hostname: str | None,
        mdns_services: list[str] | None = None,
    ) -> DeviceType:
        """Classify a device type using a heuristic decision tree.

        Evaluation order (first match wins within each tier, but later
        tiers can override if confidence is higher):

        1. Hostname patterns (strongest signal -- user-assigned names).
        2. mDNS service types (very reliable).
        3. Port signatures (good signal for servers, printers).
        4. Vendor name patterns (broad but less specific).
        5. OS guess fallback.

        Parameters
        ----------
        vendor:
            OUI vendor name.
        os_guess:
            OS fingerprint string.
        open_ports:
            List of open TCP ports.
        hostname:
            Hostname from DNS or DHCP.
        mdns_services:
            Discovered mDNS/Bonjour service types.

        Returns
        -------
        DeviceType
            Best-guess classification.
        """
        # --- Tier 1: Hostname patterns (most reliable) ---
        if hostname:
            for pattern, dtype in self.HOSTNAME_PATTERNS:
                if re.search(pattern, hostname):
                    self._logger.debug(
                        "Device classified by hostname %r -> %s",
                        hostname, dtype,
                    )
                    return dtype

        # --- Tier 2: mDNS service types ---
        if mdns_services:
            for svc in mdns_services:
                svc_lower = svc.lower()
                for svc_pattern, dtype in self.MDNS_SIGNATURES.items():
                    if svc_pattern in svc_lower:
                        self._logger.debug(
                            "Device classified by mDNS %r -> %s", svc, dtype,
                        )
                        return dtype

        # --- Tier 3: Port signatures ---
        port_set = set(open_ports)
        # Printer ports are very distinctive
        if port_set & {9100, 515, 631}:
            return DeviceType.PRINTER
        # Chromecast / smart TV
        if port_set & {8008, 8443}:
            return DeviceType.SMART_TV
        # Media server
        if port_set & {32400, 8096}:
            return DeviceType.SERVER
        # SSH + HTTP but no desktop ports: server
        if 22 in port_set and (80 in port_set or 443 in port_set) and not port_set & {3389, 5900}:
                return DeviceType.SERVER
        # RDP or VNC: desktop
        if port_set & {3389, 5900, 5901}:
            return DeviceType.DESKTOP

        # --- Tier 4: Vendor patterns ---
        if vendor:
            vendor_lower = vendor.lower()
            for vendor_key, dtype in self.KNOWN_VENDORS.items():
                if vendor_key in vendor_lower:
                    # Disambiguate Apple: laptops vs phones vs desktops
                    if "apple" in vendor_lower:
                        return self._disambiguate_apple(
                            hostname, open_ports, os_guess
                        )
                    # Disambiguate Microsoft: could be Xbox or PC
                    if "microsoft" in vendor_lower:
                        return self._disambiguate_microsoft(
                            hostname, open_ports, os_guess
                        )
                    # Disambiguate Samsung: TV vs phone
                    if "samsung" in vendor_lower:
                        return self._disambiguate_samsung(
                            hostname, open_ports
                        )
                    self._logger.debug(
                        "Device classified by vendor %r -> %s",
                        vendor, dtype,
                    )
                    return dtype

        # --- Tier 5: OS guess fallback ---
        if os_guess:
            os_lower = os_guess.lower()
            if "windows" in os_lower:
                return DeviceType.DESKTOP
            if "linux" in os_lower:
                # Linux with server ports -> server, else desktop
                if port_set & {22, 80, 443, 8080}:
                    return DeviceType.SERVER
                return DeviceType.DESKTOP
            if "ios" in os_lower or "iphone" in os_lower:
                return DeviceType.PHONE
            if "android" in os_lower:
                return DeviceType.PHONE
            if "macos" in os_lower or "mac os" in os_lower:
                return DeviceType.DESKTOP

        return DeviceType.UNKNOWN

    # ------------------------------------------------------------------
    # Vendor disambiguation helpers
    # ------------------------------------------------------------------

    def _disambiguate_apple(
        self, hostname: str | None, open_ports: list[int], os_guess: str | None
    ) -> DeviceType:
        """Disambiguate Apple devices (iPhone, iPad, Mac, Apple TV).

        Parameters
        ----------
        hostname:
            Device hostname.
        open_ports:
            Open ports.
        os_guess:
            OS fingerprint.

        Returns
        -------
        DeviceType
        """
        hn = (hostname or "").lower()
        if "iphone" in hn:
            return DeviceType.PHONE
        if "ipad" in hn:
            return DeviceType.TABLET
        if "macbook" in hn:
            return DeviceType.LAPTOP
        if "appletv" in hn or "apple-tv" in hn:
            return DeviceType.SMART_TV
        # AFP port (548) is a Mac signature
        if 548 in open_ports:
            return DeviceType.DESKTOP
        if os_guess and "ios" in os_guess.lower():
            return DeviceType.PHONE
        # Default Apple -> phone (most common Apple device)
        return DeviceType.PHONE

    def _disambiguate_microsoft(
        self, hostname: str | None, open_ports: list[int], os_guess: str | None
    ) -> DeviceType:
        """Disambiguate Microsoft devices (Xbox vs Windows PC).

        Parameters
        ----------
        hostname:
            Device hostname.
        open_ports:
            Open ports.
        os_guess:
            OS fingerprint.

        Returns
        -------
        DeviceType
        """
        hn = (hostname or "").lower()
        if "xbox" in hn:
            return DeviceType.GAMING_CONSOLE
        if "surface" in hn:
            return DeviceType.LAPTOP
        # RDP is a strong Windows PC signal
        if 3389 in open_ports:
            return DeviceType.DESKTOP
        if os_guess and "windows" in os_guess.lower():
            return DeviceType.DESKTOP
        return DeviceType.GAMING_CONSOLE

    def _disambiguate_samsung(
        self, hostname: str | None, open_ports: list[int]
    ) -> DeviceType:
        """Disambiguate Samsung devices (TV vs phone vs tablet).

        Parameters
        ----------
        hostname:
            Device hostname.
        open_ports:
            Open ports.

        Returns
        -------
        DeviceType
        """
        hn = (hostname or "").lower()
        if "galaxy" in hn:
            return DeviceType.PHONE
        if "tab" in hn:
            return DeviceType.TABLET
        # Samsung TVs often expose Chromecast-like ports
        if set(open_ports) & {8001, 8002, 8008, 8443}:
            return DeviceType.SMART_TV
        # Default Samsung -> smart TV (very common on home networks)
        return DeviceType.SMART_TV

    # ==================================================================
    # Full enrichment pipeline
    # ==================================================================

    async def enrich_device(self, device: Device) -> Device:
        """Run all fingerprinting heuristics and update the device in place.

        Adds vendor, os_guess, and device_type fields.

        Parameters
        ----------
        device:
            A device with at least ``mac_address`` and optionally
            ``ip_address`` populated.

        Returns
        -------
        Device
            The same device instance, mutated with enriched fields.
        """
        # Vendor lookup
        if not device.vendor:
            vendor = await self.fingerprint_mac(device.mac_address)
            if vendor:
                device.vendor = vendor
                self._logger.debug(
                    "Vendor for %s: %s", device.mac_address, vendor,
                )

        # OS fingerprinting (only if we have an IP)
        if not device.os_guess and device.ip_address:
            os_guess = await self.fingerprint_os(device.ip_address)
            if os_guess:
                device.os_guess = os_guess
                self._logger.debug(
                    "OS for %s: %s", device.ip_address, os_guess,
                )

        # Device type classification
        if device.device_type == DeviceType.UNKNOWN:
            device.device_type = self.identify_device_type(
                vendor=device.vendor,
                os_guess=device.os_guess,
                open_ports=device.open_ports,
                hostname=device.hostname,
                mdns_services=None,
            )
            if device.device_type != DeviceType.UNKNOWN:
                self._logger.info(
                    "Classified %s (%s) as %s",
                    device.mac_address,
                    device.hostname or device.ip_address or "?",
                    device.device_type,
                )

        return device

    # ------------------------------------------------------------------
    # Tool availability
    # ------------------------------------------------------------------

    def _is_nmap_available(self) -> bool:
        """Check whether nmap is on ``PATH``. Cached after first call.

        Returns
        -------
        bool
        """
        if self._nmap_available is None:
            self._nmap_available = shutil.which("nmap") is not None
        return self._nmap_available
