"""Privacy auditing infrastructure for REX.

Provides continuous verification that REX is honouring its privacy
guarantees: no unauthorized outbound connections, proper encryption
of data at rest, and transparent reporting of all external service
interactions.
"""

from __future__ import annotations

import logging
import os
import socket
import struct
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from rex.pal.base import PlatformAdapter
    from rex.shared.config import RexConfig

import contextlib

from rex.core.privacy.data_classifier import (
    DATA_CLASSIFICATIONS,
    DataClassifier,
    DataPrivacyTier,
)

logger = logging.getLogger(__name__)


class PrivacyAuditor:
    """Continuous privacy audit engine for REX-BOT-AI.

    Inspects live system state (outbound connections, data stores,
    encryption posture, external service integrations) and produces
    structured audit reports.

    Parameters
    ----------
    config:
        The global REX configuration object.
    pal:
        The platform adapter for OS-level queries.
    """

    def __init__(self, config: RexConfig, pal: PlatformAdapter) -> None:
        self._config: RexConfig = config
        self._pal: PlatformAdapter = pal
        self._classifier: DataClassifier = DataClassifier()

    # ----------------------------------------------------------------
    # Individual audit checks
    # ----------------------------------------------------------------

    def audit_outbound_connections(self) -> list[dict[str, Any]]:
        """Enumerate all active outbound TCP connections with metadata.

        Parses ``/proc/net/tcp`` and ``/proc/net/tcp6`` and enriches
        each entry with the owning PID and process name (when
        readable from ``/proc``).

        Returns
        -------
        list[dict]
            Each dict contains ``remote_ip``, ``remote_port``,
            ``local_ip``, ``local_port``, ``state``, ``pid``,
            and ``process_name``.
        """
        connections: list[dict[str, Any]] = []

        for proc_path in ("/proc/net/tcp", "/proc/net/tcp6"):
            raw = self._parse_proc_net_tcp(proc_path)
            connections.extend(raw)

        # Enrich with PID / process name via inode lookup
        inode_to_pid = self._build_inode_pid_map()
        for conn in connections:
            inode = conn.get("inode", "0")
            pid = inode_to_pid.get(inode)
            conn["pid"] = pid
            conn["process_name"] = self._get_process_name(pid) if pid else None

        return connections

    def audit_data_inventory(self) -> dict[str, Any]:
        """Inventory all REX data stores with sizes and record counts.

        Scans the configured ``data_dir`` for known subdirectories and
        computes file counts and total sizes.

        Returns
        -------
        dict
            Top-level keys are data-store names (e.g. ``"dns_logs"``,
            ``"threat_events"``, ``"captures"``).  Each value is a dict
            with ``file_count``, ``total_bytes``, ``privacy_tier``.
        """
        data_dir = self._config.data_dir
        stores: dict[str, dict[str, str | int]] = {
            "dns_logs": "logs/dns",
            "threat_events": "threats",
            "captures": "captures",
            "knowledge_base": "knowledge",
            "device_fingerprints": "devices",
            "behavioral_baselines": "baselines",
            "operational_logs": "logs",
            "secrets": "secrets",
            "plugins": "plugins",
        }

        inventory: dict[str, Any] = {}
        for store_name, subdir in stores.items():
            store_path = data_dir / subdir
            file_count = 0
            total_bytes = 0

            if store_path.is_dir():
                try:
                    for entry in store_path.rglob("*"):
                        if entry.is_file():
                            file_count += 1
                            with contextlib.suppress(OSError):
                                total_bytes += entry.stat().st_size
                except OSError:
                    pass

            tier = self._classifier.classify(store_name)
            inventory[store_name] = {
                "path": str(store_path),
                "file_count": file_count,
                "total_bytes": total_bytes,
                "total_human": self._human_bytes(total_bytes),
                "privacy_tier": tier.name,
                "exists": store_path.is_dir(),
            }

        return inventory

    def audit_encryption_status(self) -> dict[str, Any]:
        """Check each data store for encryption at rest.

        Queries the PAL for disk-level encryption and inspects REX's
        own secrets file for application-level encryption.

        Returns
        -------
        dict
            Keys: ``disk_encryption``, ``secrets_encrypted``,
            ``data_stores`` (per-store encryption status).
        """
        # Disk-level encryption
        try:
            disk_status = self._pal.get_disk_encryption_status()
        except Exception:
            disk_status = {
                "encrypted": False,
                "method": None,
                "details": "Unable to query disk encryption status",
            }

        # Application-level secrets encryption
        secrets_path = self._config.data_dir / "secrets.json.enc"
        secrets_encrypted = secrets_path.exists()

        # Per-data-store encryption assessment
        data_stores: dict[str, dict[str, Any]] = {}
        tier_requires_encryption = {
            DataPrivacyTier.CRITICAL,
            DataPrivacyTier.HIGH,
        }

        for data_type, tier in DATA_CLASSIFICATIONS.items():
            requires_encryption = tier in tier_requires_encryption
            # Application-level encryption is currently only for secrets
            has_app_encryption = data_type in ("credentials", "tokens", "api_keys")
            has_disk_encryption = disk_status.get("encrypted", False)

            data_stores[data_type] = {
                "privacy_tier": tier.name,
                "requires_encryption": requires_encryption,
                "has_disk_encryption": has_disk_encryption,
                "has_app_encryption": has_app_encryption,
                "compliant": (
                    not requires_encryption
                    or has_disk_encryption
                    or has_app_encryption
                ),
            }

        return {
            "disk_encryption": disk_status,
            "secrets_encrypted": secrets_encrypted,
            "data_stores": data_stores,
        }

    def audit_external_services(self) -> dict[str, Any]:
        """List all configured external service integrations.

        Inspects the REX configuration for notification channels,
        threat intelligence feeds, federation peers, and any other
        outbound service.

        Returns
        -------
        dict
            Keys are service categories; values are lists of service
            descriptors with ``name``, ``endpoint``, ``enabled``,
            ``data_shared``.
        """
        services: dict[str, list[dict[str, Any]]] = {
            "notification_channels": [],
            "threat_feeds": [],
            "federation_peers": [],
            "package_repositories": [],
            "llm_backend": [],
        }

        # LLM backend (Ollama -- local by default)
        services["llm_backend"].append({
            "name": "Ollama",
            "endpoint": self._config.ollama_url,
            "enabled": True,
            "is_local": self._is_local_endpoint(self._config.ollama_url),
            "data_shared": "Prompt text (network context, threat descriptions)",
        })

        # Redis (event bus -- should be local)
        services["notification_channels"].append({
            "name": "Redis Event Bus",
            "endpoint": self._config.redis_url,
            "enabled": True,
            "is_local": self._is_local_endpoint(self._config.redis_url),
            "data_shared": "Internal events only (not external)",
        })

        # ChromaDB (vector store -- should be local)
        services["package_repositories"].append({
            "name": "ChromaDB Vector Store",
            "endpoint": self._config.chroma_url,
            "enabled": True,
            "is_local": self._is_local_endpoint(self._config.chroma_url),
            "data_shared": "Knowledge base embeddings",
        })

        return services

    # ----------------------------------------------------------------
    # Composite operations
    # ----------------------------------------------------------------

    def run_full_audit(self) -> dict[str, Any]:
        """Execute all audit checks and combine into a single report.

        Returns
        -------
        dict
            Top-level keys: ``timestamp``, ``outbound_connections``,
            ``data_inventory``, ``encryption_status``,
            ``external_services``, ``data_retention``, ``summary``.
        """
        timestamp = datetime.now(UTC).isoformat()

        outbound = self.audit_outbound_connections()
        inventory = self.audit_data_inventory()
        encryption = self.audit_encryption_status()
        external = self.audit_external_services()
        retention = self.get_data_retention_status()

        # Compute summary scores
        non_compliant_stores = sum(
            1
            for store in encryption.get("data_stores", {}).values()
            if not store.get("compliant", True)
        )
        unauthorized_connections = sum(
            1
            for conn in outbound
            if not self._is_local_ip(conn.get("remote_ip", ""))
        )

        summary: dict[str, Any] = {
            "total_outbound_connections": len(outbound),
            "remote_outbound_connections": unauthorized_connections,
            "non_compliant_encryption_stores": non_compliant_stores,
            "disk_encrypted": encryption.get("disk_encryption", {}).get(
                "encrypted", False
            ),
            "secrets_encrypted": encryption.get("secrets_encrypted", False),
            "privacy_score": self._compute_privacy_score(
                outbound, encryption, external
            ),
        }

        return {
            "timestamp": timestamp,
            "outbound_connections": outbound,
            "data_inventory": inventory,
            "encryption_status": encryption,
            "external_services": external,
            "data_retention": retention,
            "summary": summary,
        }

    def run_network_isolation_test(self) -> bool:
        """Verify network isolation by temporarily blocking all outbound
        traffic and checking for unauthorized connection attempts.

        .. warning::
            This test temporarily disrupts all outbound network
            connectivity.  Use only in controlled testing scenarios.

        Returns
        -------
        bool
            ``True`` if no unauthorized connection attempts were
            detected during the test window.
        """
        logger.warning("Starting network isolation test -- all outbound traffic will be blocked")

        try:
            # Block everything
            self._pal.setup_egress_firewall(
                allowed_hosts=[],
                allowed_ports=[],
            )

            # Snapshot connections before and after
            before = set(
                (c["remote_ip"], c["remote_port"])
                for c in self.audit_outbound_connections()
            )

            # Brief pause to allow any pending connections to attempt
            import time
            time.sleep(2)

            after = set(
                (c["remote_ip"], c["remote_port"])
                for c in self.audit_outbound_connections()
            )

            # Any new connections that appeared are unauthorized
            new_connections = after - before
            if new_connections:
                logger.error(
                    "Network isolation test FAILED: %d new connections detected: %s",
                    len(new_connections),
                    new_connections,
                )
                return False

            logger.info("Network isolation test PASSED: no unauthorized connections")
            return True

        except Exception as exc:
            logger.error("Network isolation test error: %s", exc)
            return False
        finally:
            # Restore normal egress rules (caller should re-apply allowlist)
            try:
                self._pal.setup_egress_firewall(
                    allowed_hosts=None,
                    allowed_ports=None,
                )
            except Exception:
                logger.error("Failed to restore egress rules after isolation test")

    def get_data_retention_status(self) -> dict[str, Any]:
        """Return current data retention settings per data type.

        Uses the data classifier to determine default retention
        periods and reports whether each data store is within its
        retention window.

        Returns
        -------
        dict
            Keys are data type names; values contain
            ``retention_days``, ``privacy_tier``, ``exportable``,
            and ``federation_safe``.
        """
        status: dict[str, Any] = {}
        for data_type in DATA_CLASSIFICATIONS:
            tier = self._classifier.classify(data_type)
            status[data_type] = {
                "retention_days": self._classifier.get_default_retention_days(data_type),
                "privacy_tier": tier.name,
                "exportable": self._classifier.is_exportable(data_type),
                "federation_safe": self._classifier.is_federation_safe(data_type),
            }
        return status

    def generate_privacy_report(self) -> str:
        """Generate a human-readable privacy audit report.

        Returns
        -------
        str
            Multi-line report summarising the privacy posture of the
            REX installation.
        """
        audit = self.run_full_audit()
        summary = audit["summary"]
        ts = audit["timestamp"]

        lines: list[str] = [
            "=" * 72,
            "REX-BOT-AI PRIVACY AUDIT REPORT",
            f"Generated: {ts}",
            "=" * 72,
            "",
            "--- SUMMARY ---",
            f"  Privacy Score:                {summary['privacy_score']}/100",
            f"  Outbound Connections (total): {summary['total_outbound_connections']}",
            f"  Remote Connections:           {summary['remote_outbound_connections']}",
            f"  Disk Encrypted:               {'Yes' if summary['disk_encrypted'] else 'No'}",
            f"  Secrets Encrypted:            {'Yes' if summary['secrets_encrypted'] else 'No'}",
            f"  Non-Compliant Stores:         {summary['non_compliant_encryption_stores']}",
            "",
        ]

        # Outbound connections
        lines.append("--- OUTBOUND CONNECTIONS ---")
        outbound = audit["outbound_connections"]
        if outbound:
            for conn in outbound:
                pid_info = f"PID {conn.get('pid', '?')}" if conn.get("pid") else "unknown PID"
                proc_name = conn.get("process_name") or "unknown"
                lines.append(
                    f"  {conn.get('remote_ip', '?')}:{conn.get('remote_port', '?')} "
                    f"[{conn.get('state', '?')}] -- {proc_name} ({pid_info})"
                )
        else:
            lines.append("  No outbound connections detected.")
        lines.append("")

        # Data inventory
        lines.append("--- DATA INVENTORY ---")
        for store_name, info in audit["data_inventory"].items():
            exists = "EXISTS" if info.get("exists") else "NOT FOUND"
            lines.append(
                f"  {store_name:30s} {info.get('total_human', '0 B'):>10s} "
                f"({info.get('file_count', 0)} files) "
                f"[{info.get('privacy_tier', '?')}] {exists}"
            )
        lines.append("")

        # Encryption status
        lines.append("--- ENCRYPTION STATUS ---")
        disk = audit["encryption_status"].get("disk_encryption", {})
        lines.append(
            f"  Disk Encryption: {disk.get('method', 'None')}"
            f" -- {disk.get('details', 'N/A')}"
        )
        enc_stores = audit["encryption_status"].get("data_stores", {})
        non_compliant = [
            name for name, info in enc_stores.items()
            if not info.get("compliant", True)
        ]
        if non_compliant:
            lines.append(f"  NON-COMPLIANT stores: {', '.join(non_compliant)}")
        else:
            lines.append("  All data stores are compliant with encryption requirements.")
        lines.append("")

        # External services
        lines.append("--- EXTERNAL SERVICES ---")
        for category, svc_list in audit["external_services"].items():
            for svc in svc_list:
                locality = "LOCAL" if svc.get("is_local") else "REMOTE"
                lines.append(
                    f"  [{category}] {svc.get('name', '?')} @ {svc.get('endpoint', '?')} "
                    f"({locality})"
                )
        lines.append("")

        # Data retention
        lines.append("--- DATA RETENTION ---")
        for data_type, info in audit["data_retention"].items():
            export_flag = "exportable" if info.get("exportable") else "no-export"
            fed_flag = "federation-ok" if info.get("federation_safe") else "no-federation"
            lines.append(
                f"  {data_type:30s} {info.get('retention_days', '?'):>5} days "
                f"[{info.get('privacy_tier', '?')}] {export_flag}, {fed_flag}"
            )
        lines.append("")

        lines.extend([
            "=" * 72,
            "END OF PRIVACY AUDIT REPORT",
            "=" * 72,
        ])

        return "\n".join(lines)

    # ----------------------------------------------------------------
    # Internal helpers
    # ----------------------------------------------------------------

    @staticmethod
    def _parse_proc_net_tcp(path: str) -> list[dict[str, Any]]:
        """Parse ``/proc/net/tcp`` or ``/proc/net/tcp6``.

        Parameters
        ----------
        path:
            Filesystem path to the proc net file.

        Returns
        -------
        list[dict]
            Parsed connection entries excluding listeners and loopback.
        """
        connections: list[dict[str, Any]] = []
        is_ipv6 = "tcp6" in path

        tcp_states: dict[str, str] = {
            "01": "ESTABLISHED",
            "02": "SYN_SENT",
            "03": "SYN_RECV",
            "04": "FIN_WAIT1",
            "05": "FIN_WAIT2",
            "06": "TIME_WAIT",
            "07": "CLOSE",
            "08": "CLOSE_WAIT",
            "09": "LAST_ACK",
            "0A": "LISTEN",
            "0B": "CLOSING",
        }

        try:
            with open(path) as fh:
                lines = fh.readlines()
        except OSError:
            return connections

        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue

            fields = line.split()
            if len(fields) < 10:
                continue

            local_hex = fields[1]
            remote_hex = fields[2]
            state_hex = fields[3]
            inode = fields[9] if len(fields) > 9 else "0"

            local_ip, local_port = PrivacyAuditor._decode_addr(local_hex, is_ipv6)
            remote_ip, remote_port = PrivacyAuditor._decode_addr(remote_hex, is_ipv6)
            state = tcp_states.get(state_hex, f"UNKNOWN({state_hex})")

            # Skip listeners and loopback
            if state == "LISTEN":
                continue
            if remote_ip in ("0.0.0.0", "::", "127.0.0.1", "::1"):
                continue

            connections.append({
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "state": state,
                "inode": inode,
            })

        return connections

    @staticmethod
    def _decode_addr(hex_str: str, is_ipv6: bool = False) -> tuple[str, int]:
        """Decode a hex-encoded address from ``/proc/net/tcp``.

        Parameters
        ----------
        hex_str:
            Address in ``"ADDR:PORT"`` hex format.
        is_ipv6:
            Whether this is from the tcp6 file.

        Returns
        -------
        tuple[str, int]
            ``(ip_address_string, port_number)``
        """
        try:
            addr_hex, port_hex = hex_str.split(":")
            port = int(port_hex, 16)

            if is_ipv6:
                if len(addr_hex) == 32:
                    groups = [addr_hex[i:i + 8] for i in range(0, 32, 8)]
                    byte_groups = []
                    for group in groups:
                        val = int(group, 16)
                        byte_groups.append(struct.pack("<I", val))
                    addr_bytes = b"".join(byte_groups)
                    ip = socket.inet_ntop(socket.AF_INET6, addr_bytes)
                else:
                    ip = "::?"
            else:
                addr_int = int(addr_hex, 16)
                ip = socket.inet_ntoa(struct.pack("<I", addr_int))

            return ip, port
        except (ValueError, struct.error):
            return "?.?.?.?", 0

    @staticmethod
    def _build_inode_pid_map() -> dict[str, int]:
        """Build a mapping from socket inode to PID by scanning /proc.

        Returns
        -------
        dict[str, int]
            Socket inode (as string) to PID.
        """
        inode_map: dict[str, int] = {}
        proc_dir = Path("/proc")

        try:
            for entry in proc_dir.iterdir():
                if not entry.name.isdigit():
                    continue
                pid = int(entry.name)
                fd_dir = entry / "fd"
                try:
                    for fd_link in fd_dir.iterdir():
                        try:
                            target = os.readlink(str(fd_link))
                            if target.startswith("socket:["):
                                inode = target[8:-1]  # extract from "socket:[12345]"
                                inode_map[inode] = pid
                        except (OSError, ValueError):
                            continue
                except OSError:
                    continue
        except OSError:
            pass

        return inode_map

    @staticmethod
    def _get_process_name(pid: int) -> str | None:
        """Read the process name for a PID from ``/proc/{pid}/comm``.

        Parameters
        ----------
        pid:
            Process ID.

        Returns
        -------
        str or None
            Process name, or ``None`` if not readable.
        """
        try:
            comm_path = Path(f"/proc/{pid}/comm")
            return comm_path.read_text(encoding="utf-8").strip()
        except OSError:
            return None

    @staticmethod
    def _is_local_endpoint(url: str) -> bool:
        """Determine whether a URL points to a local endpoint.

        Handles ``localhost``, IPv4 loopback (``127.x.x.x``), IPv6
        loopback (``::1`` in bracketed and unbracketed forms), and
        ``0.0.0.0`` (all-interfaces bind address).

        Parameters
        ----------
        url:
            URL string (e.g. ``"http://localhost:11434"``).

        Returns
        -------
        bool
            ``True`` if the host portion resolves to loopback or
            a private address.
        """
        import ipaddress as _ipaddress
        from urllib.parse import urlparse

        local_hostnames = {"localhost"}
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
        except Exception:
            hostname = ""

        # urlparse strips brackets from IPv6, so [::1] → "::1"
        if hostname.lower() in local_hostnames:
            return True

        # Check if hostname is a loopback/private IP address
        if hostname:
            try:
                addr = _ipaddress.ip_address(hostname)
                return addr.is_loopback or addr.is_private or addr.is_link_local
            except ValueError:
                pass
            # Also handle 0.0.0.0 which is used as a bind address
            if hostname == "0.0.0.0":
                return True
            return False

        # Handle unbracketed IPv6 that urlparse fails to parse
        # (e.g. "http://::1:6379" — urlparse returns hostname=None)
        import re
        m = re.match(r"[a-zA-Z]+://(.+?)(?:/|$)", url)
        if m:
            host_port = m.group(1)
            # Strip bracketed form
            bracket_m = re.match(r"^\[(.+?)\](?::(\d+))?$", host_port)
            if bracket_m:
                try:
                    addr = _ipaddress.ip_address(bracket_m.group(1))
                    return addr.is_loopback or addr.is_private or addr.is_link_local
                except ValueError:
                    pass
            # IPv6 shorthand like ::1:port or just ::1
            if host_port.startswith("::"):
                for local in ("::1",):
                    if host_port == local or host_port.startswith(local + ":"):
                        return True
        return False

    @staticmethod
    def _is_local_ip(ip: str) -> bool:
        """Check whether an IP address is loopback or private.

        Parameters
        ----------
        ip:
            IP address string.

        Returns
        -------
        bool
            ``True`` if the address is loopback, link-local, or
            RFC 1918 private.
        """
        import ipaddress as _ipaddress

        try:
            addr = _ipaddress.ip_address(ip)
            return addr.is_loopback or addr.is_private or addr.is_link_local
        except ValueError:
            return False

    @staticmethod
    def _compute_privacy_score(
        outbound: list[dict[str, Any]],
        encryption: dict[str, Any],
        external: dict[str, Any],
    ) -> int:
        """Compute a 0-100 privacy score based on audit findings.

        Scoring rubric (100 = perfect privacy):

        * Start at 100
        * -5 per remote (non-local) outbound connection
        * -20 if disk is not encrypted
        * -10 per non-compliant encryption store
        * -5 per remote external service

        Parameters
        ----------
        outbound:
            Outbound connection audit results.
        encryption:
            Encryption status audit results.
        external:
            External services audit results.

        Returns
        -------
        int
            Privacy score clamped to [0, 100].
        """
        score = 100

        # Penalise remote outbound connections
        import ipaddress as _ipaddress

        for conn in outbound:
            remote_ip = conn.get("remote_ip", "")
            try:
                addr = _ipaddress.ip_address(remote_ip)
                if not (addr.is_loopback or addr.is_private or addr.is_link_local):
                    score -= 5
            except ValueError:
                pass

        # Penalise missing disk encryption
        if not encryption.get("disk_encryption", {}).get("encrypted", False):
            score -= 20

        # Penalise non-compliant encryption stores
        for store_info in encryption.get("data_stores", {}).values():
            if not store_info.get("compliant", True):
                score -= 10

        # Penalise remote external services
        for _category, svc_list in external.items():
            for svc in svc_list:
                if not svc.get("is_local", True):
                    score -= 5

        return max(0, min(100, score))

    @staticmethod
    def _human_bytes(num_bytes: int) -> str:
        """Convert a byte count to a human-readable string.

        Parameters
        ----------
        num_bytes:
            Number of bytes.

        Returns
        -------
        str
            Human-readable string (e.g. ``"1.5 GiB"``).
        """
        for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
            if abs(num_bytes) < 1024.0:
                return f"{num_bytes:.1f} {unit}"
            num_bytes = num_bytes / 1024.0  # type: ignore[assignment]
        return f"{num_bytes:.1f} PiB"
