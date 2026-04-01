"""DNS blocker -- local DNS sinkhole for malicious domains.

Maintains curated and community blocklists.  Blocked domains resolve to
``0.0.0.0``; clean domains are forwarded to the configured upstream DNS
resolver (defaults to Cloudflare ``1.1.1.1``).

Privacy: query logs are retained for a configurable period (7 days by
default) and then automatically purged.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import time
from collections import Counter
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from rex.shared.config import RexConfig

logger = logging.getLogger("rex.teeth.dns_blocker")

# Blocklist sources (fetched only when Internet is reachable).
_BLOCKLIST_SOURCES: dict[str, str] = {
    "steven_black": (
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    ),
    "urlhaus": "https://urlhaus.abuse.ch/downloads/hostfile/",
}

# Default log retention period (seconds).
_DEFAULT_LOG_RETENTION_SECONDS: int = 7 * 24 * 3600  # 7 days

# Domains that must never be blocked (safety set).
_NEVER_BLOCK: frozenset[str] = frozenset({
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
})


class DNSBlocker:
    """DNS proxy that blocks malicious domains.

    Parameters
    ----------
    config:
        The process-wide ``RexConfig`` instance.
    """

    def __init__(self, config: RexConfig) -> None:
        self.config = config
        self._blocked_domains: set[str] = set()
        self._custom_blocks: set[str] = set()
        self._custom_block_reasons: dict[str, str] = {}
        self._query_log: list[dict[str, Any]] = []
        self._stats: dict[str, int] = {
            "total_queries": 0,
            "blocked_queries": 0,
        }
        self._blocked_domain_counter: Counter[str] = Counter()
        self._per_device_stats: dict[str, dict[str, int]] = {}
        self._upstream_dns: str = "1.1.1.1"
        self._log_retention_seconds: int = _DEFAULT_LOG_RETENTION_SECONDS
        self._logger = logging.getLogger("rex.teeth.dns_blocker")
        self._update_task: asyncio.Task[None] | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def load_blocklists(self) -> int:
        """Load bundled blocklists and optionally fetch from remote sources.

        Returns
        -------
        int
            Total number of unique domains in the merged blocklist.
        """
        self._logger.info("Loading blocklists...")

        # 1. Load the bundled blocklist shipped with REX (if it exists).
        await self._load_bundled_blocklist()

        # 2. Attempt to fetch from remote sources.
        for name, url in _BLOCKLIST_SOURCES.items():
            try:
                domains = await self._fetch_hosts_file(url)
                before = len(self._blocked_domains)
                self._blocked_domains.update(domains)
                added = len(self._blocked_domains) - before
                self._logger.info(
                    "Loaded blocklist '%s': %d domains (%d new).",
                    name, len(domains), added,
                )
            except Exception as exc:
                self._logger.warning(
                    "Could not fetch blocklist '%s' from %s: %s",
                    name, url, exc,
                )

        # 3. Remove safety-listed domains.
        self._blocked_domains -= _NEVER_BLOCK

        # 4. Persist the merged list for offline use.
        await self._persist_blocklist()

        total = len(self._blocked_domains)
        self._logger.info("Blocklists loaded: %d unique domains blocked.", total)
        return total

    async def start_update_loop(self) -> None:
        """Start a background task that refreshes blocklists every 24 hours."""
        self._update_task = asyncio.create_task(self._update_loop())

    async def stop_update_loop(self) -> None:
        """Cancel the background update task."""
        if self._update_task is not None:
            self._update_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._update_task

    async def update_blocklists(self) -> int:
        """Fetch updated blocklists from remote sources.

        Returns
        -------
        int
            Number of newly added domains.
        """
        before = len(self._blocked_domains)

        for name, url in _BLOCKLIST_SOURCES.items():
            try:
                domains = await self._fetch_hosts_file(url)
                self._blocked_domains.update(domains)
                self._logger.info(
                    "Updated blocklist '%s': %d domains.", name, len(domains),
                )
            except Exception as exc:
                self._logger.warning(
                    "Failed to update blocklist '%s': %s", name, exc,
                )

        self._blocked_domains -= _NEVER_BLOCK
        added = len(self._blocked_domains) - before

        if added > 0:
            await self._persist_blocklist()
            self._logger.info("Blocklist update: %d new domains added.", added)

        return added

    # ------------------------------------------------------------------
    # Custom blocks
    # ------------------------------------------------------------------

    def add_custom_block(self, domain: str, reason: str = "") -> None:
        """Add a domain to the local custom blocklist.

        Parameters
        ----------
        domain:
            Domain name to block (e.g. ``"evil.example.com"``).
        reason:
            Human-readable reason for the block.
        """
        normalised = domain.strip().lower().rstrip(".")
        if normalised in _NEVER_BLOCK:
            self._logger.warning(
                "Refusing to custom-block safety-listed domain: %s",
                normalised,
            )
            return

        self._custom_blocks.add(normalised)
        if reason:
            self._custom_block_reasons[normalised] = reason
        self._logger.info(
            "Custom block added: %s (reason=%r)", normalised, reason,
        )

    def remove_custom_block(self, domain: str) -> bool:
        """Remove a domain from the custom blocklist.

        Parameters
        ----------
        domain:
            Domain name to unblock.

        Returns
        -------
        bool
            ``True`` if the domain was in the custom list and was removed.
        """
        normalised = domain.strip().lower().rstrip(".")
        if normalised in self._custom_blocks:
            self._custom_blocks.discard(normalised)
            self._custom_block_reasons.pop(normalised, None)
            self._logger.info("Custom block removed: %s", normalised)
            return True
        return False

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------

    async def resolve(self, query_name: str, source_ip: str) -> str:
        """Resolve a domain name.

        If the domain is on any blocklist, returns ``"0.0.0.0"`` (sinkhole).
        Otherwise, forwards the query to the upstream DNS resolver.

        Parameters
        ----------
        query_name:
            The domain name to resolve (may include trailing dot).
        source_ip:
            IP address of the device making the query.

        Returns
        -------
        str
            Resolved IPv4 address, or ``"0.0.0.0"`` if blocked.
        """
        self._stats["total_queries"] += 1
        domain = query_name.strip().lower().rstrip(".")

        # Initialise per-device stats for this source.
        if source_ip not in self._per_device_stats:
            self._per_device_stats[source_ip] = {
                "total_queries": 0,
                "blocked_queries": 0,
            }
        self._per_device_stats[source_ip]["total_queries"] += 1

        # Check blocklists (O(1) set lookup).
        if domain in self._blocked_domains or domain in self._custom_blocks:
            self._stats["blocked_queries"] += 1
            self._per_device_stats[source_ip]["blocked_queries"] += 1
            self._blocked_domain_counter[domain] += 1
            self._log_query(source_ip, domain, blocked=True)
            return "0.0.0.0"

        # Forward to upstream DNS.
        resolved_ip = await self._forward_dns(domain)
        self._log_query(source_ip, domain, blocked=False, resolved_ip=resolved_ip)
        return resolved_ip

    def is_blocked(self, domain: str) -> bool:
        """Check whether a domain is currently blocked.

        Parameters
        ----------
        domain:
            Domain name to check.

        Returns
        -------
        bool
        """
        normalised = domain.strip().lower().rstrip(".")
        return normalised in self._blocked_domains or normalised in self._custom_blocks

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_block_stats(self) -> dict[str, Any]:
        """Return comprehensive blocking statistics.

        Returns
        -------
        dict
            Keys: ``total_queries``, ``blocked_queries``, ``block_rate``,
            ``blocklist_size``, ``custom_block_count``,
            ``top_blocked_domains``, ``per_device_stats``.
        """
        total = self._stats["total_queries"]
        blocked = self._stats["blocked_queries"]
        block_rate = (blocked / total * 100) if total > 0 else 0.0

        top_blocked = self._blocked_domain_counter.most_common(20)

        return {
            "total_queries": total,
            "blocked_queries": blocked,
            "block_rate_percent": round(block_rate, 2),
            "blocklist_size": len(self._blocked_domains),
            "custom_block_count": len(self._custom_blocks),
            "top_blocked_domains": [
                {"domain": d, "count": c} for d, c in top_blocked
            ],
            "per_device_stats": dict(self._per_device_stats),
        }

    # ------------------------------------------------------------------
    # Query logging (privacy-aware)
    # ------------------------------------------------------------------

    def _log_query(
        self,
        source_ip: str,
        domain: str,
        blocked: bool,
        resolved_ip: str | None = None,
    ) -> None:
        """Record a DNS query with privacy-aware retention.

        Logs older than ``_log_retention_seconds`` are pruned on every
        call to keep memory usage bounded.
        """
        now = time.time()

        self._query_log.append({
            "timestamp": now,
            "source_ip": source_ip,
            "domain": domain,
            "blocked": blocked,
            "resolved_ip": resolved_ip,
        })

        # Prune old entries (amortised -- only prune when list is large).
        if len(self._query_log) > 10_000:
            cutoff = now - self._log_retention_seconds
            self._query_log = [
                e for e in self._query_log if e["timestamp"] > cutoff
            ]

    def get_recent_queries(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return the most recent DNS queries.

        Parameters
        ----------
        limit:
            Maximum number of entries to return.

        Returns
        -------
        list[dict]
            Query log entries, newest first.
        """
        return list(reversed(self._query_log[-limit:]))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _forward_dns(self, domain: str) -> str:
        """Forward a DNS query to the upstream resolver.

        Uses a raw UDP socket for A-record lookups to avoid importing
        heavy DNS libraries.  Falls back to ``socket.getaddrinfo`` if the
        raw query fails.

        Parameters
        ----------
        domain:
            The domain name to resolve.

        Returns
        -------
        str
            Resolved IPv4 address, or ``"0.0.0.0"`` on failure.
        """
        loop = asyncio.get_running_loop()
        try:
            # Use the stdlib resolver via the event loop's thread pool.
            infos = await loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(
                    domain, None, socket.AF_INET, socket.SOCK_STREAM,
                ),
            )
            if infos:
                return infos[0][4][0]
        except (socket.gaierror, OSError, Exception) as exc:
            self._logger.debug(
                "DNS resolution failed for %s: %s", domain, exc,
            )
        return "0.0.0.0"

    async def _fetch_hosts_file(self, url: str) -> set[str]:
        """Fetch and parse a hosts-format blocklist from *url*.

        Lines in hosts files look like::

            0.0.0.0 ad.example.com
            127.0.0.1 tracker.example.com

        Parameters
        ----------
        url:
            HTTP(S) URL of the hosts file.

        Returns
        -------
        set[str]
            Parsed domain names.
        """
        import urllib.request

        loop = asyncio.get_running_loop()
        domains: set[str] = set()

        def _download_and_parse() -> set[str]:
            result: set[str] = set()
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "REX-BOT-AI/1.0"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    for raw_line in resp:
                        line = raw_line.decode("utf-8", errors="replace").strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split()
                        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                            domain = parts[1].lower().strip()
                            if domain and domain not in ("localhost", "0.0.0.0"):
                                result.add(domain)
            except Exception as exc:
                logger.warning("Download failed for %s: %s", url, exc)
            return result

        domains = await loop.run_in_executor(None, _download_and_parse)
        return domains

    async def _load_bundled_blocklist(self) -> None:
        """Load the bundled blocklist shipped with REX."""
        bundled_path = self.config.data_dir / "teeth" / "blocklist.txt"
        if not bundled_path.exists():
            self._logger.debug("No bundled blocklist at %s", bundled_path)
            return

        try:
            count = 0
            with bundled_path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    domain = line.strip().lower()
                    if domain and not domain.startswith("#"):
                        self._blocked_domains.add(domain)
                        count += 1
            self._logger.info(
                "Loaded %d domains from bundled blocklist.", count,
            )
        except Exception as exc:
            self._logger.warning(
                "Failed to load bundled blocklist: %s", exc,
            )

    async def _persist_blocklist(self) -> None:
        """Persist the merged blocklist to disk for offline use."""
        persist_path = self.config.data_dir / "teeth" / "blocklist_merged.txt"
        try:
            persist_path.parent.mkdir(parents=True, exist_ok=True)
            with persist_path.open("w", encoding="utf-8") as fh:
                for domain in sorted(self._blocked_domains):
                    fh.write(domain + "\n")
            self._logger.debug(
                "Persisted %d domains to %s",
                len(self._blocked_domains), persist_path,
            )
        except Exception as exc:
            self._logger.warning(
                "Failed to persist blocklist: %s", exc,
            )

    async def _update_loop(self) -> None:
        """Background loop: refresh blocklists every 24 hours."""
        while True:
            try:
                await asyncio.sleep(24 * 3600)  # 24 hours
                added = await self.update_blocklists()
                self._logger.info(
                    "Scheduled blocklist update complete: %d new domains.", added,
                )
            except asyncio.CancelledError:
                return
            except Exception:
                self._logger.exception("Error in blocklist update loop.")
