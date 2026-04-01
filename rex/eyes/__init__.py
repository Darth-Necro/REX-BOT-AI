"""REX Eyes -- network discovery, fingerprinting, and traffic monitoring.

Layer 1 -- the sensory system of the REX network guardian.

This package provides:
- :class:`NetworkScanner` -- ARP + nmap device discovery.
- :class:`DeviceFingerprinter` -- OUI vendor lookup and OS detection.
- :class:`DNSMonitor` -- passive DNS threat detection.
- :class:`TrafficMonitor` -- traffic anomaly detection.
- :class:`PortScanner` -- TCP port scanning (nmap + socket fallback).
- :class:`DeviceStore` -- in-memory device inventory.
- :class:`EyesService` -- orchestrator that ties all components together.
"""

from rex.eyes.device_store import DeviceStore
from rex.eyes.dns_monitor import DNSMonitor
from rex.eyes.fingerprinter import DeviceFingerprinter
from rex.eyes.port_scanner import PortScanner
from rex.eyes.scanner import NetworkScanner
from rex.eyes.service import EyesService
from rex.eyes.traffic import TrafficMonitor

__all__ = [
    "DNSMonitor",
    "DeviceFingerprinter",
    "DeviceStore",
    "EyesService",
    "NetworkScanner",
    "PortScanner",
    "TrafficMonitor",
]
