"""Shared data registry for dashboard access to service data.

Services register their data stores here during startup.
Dashboard routers query through this registry.
"""
from __future__ import annotations
import logging
from typing import Any

logger = logging.getLogger(__name__)

_device_store: Any = None
_threat_log: Any = None
_knowledge_base: Any = None

def set_device_store(store: Any) -> None:
    global _device_store
    _device_store = store

def set_threat_log(log: Any) -> None:
    global _threat_log
    _threat_log = log

def set_knowledge_base(kb: Any) -> None:
    global _knowledge_base
    _knowledge_base = kb

def get_device_store() -> Any:
    return _device_store

def get_threat_log() -> Any:
    return _threat_log

def get_knowledge_base() -> Any:
    return _knowledge_base
