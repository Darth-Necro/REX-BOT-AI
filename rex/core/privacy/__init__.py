"""rex.core.privacy -- Privacy infrastructure for REX-BOT-AI.

This package enforces REX's privacy-first architecture:

* **Egress firewall** -- default-deny outbound network policy.
* **Secrets management** -- hardware-bound encryption for credentials.
* **Privacy auditing** -- continuous verification of data handling.
* **Data classification** -- tiered sensitivity labels and retention.

All data handling follows the principle that user network data never
leaves the host unless the operator explicitly opts in.

Usage::

    from rex.core.privacy import (
        EgressFirewall,
        SecretsManager,
        PrivacyAuditor,
        DataClassifier,
        DataPrivacyTier,
    )
"""

from __future__ import annotations

from rex.core.privacy.audit import PrivacyAuditor
from rex.core.privacy.data_classifier import (
    DATA_CLASSIFICATIONS,
    DataClassifier,
    DataPrivacyTier,
)
from rex.core.privacy.egress_firewall import EgressFirewall
from rex.core.privacy.encryption import SecretsManager

__all__ = [
    "DATA_CLASSIFICATIONS",
    "DataClassifier",
    "DataPrivacyTier",
    "EgressFirewall",
    "PrivacyAuditor",
    "SecretsManager",
]
