"""
QuShield Services

External service integrations for extended discovery capabilities.
"""

from qushield.services.extended import (
    ExtendedDiscoveryService,
    NameserverRecord,
    MXRecord,
    TXTRecord,
    WHOISInfo,
    PortScanResult,
    ASNInfo,
    GeoIPInfo,
    ServiceInfo,
    FormInfo,
    CloudInfo,
    IoTInfo,
)
from qushield.services.remediation import (
    RemediationAdvisor,
    ConfigPatch,
    RemediationPlan,
    MigrationStep,
    ServerType,
    MigrationPhase,
)

__all__ = [
    # Extended Discovery
    "ExtendedDiscoveryService",
    "NameserverRecord",
    "MXRecord",
    "TXTRecord",
    "WHOISInfo",
    "PortScanResult",
    "ASNInfo",
    "GeoIPInfo",
    "ServiceInfo",
    "FormInfo",
    "CloudInfo",
    "IoTInfo",
    # Remediation
    "RemediationAdvisor",
    "ConfigPatch",
    "RemediationPlan",
    "MigrationStep",
    "ServerType",
    "MigrationPhase",
]
