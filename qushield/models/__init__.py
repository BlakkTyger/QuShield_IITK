"""
QuShield Data Models

Shared data models used across the QuShield pipeline.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Dict, List, Any, Optional


class AssetType(str, Enum):
    """Asset type classification."""
    WEB_APP = "Web Application"
    API = "API"
    SERVER = "Server"
    GATEWAY = "Gateway"
    LOAD_BALANCER = "Load Balancer"
    CDN = "CDN"
    MAIL_SERVER = "Mail Server"
    VPN = "VPN"
    DATABASE = "Database"
    IOT = "IoT Device"
    UNKNOWN = "Unknown"


class RiskLevel(str, Enum):
    """Risk level classification."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "Unknown"


@dataclass
class AssetInfo:
    """
    Information about a discovered asset.
    
    Attributes:
        fqdn: Fully qualified domain name
        port: Port number
        ipv4: IPv4 address
        ipv6: IPv6 address
        asset_type: Type of asset
        discovery_source: How the asset was discovered
        discovered_at: Discovery timestamp
    """
    fqdn: str
    port: int = 443
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    asset_type: AssetType = AssetType.UNKNOWN
    discovery_source: str = ""
    discovered_at: Optional[datetime] = None
    
    # Extended information
    asn: Optional[int] = None
    asn_name: Optional[str] = None
    country_code: Optional[str] = None
    is_cloud_hosted: bool = False
    cloud_provider: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["asset_type"] = self.asset_type.value
        if self.discovered_at:
            result["discovered_at"] = self.discovered_at.isoformat()
        return result


@dataclass
class ScanResult:
    """
    Complete scan result for an asset.
    
    Combines discovery, scanning, analysis, and certification results.
    """
    # Identity
    fqdn: str
    port: int = 443
    
    # Layer 1: Discovery
    asset_info: Optional[AssetInfo] = None
    
    # Layer 2: TLS Scan
    scan_success: bool = False
    tls_versions: List[str] = field(default_factory=list)
    cipher_suites: List[str] = field(default_factory=list)
    key_exchange_algorithms: List[str] = field(default_factory=list)
    certificate_algorithm: str = ""
    certificate_expiry: Optional[str] = None
    
    # Layer 3: Analysis
    quantum_safety: str = "UNKNOWN"
    hndl_score: Optional[float] = None
    hndl_label: str = ""
    recommended_action: str = ""
    
    # Layer 4: Certification
    certification_tier: str = "NOT_CERTIFIED"
    certification_issued: bool = False
    
    # Risk
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    vulnerabilities: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            "fqdn": self.fqdn,
            "port": self.port,
            "scan_success": self.scan_success,
            "tls_versions": self.tls_versions,
            "cipher_suites": self.cipher_suites,
            "key_exchange_algorithms": self.key_exchange_algorithms,
            "certificate_algorithm": self.certificate_algorithm,
            "certificate_expiry": self.certificate_expiry,
            "quantum_safety": self.quantum_safety,
            "hndl_score": self.hndl_score,
            "hndl_label": self.hndl_label,
            "recommended_action": self.recommended_action,
            "certification_tier": self.certification_tier,
            "certification_issued": self.certification_issued,
            "risk_level": self.risk_level.value,
            "vulnerabilities": self.vulnerabilities,
        }
        if self.asset_info:
            result["asset_info"] = self.asset_info.to_dict()
        return result


@dataclass
class WorkflowSummary:
    """Summary of a complete workflow run."""
    domain: str
    start_time: str
    end_time: str
    duration_ms: float
    
    # Counts
    assets_discovered: int = 0
    assets_scanned: int = 0
    scan_failures: int = 0
    
    # Analysis summary
    quantum_safe_count: int = 0
    hybrid_count: int = 0
    vulnerable_count: int = 0
    critical_count: int = 0
    
    # Certification summary
    platinum_count: int = 0
    gold_count: int = 0
    silver_count: int = 0
    bronze_count: int = 0
    
    # Average scores
    average_hndl_score: float = 0.0
    
    # Output
    output_file: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


__all__ = [
    "AssetType",
    "RiskLevel",
    "AssetInfo",
    "ScanResult",
    "WorkflowSummary",
]
