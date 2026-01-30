"""Dashboard Schemas"""

from typing import Dict, List, Optional
from pydantic import BaseModel


class AssetCounts(BaseModel):
    """Asset count metrics."""
    total_assets: int = 0
    public_web_apps: int = 0
    apis: int = 0
    servers: int = 0
    gateways: int = 0
    cdns: int = 0


class QuantumSafetyCounts(BaseModel):
    """Quantum safety metrics."""
    quantum_safe: int = 0
    hybrid: int = 0
    vulnerable: int = 0
    critical: int = 0


class CertificationCounts(BaseModel):
    """Certification tier counts."""
    platinum: int = 0
    gold: int = 0
    silver: int = 0
    bronze: int = 0


class CertExpiryCounts(BaseModel):
    """Certificate expiry buckets."""
    expired: int = 0
    expiring_30d: int = 0
    expiring_60d: int = 0
    expiring_90d: int = 0


class IPBreakdown(BaseModel):
    """IP version breakdown."""
    ipv4_count: int = 0
    ipv6_count: int = 0
    ipv4_percent: float = 0.0
    ipv6_percent: float = 0.0


class DashboardMetrics(BaseModel):
    """Schema for dashboard metrics response."""
    asset_counts: AssetCounts
    quantum_safety: QuantumSafetyCounts
    certifications: CertificationCounts
    cert_expiry: CertExpiryCounts
    ip_breakdown: IPBreakdown
    enterprise_score: Optional[int] = None
    rating_category: Optional[str] = None
    average_hndl_score: Optional[float] = None
    last_scan_id: Optional[str] = None
    last_scan_domain: Optional[str] = None


class RiskDistributionItem(BaseModel):
    """Single risk distribution item."""
    label: str
    count: int
    percentage: float


class HighRiskAsset(BaseModel):
    """High risk asset summary."""
    id: str
    fqdn: str
    risk_level: str
    hndl_score: Optional[float]
    quantum_safety: Optional[str]


class ExpiringCert(BaseModel):
    """Expiring certificate summary."""
    id: str
    asset_fqdn: str
    subject_cn: Optional[str]
    valid_until: str
    days_until_expiry: int


class MoscaAsset(BaseModel):
    """Asset evaluated against Mosca's Theorem."""
    id: str
    fqdn: str
    d_years: int
    t_years: int
    z_years: int
    is_violation: bool


class RiskDistribution(BaseModel):
    """Schema for risk distribution charts."""
    risk_levels: List[RiskDistributionItem]
    asset_types: List[RiskDistributionItem]
    quantum_safety: List[RiskDistributionItem]
    high_risk_assets: List[HighRiskAsset]
    expiring_certs: List[ExpiringCert]
    mosca_assets: List[MoscaAsset] = []
