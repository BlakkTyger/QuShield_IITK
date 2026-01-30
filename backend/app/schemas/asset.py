"""Asset Schemas"""

from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel


class AssetCreate(BaseModel):
    """Schema for creating an asset manually."""
    fqdn: str
    port: int = 443
    owner: Optional[str] = None
    asset_type: Optional[str] = None


class CertificateResponse(BaseModel):
    """Schema for certificate response."""
    id: str
    sha256_fingerprint: Optional[str]
    subject_cn: Optional[str]
    issuer_cn: Optional[str]
    certificate_authority: Optional[str]
    valid_from: Optional[datetime]
    valid_until: Optional[datetime]
    key_algorithm: Optional[str]
    key_size: Optional[int]
    is_expired: bool = False
    days_until_expiry: Optional[int]
    
    class Config:
        from_attributes = True


class CryptoSecurityResponse(BaseModel):
    """Schema for crypto security response."""
    id: str
    tls_version: Optional[str]
    cipher_suite: Optional[str]
    key_exchange_algorithm: Optional[str]
    key_length: Optional[int]
    is_pfs_enabled: bool = False
    
    class Config:
        from_attributes = True


class AssetResponse(BaseModel):
    """Schema for asset response."""
    id: str
    fqdn: str
    ipv4_address: Optional[str]
    ipv6_address: Optional[str]
    port: int
    asset_type: Optional[str]
    discovery_source: Optional[str]
    status: str
    risk_level: Optional[str]
    quantum_safety: Optional[str]
    hndl_score: Optional[float]
    cert_tier: Optional[str]
    owner: Optional[str]
    last_scan_time: Optional[datetime]
    detection_date: Optional[datetime]
    
    class Config:
        from_attributes = True


class AssetDetail(AssetResponse):
    """Schema for detailed asset response."""
    scan_success: bool = False
    scan_error: Optional[str]
    hndl_label: Optional[str]
    recommended_action: Optional[str]
    certificates: List[CertificateResponse] = []
    crypto_security: List[CryptoSecurityResponse] = []
    
    class Config:
        from_attributes = True


class AssetListResponse(BaseModel):
    """Schema for paginated asset list."""
    items: List[AssetResponse]
    total: int
    page: int
    size: int
