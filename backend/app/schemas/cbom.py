"""CBOM Schemas"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel


class CipherUsage(BaseModel):
    """Cipher usage statistics."""
    cipher: str
    count: int
    percentage: float


class KeyLengthDist(BaseModel):
    """Key length distribution."""
    key_length: int
    count: int
    percentage: float


class CADistribution(BaseModel):
    """Certificate authority distribution."""
    ca_name: str
    count: int
    percentage: float


class TLSVersionDist(BaseModel):
    """TLS version distribution."""
    version: str
    count: int
    percentage: float


class CBOMMetrics(BaseModel):
    """Schema for CBOM metrics response."""
    total_applications: int = 0
    active_certificates: int = 0
    weak_crypto_count: int = 0
    certificate_issues: int = 0
    
    cipher_usage: List[CipherUsage] = []
    key_length_distribution: List[KeyLengthDist] = []
    top_cas: List[CADistribution] = []
    tls_version_distribution: List[TLSVersionDist] = []


class CryptoComponent(BaseModel):
    """CBOM crypto component."""
    type: str
    name: str
    bom_ref: str
    crypto_type: Optional[str]
    algorithm_properties: Optional[Dict[str, Any]]


class CBOMExport(BaseModel):
    """Schema for CBOM export (CycloneDX format)."""
    bom_format: str = "CycloneDX"
    spec_version: str = "1.6"
    serial_number: str
    version: int = 1
    metadata: Dict[str, Any]
    components: List[CryptoComponent]
    x_cert_in_qbom: Optional[Dict[str, Any]] = None
