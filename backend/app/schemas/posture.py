"""Posture Schemas"""

from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel


class ClassificationGrade(BaseModel):
    """Classification grade percentages."""
    grade: str
    count: int
    percentage: float


class PostureSummary(BaseModel):
    """Schema for PQC posture summary."""
    pqc_adoption_progress: float = 0.0
    compliance_status: str = "NON_COMPLIANT"
    migration_priority: str = "CRITICAL"
    
    classifications: List[ClassificationGrade] = []
    
    elite_count: int = 0
    standard_count: int = 0
    legacy_count: int = 0
    critical_count: int = 0


class Recommendation(BaseModel):
    """Schema for remediation recommendation."""
    id: str
    priority: str  # critical, high, medium, low
    category: str  # key_exchange, signature, protocol
    title: str
    description: str
    affected_assets: int
    action: str


class RecommendationList(BaseModel):
    """Schema for recommendation list."""
    items: List[Recommendation]
    total: int


class PQCCertificateResponse(BaseModel):
    """Schema for PQC certificate response."""
    id: str
    asset_id: str
    asset_fqdn: str
    cert_tier: str
    certification_level: str
    score: Optional[float]
    issued_at: datetime
    valid_until: Optional[datetime]
    signature_algorithm: str = "ML-DSA-87"
    
    class Config:
        from_attributes = True


class PQCCertificateList(BaseModel):
    """Schema for PQC certificate list."""
    items: List[PQCCertificateResponse]
    total: int
