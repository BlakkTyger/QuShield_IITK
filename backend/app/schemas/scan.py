"""Scan Schemas"""

from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field


class ScanTrigger(BaseModel):
    """Schema for triggering a new scan."""
    domain: str = Field(..., description="Target domain to scan")
    max_assets: int = Field(default=50, ge=1, le=500)
    skip_discovery: bool = False
    targets: Optional[List[str]] = None


class ScanCreate(BaseModel):
    """Schema for creating a scan record."""
    domain: str
    max_assets: int = 50


class ScanStatus(BaseModel):
    """Schema for scan status response."""
    id: str
    status: str
    progress: Optional[int] = None
    assets_discovered: int = 0
    assets_scanned: int = 0
    started_at: Optional[datetime]
    error_message: Optional[str] = None


class ScanSummaryResponse(BaseModel):
    """Schema for scan summary."""
    total_assets: int = 0
    public_web_apps: int = 0
    apis: int = 0
    servers: int = 0
    quantum_safe_count: int = 0
    hybrid_count: int = 0
    vulnerable_count: int = 0
    critical_count: int = 0
    enterprise_score: Optional[int] = None
    rating_category: Optional[str] = None
    average_hndl_score: Optional[float] = None
    
    class Config:
        from_attributes = True


class ScanResponse(BaseModel):
    """Schema for scan response."""
    id: str
    domain: str
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    duration_ms: Optional[int]
    assets_discovered: int = 0
    assets_scanned: int = 0
    scan_failures: int = 0
    output_file: Optional[str] = None
    created_at: datetime
    summary: Optional[ScanSummaryResponse] = None
    
    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    """Schema for paginated scan list."""
    items: List[ScanResponse]
    total: int
    page: int
    size: int
