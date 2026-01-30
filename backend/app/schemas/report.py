"""Report Schemas"""

from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, EmailStr


class ReportGenerate(BaseModel):
    """Schema for on-demand report generation."""
    scan_id: str
    report_type: str = "full"  # full, summary, cbom, posture
    file_format: str = "pdf"  # pdf, json
    include_charts: bool = True
    password_protected: bool = False


class ReportSchedule(BaseModel):
    """Schema for scheduled report."""
    report_type: str
    frequency: str  # daily, weekly, monthly
    cron_expression: Optional[str] = None
    selected_scans: Optional[List[str]] = None
    included_sections: List[str] = ["discovery", "inventory", "cbom", "pqc", "rating"]
    delivery_email: Optional[EmailStr] = None


class ReportResponse(BaseModel):
    """Schema for report response."""
    id: str
    report_type: str
    file_path: Optional[str]
    file_format: str
    generated_at: datetime
    expires_at: Optional[datetime]
    download_url: Optional[str]
    
    class Config:
        from_attributes = True


class ReportListResponse(BaseModel):
    """Schema for report list."""
    items: List[ReportResponse]
    total: int


class ScheduledReportResponse(BaseModel):
    """Schema for scheduled report response."""
    id: str
    report_type: str
    frequency: str
    is_active: bool
    last_run_at: Optional[datetime]
    next_run_at: Optional[datetime]
    created_at: datetime
    
    class Config:
        from_attributes = True
