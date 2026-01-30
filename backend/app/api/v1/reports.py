"""
Reports Routes

Report generation and scheduling endpoints.
"""

from typing import Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.api.deps import get_db, get_current_active_user
from app.models.user import User
from app.models.scan import Scan
from app.models.report import ScheduledReport, GeneratedReport
from app.schemas.report import (
    ReportGenerate, ReportSchedule, ReportResponse,
    ReportListResponse, ScheduledReportResponse
)

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.post("/generate", response_model=ReportResponse, status_code=201)
def generate_report(
    report_data: ReportGenerate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Generate an on-demand report."""
    # Verify scan belongs to user
    scan = db.query(Scan).filter(
        Scan.id == report_data.scan_id,
        Scan.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Create report record
    report = GeneratedReport(
        user_id=current_user.id,
        scan_id=scan.id,
        report_type=report_data.report_type,
        file_format=report_data.file_format,
        file_path=f"reports/{scan.domain}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.{report_data.file_format}",
        expires_at=datetime.utcnow() + timedelta(days=7),
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    
    return report


@router.post("/schedule", response_model=ScheduledReportResponse, status_code=201)
def schedule_report(
    schedule_data: ReportSchedule,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Schedule automated report generation."""
    scheduled = ScheduledReport(
        user_id=current_user.id,
        report_type=schedule_data.report_type,
        frequency=schedule_data.frequency,
        cron_expression=schedule_data.cron_expression,
        selected_scans=schedule_data.selected_scans,
        included_sections=schedule_data.included_sections,
        delivery_email=schedule_data.delivery_email,
        next_run_at=datetime.utcnow() + timedelta(days=1),
    )
    db.add(scheduled)
    db.commit()
    db.refresh(scheduled)
    
    return scheduled


@router.get("", response_model=ReportListResponse)
def list_reports(
    page: int = 1,
    size: int = 20,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List generated reports."""
    query = db.query(GeneratedReport).filter(GeneratedReport.user_id == current_user.id)
    total = query.count()
    reports = query.order_by(GeneratedReport.generated_at.desc()).offset((page - 1) * size).limit(size).all()
    
    return ReportListResponse(
        items=[ReportResponse.model_validate(r) for r in reports],
        total=total
    )
