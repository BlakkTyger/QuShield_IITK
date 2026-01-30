"""
Scan Routes

Scan management and triggering endpoints.
"""

import threading
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.api.deps import get_db, get_current_active_user
from app.models.user import User
from app.models.scan import Scan, ScanSummary
from app.schemas.scan import ScanTrigger, ScanResponse, ScanStatus, ScanListResponse
from app.services.scan_service import execute_scan

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.get("", response_model=ScanListResponse)
def list_scans(
    page: int = 1,
    size: int = 20,
    status_filter: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List user's scans with pagination."""
    query = db.query(Scan).filter(Scan.user_id == current_user.id)
    
    if status_filter:
        query = query.filter(Scan.status == status_filter)
    
    total = query.count()
    scans = query.order_by(Scan.created_at.desc()).offset((page - 1) * size).limit(size).all()
    
    return ScanListResponse(
        items=[ScanResponse.model_validate(s) for s in scans],
        total=total,
        page=page,
        size=size
    )


@router.post("/trigger", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
def trigger_scan(
    scan_data: ScanTrigger,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Trigger a new scan (runs in background thread)."""
    # Create scan record
    scan = Scan(
        user_id=current_user.id,
        domain=scan_data.domain,
        status="pending",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # Run scan in a separate daemon thread
    scan_thread = threading.Thread(
        target=execute_scan,
        kwargs={
            "scan_id": scan.id,
            "domain": scan_data.domain,
            "max_assets": scan_data.max_assets,
            "skip_discovery": scan_data.skip_discovery,
            "targets": scan_data.targets,
        },
        daemon=True
    )
    scan_thread.start()
    
    return scan


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get scan details."""
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan


@router.get("/{scan_id}/status", response_model=ScanStatus)
def get_scan_status(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get scan status and progress."""
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Calculate progress
    progress = None
    if scan.status == "running" and scan.assets_discovered > 0:
        progress = int((scan.assets_scanned / scan.assets_discovered) * 100)
    elif scan.status == "completed":
        progress = 100
    
    return ScanStatus(
        id=scan.id,
        status=scan.status,
        progress=progress,
        assets_discovered=scan.assets_discovered,
        assets_scanned=scan.assets_scanned,
        started_at=scan.started_at,
        error_message=scan.error_message
    )
