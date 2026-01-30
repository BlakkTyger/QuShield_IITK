"""
Asset Routes

Asset management endpoints.
"""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_
from app.api.deps import get_db, get_current_active_user
from app.models.user import User
from app.models.scan import Scan
from app.models.asset import Asset
from app.models.certificate import Certificate
from app.models.crypto import CryptoSecurity
from app.schemas.asset import (
    AssetCreate, AssetResponse, AssetDetail, AssetListResponse,
    CertificateResponse, CryptoSecurityResponse
)

router = APIRouter(prefix="/assets", tags=["Assets"])


@router.get("", response_model=AssetListResponse)
def list_assets(
    page: int = 1,
    size: int = 20,
    scan_id: Optional[str] = None,
    risk_level: Optional[str] = None,
    asset_type: Optional[str] = None,
    quantum_safety: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List assets with filters and pagination."""
    # Base query - only user's scans
    query = db.query(Asset).join(Scan).filter(Scan.user_id == current_user.id)
    
    if scan_id:
        query = query.filter(Asset.scan_id == scan_id)
    if risk_level:
        query = query.filter(Asset.risk_level == risk_level)
    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)
    if quantum_safety:
        query = query.filter(Asset.quantum_safety == quantum_safety)
    if search:
        query = query.filter(or_(
            Asset.fqdn.ilike(f"%{search}%"),
            Asset.ipv4_address.ilike(f"%{search}%")
        ))
    
    total = query.count()
    assets = query.order_by(Asset.fqdn).offset((page - 1) * size).limit(size).all()
    
    return AssetListResponse(
        items=[AssetResponse.model_validate(a) for a in assets],
        total=total,
        page=page,
        size=size
    )


@router.post("", response_model=AssetResponse, status_code=201)
def create_asset(
    asset_data: AssetCreate,
    scan_id: str = Query(..., description="Scan ID to add asset to"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Add a new asset manually."""
    # Verify scan belongs to user
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Check if asset already exists
    existing = db.query(Asset).filter(
        Asset.scan_id == scan_id,
        Asset.fqdn == asset_data.fqdn,
        Asset.port == asset_data.port
    ).first()
    
    if existing:
        raise HTTPException(status_code=400, detail="Asset already exists in this scan")
    
    asset = Asset(
        scan_id=scan_id,
        fqdn=asset_data.fqdn,
        port=asset_data.port,
        owner=asset_data.owner,
        asset_type=asset_data.asset_type,
        discovery_source="manual",
        status="confirmed",
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    
    return asset


@router.get("/{asset_id}", response_model=AssetDetail)
def get_asset(
    asset_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get detailed asset information."""
    asset = db.query(Asset).join(Scan).filter(
        Asset.id == asset_id,
        Scan.user_id == current_user.id
    ).first()
    
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    return AssetDetail(
        **AssetResponse.model_validate(asset).model_dump(),
        scan_success=asset.scan_success,
        scan_error=asset.scan_error,
        hndl_label=asset.hndl_label,
        recommended_action=asset.recommended_action,
        certificates=[CertificateResponse.model_validate(c) for c in asset.certificates],
        crypto_security=[CryptoSecurityResponse.model_validate(cs) for cs in asset.crypto_security]
    )


@router.get("/{asset_id}/certificates", response_model=List[CertificateResponse])
def get_asset_certificates(
    asset_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get asset certificates."""
    asset = db.query(Asset).join(Scan).filter(
        Asset.id == asset_id,
        Scan.user_id == current_user.id
    ).first()
    
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    return [CertificateResponse.model_validate(c) for c in asset.certificates]


@router.get("/{asset_id}/crypto", response_model=List[CryptoSecurityResponse])
def get_asset_crypto(
    asset_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get asset crypto security details."""
    asset = db.query(Asset).join(Scan).filter(
        Asset.id == asset_id,
        Scan.user_id == current_user.id
    ).first()
    
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    return [CryptoSecurityResponse.model_validate(cs) for cs in asset.crypto_security]
