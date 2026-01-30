"""
Rating Routes

Cyber rating endpoints.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.api.deps import get_db, get_current_active_user
from app.models.user import User
from app.models.scan import Scan, ScanSummary
from app.models.asset import Asset
from app.schemas.rating import EnterpriseRating, AssetRating, AssetRatingItem

router = APIRouter(prefix="/rating", tags=["Rating"])


def calculate_asset_score(asset: Asset) -> int:
    """Calculate individual asset cyber rating score (0-1000)."""
    score = 500  # Base score
    
    # Quantum safety adjustments
    if asset.quantum_safety == "FULLY_SAFE":
        score += 300
    elif asset.quantum_safety == "HYBRID":
        score += 150
    elif asset.quantum_safety == "VULNERABLE":
        score -= 100
    elif asset.quantum_safety == "CRITICAL":
        score -= 250
    
    # HNDL score adjustments (lower is better)
    if asset.hndl_score is not None:
        hndl_penalty = int(asset.hndl_score * 200)
        score -= hndl_penalty
    
    # Certification tier bonus
    if asset.cert_tier == "PLATINUM":
        score += 100
    elif asset.cert_tier == "GOLD":
        score += 75
    elif asset.cert_tier == "SILVER":
        score += 50
    elif asset.cert_tier == "BRONZE":
        score += 25
    
    # Clamp to 0-1000 range
    return max(0, min(1000, score))


def get_rating_category(score: int) -> str:
    """Get rating category from score."""
    if score >= 700:
        return "Elite"
    elif score >= 400:
        return "Standard"
    else:
        return "Legacy"


@router.get("/enterprise", response_model=EnterpriseRating)
def get_enterprise_rating(
    scan_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get enterprise cyber rating."""
    # Get latest scan or specific scan
    if scan_id:
        scan = db.query(Scan).filter(
            Scan.id == scan_id,
            Scan.user_id == current_user.id
        ).first()
    else:
        scan = db.query(Scan).filter(
            Scan.user_id == current_user.id,
            Scan.status == "completed"
        ).order_by(Scan.completed_at.desc()).first()
    
    if not scan or not scan.summary:
        return EnterpriseRating(
            enterprise_score=0,
            category="Legacy"
        )
    
    # Use stored enterprise score or calculate
    if scan.summary.enterprise_score is not None:
        score = scan.summary.enterprise_score
    else:
        # Calculate average score from assets
        assets = db.query(Asset).filter(
            Asset.scan_id == scan.id,
            Asset.scan_success == True
        ).all()
        
        if assets:
            scores = [calculate_asset_score(a) for a in assets]
            score = int(sum(scores) / len(scores))
        else:
            score = 0
    
    category = scan.summary.rating_category or get_rating_category(score)
    
    # Score breakdown
    breakdown = {
        "quantum_safety": {
            "weight": 0.4,
            "score": min(1.0, (scan.summary.quantum_safe_count + scan.summary.hybrid_count * 0.5) / max(1, scan.summary.total_assets))
        },
        "certificate_health": {
            "weight": 0.2,
            "score": 1.0 - min(1.0, scan.summary.expiring_certs_30d / max(1, scan.summary.total_assets))
        },
        "protocol_strength": {
            "weight": 0.2,
            "score": 1.0 - min(1.0, scan.summary.weak_crypto_count / max(1, scan.summary.total_assets))
        },
        "hndl_risk": {
            "weight": 0.2,
            "score": 1.0 - (scan.summary.average_hndl_score or 0)
        }
    }
    
    return EnterpriseRating(
        enterprise_score=score,
        category=category,
        breakdown=breakdown
    )


@router.get("/assets", response_model=AssetRating)
def get_asset_ratings(
    scan_id: Optional[str] = None,
    page: int = 1,
    size: int = 20,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get individual asset ratings."""
    # Build query
    if scan_id:
        query = db.query(Asset).join(Scan).filter(
            Asset.scan_id == scan_id,
            Scan.user_id == current_user.id,
            Asset.scan_success == True
        )
    else:
        # Get assets from latest completed scan
        latest_scan = db.query(Scan).filter(
            Scan.user_id == current_user.id,
            Scan.status == "completed"
        ).order_by(Scan.completed_at.desc()).first()
        
        if not latest_scan:
            return AssetRating(items=[], total=0, average_score=0)
        
        query = db.query(Asset).filter(
            Asset.scan_id == latest_scan.id,
            Asset.scan_success == True
        )
    
    total = query.count()
    assets = query.order_by(Asset.fqdn).offset((page - 1) * size).limit(size).all()
    
    items = []
    total_score = 0
    for asset in assets:
        score = calculate_asset_score(asset)
        total_score += score
        items.append(AssetRatingItem(
            id=asset.id,
            fqdn=asset.fqdn,
            url=f"https://{asset.fqdn}:{asset.port}",
            score=score,
            category=get_rating_category(score),
            hndl_score=asset.hndl_score,
            quantum_safety=asset.quantum_safety,
        ))
    
    avg_score = total_score / len(items) if items else 0
    
    return AssetRating(
        items=items,
        total=total,
        average_score=round(avg_score, 1)
    )
