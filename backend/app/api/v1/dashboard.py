"""
Dashboard Routes

Dashboard metrics and risk distribution endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Optional
from app.api.deps import get_db, get_current_active_user
from app.models.user import User
from app.models.scan import Scan, ScanSummary
from app.models.asset import Asset
from app.models.certificate import Certificate
from app.schemas.dashboard import (
    DashboardMetrics, RiskDistribution, AssetCounts, QuantumSafetyCounts,
    CertificationCounts, CertExpiryCounts, IPBreakdown,
    RiskDistributionItem, HighRiskAsset, ExpiringCert, MoscaAsset
)

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/metrics", response_model=DashboardMetrics)
def get_dashboard_metrics(
    scan_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get dashboard metrics (counts, scores, etc.)."""
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
        return DashboardMetrics(
            asset_counts=AssetCounts(),
            quantum_safety=QuantumSafetyCounts(),
            certifications=CertificationCounts(),
            cert_expiry=CertExpiryCounts(),
            ip_breakdown=IPBreakdown()
        )
    
    summary = scan.summary
    total_ips = summary.ipv4_count + summary.ipv6_count
    
    return DashboardMetrics(
        asset_counts=AssetCounts(
            total_assets=summary.total_assets,
            public_web_apps=summary.public_web_apps,
            apis=summary.apis,
            servers=summary.servers,
            gateways=summary.gateways,
            cdns=summary.cdns,
        ),
        quantum_safety=QuantumSafetyCounts(
            quantum_safe=summary.quantum_safe_count,
            hybrid=summary.hybrid_count,
            vulnerable=summary.vulnerable_count,
            critical=summary.critical_count,
        ),
        certifications=CertificationCounts(
            platinum=summary.platinum_count,
            gold=summary.gold_count,
            silver=summary.silver_count,
            bronze=summary.bronze_count,
        ),
        cert_expiry=CertExpiryCounts(
            expired=summary.expired_certs,
            expiring_30d=summary.expiring_certs_30d,
            expiring_60d=summary.expiring_certs_60d,
            expiring_90d=summary.expiring_certs_90d,
        ),
        ip_breakdown=IPBreakdown(
            ipv4_count=summary.ipv4_count,
            ipv6_count=summary.ipv6_count,
            ipv4_percent=round(summary.ipv4_count / total_ips * 100, 1) if total_ips > 0 else 0,
            ipv6_percent=round(summary.ipv6_count / total_ips * 100, 1) if total_ips > 0 else 0,
        ),
        enterprise_score=summary.enterprise_score,
        rating_category=summary.rating_category,
        average_hndl_score=summary.average_hndl_score,
        last_scan_id=scan.id,
        last_scan_domain=scan.domain,
    )


@router.get("/risk-distribution", response_model=RiskDistribution)
def get_risk_distribution(
    scan_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get risk distribution data for charts."""
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
    
    if not scan:
        return RiskDistribution(
            risk_levels=[],
            asset_types=[],
            quantum_safety=[],
            high_risk_assets=[],
            expiring_certs=[]
        )
    
    # Risk level distribution
    risk_counts = db.query(
        Asset.risk_level, func.count(Asset.id)
    ).filter(Asset.scan_id == scan.id).group_by(Asset.risk_level).all()
    
    total_assets = sum(c[1] for c in risk_counts)
    risk_levels = [
        RiskDistributionItem(
            label=level or "unknown",
            count=count,
            percentage=round(count / total_assets * 100, 1) if total_assets > 0 else 0
        )
        for level, count in risk_counts
    ]
    
    # Asset type distribution
    type_counts = db.query(
        Asset.asset_type, func.count(Asset.id)
    ).filter(Asset.scan_id == scan.id).group_by(Asset.asset_type).all()
    
    asset_types = [
        RiskDistributionItem(
            label=atype or "unknown",
            count=count,
            percentage=round(count / total_assets * 100, 1) if total_assets > 0 else 0
        )
        for atype, count in type_counts
    ]
    
    # Quantum safety distribution
    safety_counts = db.query(
        Asset.quantum_safety, func.count(Asset.id)
    ).filter(Asset.scan_id == scan.id).group_by(Asset.quantum_safety).all()
    
    quantum_safety = [
        RiskDistributionItem(
            label=safety or "unknown",
            count=count,
            percentage=round(count / total_assets * 100, 1) if total_assets > 0 else 0
        )
        for safety, count in safety_counts
    ]
    
    # High risk assets
    high_risk = db.query(Asset).filter(
        Asset.scan_id == scan.id,
        Asset.risk_level.in_(["critical", "high"])
    ).limit(10).all()
    
    high_risk_assets = [
        HighRiskAsset(
            id=a.id,
            fqdn=a.fqdn,
            risk_level=a.risk_level,
            hndl_score=a.hndl_score,
            quantum_safety=a.quantum_safety
        )
        for a in high_risk
    ]
    
    # Expiring certificates
    expiring = db.query(Certificate).join(Asset).filter(
        Asset.scan_id == scan.id,
        Certificate.days_until_expiry <= 90,
        Certificate.days_until_expiry > 0
    ).limit(10).all()
    
    expiring_certs = [
        ExpiringCert(
            id=c.id,
            asset_fqdn=c.asset.fqdn,
            subject_cn=c.subject_cn,
            valid_until=c.valid_until.isoformat() if c.valid_until else "",
            days_until_expiry=c.days_until_expiry or 0
        )
        for c in expiring
    ]
    
    # Mosca's Theorem Evaluation
    all_assets = db.query(Asset).filter(Asset.scan_id == scan.id).all()
    mosca_assets = []
    
    for a in all_assets:
        t_years = 5
        d_years = 10 if a.asset_type and "payment" in a.asset_type.lower() else 5
        
        if a.quantum_safety == "CRITICAL" or a.quantum_safety == "CRITICAL_LEGACY":
            z_years = 0
        elif a.quantum_safety == "VULNERABLE" or a.quantum_safety == "QUANTUM_VULNERABLE":
            z_years = 10
        elif a.quantum_safety == "HYBRID" or a.quantum_safety == "PQC_READY":
            z_years = 20
        else:
            z_years = 50
            
        is_violation = (d_years + t_years) >= z_years
        
        if is_violation:
            mosca_assets.append(MoscaAsset(
                id=a.id,
                fqdn=a.fqdn,
                d_years=d_years,
                t_years=t_years,
                z_years=z_years,
                is_violation=True
            ))
    
    return RiskDistribution(
        risk_levels=risk_levels,
        asset_types=asset_types,
        quantum_safety=quantum_safety,
        high_risk_assets=high_risk_assets,
        expiring_certs=expiring_certs,
        mosca_assets=mosca_assets[:15] # Top 15 to keep payload reasonable
    )
