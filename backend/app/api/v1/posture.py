"""
Posture Routes

PQC posture and compliance endpoints.
"""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.api.deps import get_db, get_current_active_user
from app.models.user import User
from app.models.scan import Scan, ScanSummary
from app.models.asset import Asset
from app.models.certification import PQCCertification
from app.schemas.posture import (
    PostureSummary, ClassificationGrade, Recommendation, RecommendationList,
    PQCCertificateResponse, PQCCertificateList
)

router = APIRouter(prefix="/posture", tags=["Posture"])


@router.get("/summary", response_model=PostureSummary)
def get_posture_summary(
    scan_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get PQC posture summary."""
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
        return PostureSummary()
    
    summary = scan.summary
    total = summary.total_assets
    
    # Calculate PQC adoption progress
    pqc_adoption = 0.0
    if total > 0:
        pqc_adoption = round((summary.quantum_safe_count + summary.hybrid_count * 0.5) / total * 100, 1)
    
    # Determine compliance status
    if summary.critical_count > 0:
        compliance_status = "NON_COMPLIANT"
        migration_priority = "CRITICAL"
    elif summary.vulnerable_count > 0:
        compliance_status = "PARTIAL"
        migration_priority = "HIGH"
    elif summary.hybrid_count > 0:
        compliance_status = "PARTIAL"
        migration_priority = "MEDIUM"
    else:
        compliance_status = "COMPLIANT"
        migration_priority = "LOW"
    
    # Classification grades
    classifications = []
    if total > 0:
        classifications = [
            ClassificationGrade(
                grade="Elite (Quantum-Safe)",
                count=summary.quantum_safe_count,
                percentage=round(summary.quantum_safe_count / total * 100, 1)
            ),
            ClassificationGrade(
                grade="Standard (Hybrid)",
                count=summary.hybrid_count,
                percentage=round(summary.hybrid_count / total * 100, 1)
            ),
            ClassificationGrade(
                grade="Legacy (Vulnerable)",
                count=summary.vulnerable_count,
                percentage=round(summary.vulnerable_count / total * 100, 1)
            ),
            ClassificationGrade(
                grade="Critical",
                count=summary.critical_count,
                percentage=round(summary.critical_count / total * 100, 1)
            ),
        ]
    
    return PostureSummary(
        pqc_adoption_progress=pqc_adoption,
        compliance_status=compliance_status,
        migration_priority=migration_priority,
        classifications=classifications,
        elite_count=summary.quantum_safe_count,
        standard_count=summary.hybrid_count,
        legacy_count=summary.vulnerable_count,
        critical_count=summary.critical_count,
    )


@router.get("/recommendations", response_model=RecommendationList)
def get_recommendations(
    scan_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get PQC remediation recommendations."""
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
        return RecommendationList(items=[], total=0)
    
    recommendations = []
    
    # Count assets by risk
    critical_count = db.query(func.count(Asset.id)).filter(
        Asset.scan_id == scan.id,
        Asset.quantum_safety == "CRITICAL"
    ).scalar() or 0
    
    vulnerable_count = db.query(func.count(Asset.id)).filter(
        Asset.scan_id == scan.id,
        Asset.quantum_safety == "VULNERABLE"
    ).scalar() or 0
    
    hybrid_count = db.query(func.count(Asset.id)).filter(
        Asset.scan_id == scan.id,
        Asset.quantum_safety == "HYBRID"
    ).scalar() or 0
    
    # Generate recommendations based on findings
    if critical_count > 0:
        recommendations.append(Recommendation(
            id="rec-1",
            priority="critical",
            category="key_exchange",
            title="Migrate from RSA Key Exchange",
            description="Replace RSA key exchange with ML-KEM (FIPS 203) or hybrid X25519+ML-KEM",
            affected_assets=critical_count,
            action="Upgrade to ML-KEM-768 or X25519Kyber768"
        ))
    
    if vulnerable_count > 0:
        recommendations.append(Recommendation(
            id="rec-2",
            priority="high",
            category="protocol",
            title="Upgrade to TLS 1.3 with PQC",
            description="Migrate to TLS 1.3 with post-quantum key encapsulation mechanisms",
            affected_assets=vulnerable_count,
            action="Deploy TLS 1.3 with hybrid PQC cipher suites"
        ))
    
    if hybrid_count > 0:
        recommendations.append(Recommendation(
            id="rec-3",
            priority="medium",
            category="signature",
            title="Transition to PQC Signatures",
            description="Replace ECDSA/RSA signatures with ML-DSA (FIPS 204)",
            affected_assets=hybrid_count,
            action="Deploy ML-DSA-65 for certificate signatures"
        ))
    
    # General recommendations
    recommendations.append(Recommendation(
        id="rec-4",
        priority="low",
        category="monitoring",
        title="Enable Continuous PQC Monitoring",
        description="Set up scheduled scans to track PQC migration progress",
        affected_assets=scan.assets_scanned,
        action="Configure weekly automated scans"
    ))
    
    return RecommendationList(items=recommendations, total=len(recommendations))


@router.get("/certificates", response_model=PQCCertificateList)
def get_pqc_certificates(
    scan_id: Optional[str] = None,
    page: int = 1,
    size: int = 20,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get issued PQC certificates."""
    # Build query
    query = db.query(PQCCertification).join(Asset).join(Scan).filter(
        Scan.user_id == current_user.id
    )
    
    if scan_id:
        query = query.filter(Asset.scan_id == scan_id)
    
    total = query.count()
    certs = query.order_by(PQCCertification.issued_at.desc()).offset((page - 1) * size).limit(size).all()
    
    return PQCCertificateList(
        items=[
            PQCCertificateResponse(
                id=c.id,
                asset_id=c.asset_id,
                asset_fqdn=c.asset.fqdn,
                cert_tier=c.cert_tier,
                certification_level=c.certification_level,
                score=c.score,
                issued_at=c.issued_at,
                valid_until=c.valid_until,
                signature_algorithm=c.signature_algorithm,
            )
            for c in certs
        ],
        total=total
    )
