"""
CBOM Routes

Cryptographic Bill of Materials endpoints.
"""

import uuid
from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.api.deps import get_db, get_current_active_user
from app.models.user import User
from app.models.scan import Scan
from app.models.asset import Asset
from app.models.certificate import Certificate
from app.models.crypto import CryptoSecurity
from app.schemas.cbom import (
    CBOMMetrics, CBOMExport, CipherUsage, KeyLengthDist,
    CADistribution, TLSVersionDist, CryptoComponent
)

router = APIRouter(prefix="/cbom", tags=["CBOM"])


@router.get("/metrics", response_model=CBOMMetrics)
def get_cbom_metrics(
    scan_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get CBOM aggregation metrics."""
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
        return CBOMMetrics()
    
    # Total applications (assets with scan success)
    total_apps = db.query(func.count(Asset.id)).filter(
        Asset.scan_id == scan.id,
        Asset.scan_success == True
    ).scalar() or 0
    
    # Active certificates
    active_certs = db.query(func.count(Certificate.id)).join(Asset).filter(
        Asset.scan_id == scan.id,
        Certificate.is_expired == False
    ).scalar() or 0
    
    # Weak crypto (RSA < 2048 or vulnerable algorithms)
    weak_crypto = db.query(func.count(CryptoSecurity.id)).join(Asset).filter(
        Asset.scan_id == scan.id,
        CryptoSecurity.key_length < 2048
    ).scalar() or 0
    
    # Certificate issues (expired or expiring soon)
    cert_issues = db.query(func.count(Certificate.id)).join(Asset).filter(
        Asset.scan_id == scan.id,
        Certificate.days_until_expiry <= 30
    ).scalar() or 0
    
    # Cipher usage distribution
    cipher_counts = db.query(
        CryptoSecurity.cipher_suite, func.count(CryptoSecurity.id)
    ).join(Asset).filter(
        Asset.scan_id == scan.id
    ).group_by(CryptoSecurity.cipher_suite).all()
    
    total_crypto = sum(c[1] for c in cipher_counts)
    cipher_usage = [
        CipherUsage(
            cipher=cipher or "unknown",
            count=count,
            percentage=round(count / total_crypto * 100, 1) if total_crypto > 0 else 0
        )
        for cipher, count in cipher_counts[:10]
    ]
    
    # Key length distribution
    key_counts = db.query(
        CryptoSecurity.key_length, func.count(CryptoSecurity.id)
    ).join(Asset).filter(
        Asset.scan_id == scan.id,
        CryptoSecurity.key_length.isnot(None)
    ).group_by(CryptoSecurity.key_length).all()
    
    key_distribution = [
        KeyLengthDist(
            key_length=length,
            count=count,
            percentage=round(count / total_crypto * 100, 1) if total_crypto > 0 else 0
        )
        for length, count in key_counts
    ]
    
    # Top CAs
    ca_counts = db.query(
        Certificate.certificate_authority, func.count(Certificate.id)
    ).join(Asset).filter(
        Asset.scan_id == scan.id
    ).group_by(Certificate.certificate_authority).order_by(
        func.count(Certificate.id).desc()
    ).limit(10).all()
    
    total_certs = sum(c[1] for c in ca_counts)
    top_cas = [
        CADistribution(
            ca_name=ca or "unknown",
            count=count,
            percentage=round(count / total_certs * 100, 1) if total_certs > 0 else 0
        )
        for ca, count in ca_counts
    ]
    
    # TLS version distribution
    tls_counts = db.query(
        CryptoSecurity.tls_version, func.count(CryptoSecurity.id)
    ).join(Asset).filter(
        Asset.scan_id == scan.id
    ).group_by(CryptoSecurity.tls_version).all()
    
    tls_distribution = [
        TLSVersionDist(
            version=version or "unknown",
            count=count,
            percentage=round(count / total_crypto * 100, 1) if total_crypto > 0 else 0
        )
        for version, count in tls_counts
    ]
    
    return CBOMMetrics(
        total_applications=total_apps,
        active_certificates=active_certs,
        weak_crypto_count=weak_crypto,
        certificate_issues=cert_issues,
        cipher_usage=cipher_usage,
        key_length_distribution=key_distribution,
        top_cas=top_cas,
        tls_version_distribution=tls_distribution,
    )


@router.get("/export")
def export_cbom(
    scan_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Export CBOM in CycloneDX 1.6 format."""
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
        raise HTTPException(status_code=404, detail="No scan found")
    
    # Get crypto security data
    crypto_data = db.query(CryptoSecurity).join(Asset).filter(
        Asset.scan_id == scan.id
    ).all()
    
    # Build components
    components = []
    for cs in crypto_data:
        if cs.cipher_suite:
            components.append({
                "type": "cryptographic-asset",
                "name": cs.cipher_suite,
                "bom-ref": f"crypto-{cs.id}",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": "cipher",
                        "mode": cs.encryption_algorithm,
                        "keyLength": cs.key_length,
                    }
                }
            })
    
    # Build CBOM
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tools": [{"name": "QuShield", "version": "1.0.0"}],
            "component": {
                "type": "application",
                "name": scan.domain,
                "version": "1.0.0",
            }
        },
        "components": components,
        "x-cert-in-qbom": {
            "pqc_readiness_score": scan.summary.average_hndl_score if scan.summary else 0,
            "migration_priority": "HIGH" if scan.summary and scan.summary.critical_count > 0 else "MEDIUM",
            "compliance_status": "PARTIAL" if scan.summary and scan.summary.quantum_safe_count > 0 else "NON_COMPLIANT",
        }
    }
    
    return JSONResponse(content=cbom, media_type="application/json")
