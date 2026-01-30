"""Scan Service

Integrates qushield workflow with database persistence.
Supports real-time streaming of scan results to database.
"""

import sys
import asyncio
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

# Add qushield to path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.scan import Scan, ScanSummary
from app.models.asset import Asset
from app.models.certificate import Certificate
from app.models.dns_record import DNSRecord
from app.models.crypto import CryptoSecurity
from app.models.graph import GraphNode, GraphEdge
from app.models.whois import WhoisInfo
from app.models.certification import PQCCertification

logger = logging.getLogger(__name__)


class RealTimeScanPersister:
    """Handles real-time persistence of scan results to database."""
    
    def __init__(self, scan_id: str, domain: str):
        self.scan_id = scan_id
        self.domain = domain
        self.assets_discovered = 0
        self.assets_scanned = 0
        self.quantum_safe_count = 0
        self.vulnerable_count = 0
        self.hybrid_count = 0
        self.critical_count = 0
        self.hndl_scores = []
        self.assets_successful = 0
    
    async def on_discovery(self, assets):
        """Called when assets are discovered - persist immediately."""
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == self.scan_id).first()
            if not scan:
                return
            
            # Update discovery count
            self.assets_discovered = len(assets)
            scan.assets_discovered = self.assets_discovered
            
            # Create domain graph node
            domain_node = GraphNode(
                scan_id=scan.id,
                node_id=f"domain:{self.domain}",
                node_type="domain",
                label=self.domain,
            )
            db.add(domain_node)
            
            # Create asset records for all discovered assets
            for asset_data in assets:
                asset = Asset(
                    scan_id=scan.id,
                    fqdn=asset_data.fqdn,
                    port=asset_data.port,
                    discovery_source=asset_data.source,
                    quantum_safety="UNKNOWN",
                    cert_tier="NOT_SCANNED",
                    risk_level="low",
                    scan_success=False,
                )
                db.add(asset)
                
                # Add subdomain graph node
                node = GraphNode(
                    scan_id=scan.id,
                    node_id=f"subdomain:{asset_data.fqdn}",
                    node_type="subdomain",
                    label=asset_data.fqdn,
                )
                db.add(node)
                
                # Add edge: domain -> subdomain
                edge = GraphEdge(
                    scan_id=scan.id,
                    source_id=f"domain:{self.domain}",
                    target_id=f"subdomain:{asset_data.fqdn}",
                    edge_type="has_subdomain"
                )
                db.add(edge)
            
            db.commit()
            logger.info(f"Persisted {len(assets)} discovered assets for scan {self.scan_id}")
            
        except Exception as e:
            logger.error(f"Failed to persist discovery: {e}")
            db.rollback()
        finally:
            db.close()
    
    async def on_asset_scanned(self, asset_analysis):
        """Called when each asset is scanned - update immediately."""
        db = SessionLocal()
        try:
            # Find the asset record
            asset = db.query(Asset).filter(
                Asset.scan_id == self.scan_id,
                Asset.fqdn == asset_analysis.fqdn
            ).first()
            
            if not asset:
                return
            
            # Update asset with scan results
            asset.quantum_safety = asset_analysis.quantum_safety
            asset.cert_tier = asset_analysis.cert_tier
            asset.scan_success = asset_analysis.scan_success
            asset.last_scan_time = datetime.utcnow()
            
            if asset_analysis.hndl_score:
                asset.hndl_score = asset_analysis.hndl_score.score
                asset.hndl_label = asset_analysis.hndl_score.label.value
                asset.recommended_action = asset_analysis.hndl_score.recommended_action
                self.hndl_scores.append(asset_analysis.hndl_score.score)
            
            # Set risk level
            if asset_analysis.quantum_safety == "CRITICAL_LEGACY":
                asset.risk_level = "critical"
                self.critical_count += 1
            elif asset_analysis.quantum_safety == "QUANTUM_VULNERABLE":
                asset.risk_level = "high"
                self.vulnerable_count += 1
            elif asset_analysis.quantum_safety == "PQC_READY":
                asset.risk_level = "medium"
                self.hybrid_count += 1
            elif asset_analysis.quantum_safety == "FULLY_QUANTUM_SAFE":
                asset.risk_level = "low"
                self.quantum_safe_count += 1
            
            # Process certificate if available
            if asset_analysis.scan_result and hasattr(asset_analysis.scan_result, 'certificate'):
                cert_info = asset_analysis.scan_result.certificate
                if cert_info:
                    asset.ipv4_address = getattr(asset_analysis.scan_result, 'ip_address', None)
                    self._persist_certificate(db, asset, cert_info)
                    self._persist_crypto(db, asset, asset_analysis)
            
            # Update scan progress (assets_scanned stores assets PROCESSED)
            self.assets_scanned += 1
            
            if asset_analysis.scan_success:
                self.assets_successful += 1
            
            scan = db.query(Scan).filter(Scan.id == self.scan_id).first()
            if scan:
                scan.assets_scanned = self.assets_scanned
            
            db.commit()
            
        except Exception as e:
            logger.error(f"Failed to persist asset scan: {e}")
            db.rollback()
        finally:
            db.close()
    
    def _persist_certificate(self, db: Session, asset: Asset, cert_info):
        """Persist certificate data."""
        def parse_cert_date(date_val):
            if date_val is None:
                return None
            if isinstance(date_val, datetime):
                return date_val.replace(tzinfo=None) if date_val.tzinfo else date_val
            if isinstance(date_val, str):
                try:
                    dt = datetime.fromisoformat(date_val.replace('Z', '+00:00'))
                    return dt.replace(tzinfo=None)
                except (ValueError, AttributeError):
                    return None
            return None
        
        valid_from_dt = parse_cert_date(getattr(cert_info, 'not_before', None))
        valid_until_dt = parse_cert_date(getattr(cert_info, 'not_after', None))
        
        cert = Certificate(
            asset_id=asset.id,
            sha256_fingerprint=getattr(cert_info, 'sha256_fingerprint', None),
            subject_cn=getattr(cert_info, 'common_name', getattr(cert_info, 'subject', None)),
            issuer_cn=getattr(cert_info, 'issuer', None),
            certificate_authority=getattr(cert_info, 'issuer', None),
            valid_from=valid_from_dt,
            valid_until=valid_until_dt,
            key_algorithm=getattr(cert_info, 'public_key_algorithm', None),
            key_size=getattr(cert_info, 'public_key_size', None),
            signature_algorithm=getattr(cert_info, 'signature_algorithm', None),
            san_entries=getattr(cert_info, 'san_entries', getattr(cert_info, 'san', [])),
            is_self_signed=getattr(cert_info, 'is_self_signed', False),
        )
        
        if valid_until_dt:
            days_until = (valid_until_dt - datetime.utcnow()).days
            cert.days_until_expiry = days_until
            cert.is_expired = days_until < 0
        
        db.add(cert)
    
    def _persist_crypto(self, db: Session, asset: Asset, asset_analysis):
        """Persist crypto security data."""
        scan_result = asset_analysis.scan_result
        if not scan_result:
            return
        
        tls_versions = getattr(scan_result, 'tls_versions', [])
        cipher_suites = getattr(scan_result, 'cipher_suites', [])
        
        crypto = CryptoSecurity(
            asset_id=asset.id,
            tls_version=tls_versions[0] if tls_versions else None,
            supported_tls_versions=tls_versions,
            cipher_suite=cipher_suites[0] if cipher_suites else None,
            cipher_suites=cipher_suites,
            key_exchange_algorithm=asset_analysis.key_exchange_algorithms[0] if asset_analysis.key_exchange_algorithms else None,
            key_exchange_algorithms=asset_analysis.key_exchange_algorithms,
            is_pfs_enabled='DHE' in str(asset_analysis.key_exchange_algorithms) or 'ECDHE' in str(asset_analysis.key_exchange_algorithms),
            supports_tls13='TLS 1.3' in str(tls_versions) or '1.3' in str(tls_versions),
        )
        db.add(crypto)
    
    async def on_progress(self, stage: str, current: int, total: int):
        """Called to report progress."""
        logger.debug(f"Scan progress: {stage} {current}/{total}")
    
    def finalize(self, result) -> None:
        """Finalize scan with summary data."""
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == self.scan_id).first()
            if not scan:
                return
            
            # Create scan summary
            avg_hndl = sum(self.hndl_scores) / len(self.hndl_scores) if self.hndl_scores else 0.0
            
            summary = ScanSummary(
                scan_id=scan.id,
                total_assets=self.assets_discovered,
                quantum_safe_count=self.quantum_safe_count,
                hybrid_count=self.hybrid_count,
                vulnerable_count=self.vulnerable_count,
                critical_count=self.critical_count,
                average_hndl_score=avg_hndl,
            )
            
            # Calculate enterprise score
            total = self.assets_scanned or 1
            safe_ratio = (self.quantum_safe_count + self.hybrid_count * 0.5) / total
            summary.enterprise_score = int(400 + safe_ratio * 600)
            
            if summary.enterprise_score >= 700:
                summary.rating_category = "Elite"
            elif summary.enterprise_score >= 400:
                summary.rating_category = "Standard"
            else:
                summary.rating_category = "Legacy"
            
            # Count certificate expiry
            certs = db.query(Certificate).join(Asset).filter(Asset.scan_id == scan.id).all()
            summary.expiring_certs_30d = sum(1 for c in certs if c.days_until_expiry and 0 < c.days_until_expiry <= 30)
            summary.expiring_certs_60d = sum(1 for c in certs if c.days_until_expiry and 30 < c.days_until_expiry <= 60)
            summary.expiring_certs_90d = sum(1 for c in certs if c.days_until_expiry and 60 < c.days_until_expiry <= 90)
            summary.expired_certs = sum(1 for c in certs if c.is_expired)
            
            # Count IPs
            summary.ipv4_count = db.query(Asset).filter(Asset.scan_id == scan.id, Asset.ipv4_address.isnot(None)).count()
            summary.ipv6_count = db.query(Asset).filter(Asset.scan_id == scan.id, Asset.ipv6_address.isnot(None)).count()
            
            db.add(summary)
            db.commit()
            
            logger.info(f"Finalized scan summary: {self.assets_scanned} scanned, score={summary.enterprise_score}")
            
        except Exception as e:
            logger.error(f"Failed to finalize scan: {e}")
            db.rollback()
        finally:
            db.close()


def execute_scan(
    scan_id: str,
    domain: str,
    max_assets: int = 50,
    skip_discovery: bool = False,
    targets: Optional[List[str]] = None,
):
    """Execute scan in background thread with new event loop and real-time streaming."""
    logger.info(f"Starting scan execution for {domain} (scan_id: {scan_id})")
    
    # Create a new event loop for this thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_execute_scan_async(
            scan_id, domain, max_assets, skip_discovery, targets
        ))
    except Exception as e:
        logger.error(f"Scan execution failed: {e}", exc_info=True)
        # Update scan status to failed
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = "failed"
                scan.error_message = str(e)
                scan.completed_at = datetime.utcnow()
                db.commit()
        finally:
            db.close()
    finally:
        loop.close()


async def _execute_scan_async(
    scan_id: str,
    domain: str,
    max_assets: int,
    skip_discovery: bool,
    targets: Optional[List[str]],
):
    """Execute scan asynchronously with real-time database streaming."""
    db = SessionLocal()
    
    try:
        # Update status to running
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
        
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        db.commit()
        db.close()  # Close initial connection
        
        # Create real-time persister
        persister = RealTimeScanPersister(scan_id, domain)
        
        # Import qushield workflow
        from qushield.workflow import QuShieldWorkflow
        
        # Run qushield workflow with callbacks for real-time streaming
        workflow = QuShieldWorkflow(
            scan_timeout=45,
            max_concurrent_scans=20,  # Increased for better throughput
            save_outputs=True,
            on_discovery=persister.on_discovery,
            on_asset_scanned=persister.on_asset_scanned,
            on_progress=persister.on_progress,
        )
        
        result = await workflow.run(
            domain=domain,
            max_assets=max_assets,
            skip_discovery=skip_discovery,
            targets=targets,
        )
        
        # Finalize with summary
        persister.finalize(result)
        
        # Update final scan status
        db = SessionLocal()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "completed"
            scan.completed_at = datetime.utcnow()
            scan.duration_ms = int(result.duration_ms)
            scan.assets_discovered = result.assets_discovered
            scan.assets_scanned = result.assets_scanned
            scan.scan_failures = result.scan_failures
            scan.output_file = result.output_file
            db.commit()
        db.close()
        
    except Exception as e:
        # Update status to failed
        db = SessionLocal()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "failed"
            scan.error_message = str(e)
            scan.completed_at = datetime.utcnow()
            db.commit()
        db.close()
        raise


async def persist_scan_results(db: Session, scan: Scan, result):
    """Persist qushield workflow results to database."""
    
    # Get structured output if available
    output = getattr(result, 'structured_output', None)
    
    # Create asset ID mapping for relationships
    asset_id_map = {}
    
    # 1. Persist assets
    for asset_data in result.assets:
        asset = Asset(
            scan_id=scan.id,
            fqdn=asset_data.fqdn,
            port=asset_data.port,
            discovery_source=asset_data.discovery_source,
            quantum_safety=asset_data.quantum_safety,
            hndl_score=asset_data.hndl_score.score if asset_data.hndl_score else None,
            hndl_label=asset_data.hndl_score.label.value if asset_data.hndl_score else None,
            recommended_action=asset_data.hndl_score.recommended_action if asset_data.hndl_score else None,
            cert_tier=asset_data.cert_tier,
            scan_success=asset_data.scan_success,
            last_scan_time=datetime.utcnow(),
        )
        
        # Set risk level based on quantum safety
        if asset_data.quantum_safety == "CRITICAL_LEGACY":
            asset.risk_level = "critical"
        elif asset_data.quantum_safety == "QUANTUM_VULNERABLE":
            asset.risk_level = "high"
        elif asset_data.quantum_safety == "PQC_READY":
            asset.risk_level = "medium"
        else:
            asset.risk_level = "low"
        
        # Extract IP from scan result
        if asset_data.scan_result:
            scan_result = asset_data.scan_result
            asset.ipv4_address = getattr(scan_result, 'ip_address', None)
            
            # Persist certificate
            if hasattr(scan_result, 'certificate') and scan_result.certificate:
                cert_info = scan_result.certificate
                db.add(asset)
                db.flush()  # Get asset ID
                
                # Parse date strings to datetime objects
                def parse_cert_date(date_val):
                    if date_val is None:
                        return None
                    if isinstance(date_val, datetime):
                        return date_val.replace(tzinfo=None) if date_val.tzinfo else date_val
                    if isinstance(date_val, str):
                        try:
                            dt = datetime.fromisoformat(date_val.replace('Z', '+00:00'))
                            return dt.replace(tzinfo=None)
                        except (ValueError, AttributeError):
                            return None
                    return None
                
                valid_from_dt = parse_cert_date(getattr(cert_info, 'not_before', None))
                valid_until_dt = parse_cert_date(getattr(cert_info, 'not_after', None))
                
                cert = Certificate(
                    asset_id=asset.id,
                    sha256_fingerprint=getattr(cert_info, 'sha256_fingerprint', None),
                    subject_cn=getattr(cert_info, 'common_name', None),
                    issuer_cn=getattr(cert_info, 'issuer', None),
                    certificate_authority=getattr(cert_info, 'issuer', None),
                    valid_from=valid_from_dt,
                    valid_until=valid_until_dt,
                    key_algorithm=getattr(cert_info, 'public_key_algorithm', None),
                    key_size=getattr(cert_info, 'public_key_size', None),
                    signature_algorithm=getattr(cert_info, 'signature_algorithm', None),
                    san_entries=getattr(cert_info, 'san', []),
                    is_self_signed=getattr(cert_info, 'is_self_signed', False),
                )
                
                # Calculate expiry
                if valid_until_dt:
                    days_until = (valid_until_dt - datetime.utcnow()).days
                    cert.days_until_expiry = days_until
                    cert.is_expired = days_until < 0
                
                db.add(cert)
            
            # Persist crypto security
            if hasattr(scan_result, 'cipher_suites') or hasattr(scan_result, 'tls_versions'):
                db.add(asset)
                db.flush()
                
                crypto = CryptoSecurity(
                    asset_id=asset.id,
                    tls_version=scan_result.tls_versions[0] if getattr(scan_result, 'tls_versions', None) else None,
                    supported_tls_versions=getattr(scan_result, 'tls_versions', []),
                    cipher_suite=scan_result.cipher_suites[0] if getattr(scan_result, 'cipher_suites', None) else None,
                    cipher_suites=getattr(scan_result, 'cipher_suites', []),
                    key_exchange_algorithm=asset_data.key_exchange_algorithms[0] if asset_data.key_exchange_algorithms else None,
                    key_exchange_algorithms=asset_data.key_exchange_algorithms,
                    is_pfs_enabled='DHE' in str(asset_data.key_exchange_algorithms) or 'ECDHE' in str(asset_data.key_exchange_algorithms),
                    supports_tls13='TLS 1.3' in str(getattr(scan_result, 'tls_versions', [])),
                )
                db.add(crypto)
        
        db.add(asset)
        asset_id_map[asset_data.fqdn] = asset
    
    db.flush()
    
    # 2. Persist graph data
    # Add domain node
    domain_node = GraphNode(
        scan_id=scan.id,
        node_id=f"domain:{scan.domain}",
        node_type="domain",
        label=scan.domain,
    )
    db.add(domain_node)
    
    # Add asset nodes and edges
    for fqdn, asset in asset_id_map.items():
        # Subdomain node
        node = GraphNode(
            scan_id=scan.id,
            node_id=f"subdomain:{fqdn}",
            node_type="subdomain",
            label=fqdn,
            properties={"risk_level": asset.risk_level, "quantum_safety": asset.quantum_safety}
        )
        db.add(node)
        
        # Edge: domain -> subdomain
        edge = GraphEdge(
            scan_id=scan.id,
            source_id=f"domain:{scan.domain}",
            target_id=f"subdomain:{fqdn}",
            edge_type="has_subdomain"
        )
        db.add(edge)
        
        # IP node and edge
        if asset.ipv4_address:
            ip_node = GraphNode(
                scan_id=scan.id,
                node_id=f"ip:{asset.ipv4_address}",
                node_type="ip",
                label=asset.ipv4_address,
            )
            db.add(ip_node)
            
            ip_edge = GraphEdge(
                scan_id=scan.id,
                source_id=f"subdomain:{fqdn}",
                target_id=f"ip:{asset.ipv4_address}",
                edge_type="resolves_to"
            )
            db.add(ip_edge)
    
    # 3. Create scan summary - calculate counts from assets
    hybrid_count = sum(1 for a in result.assets if a.quantum_safety == "PQC_READY")
    platinum_count = sum(1 for a in result.assets if a.cert_tier == "FULLY_QUANTUM_SAFE")
    gold_count = sum(1 for a in result.assets if a.cert_tier == "PQC_READY")
    silver_count = sum(1 for a in result.assets if a.cert_tier == "VULNERABLE")
    bronze_count = sum(1 for a in result.assets if a.cert_tier == "CRITICAL")
    
    summary = ScanSummary(
        scan_id=scan.id,
        total_assets=result.assets_discovered,
        quantum_safe_count=result.quantum_safe_count,
        hybrid_count=hybrid_count,
        vulnerable_count=result.vulnerable_count,
        critical_count=result.critical_count,
        platinum_count=platinum_count,
        gold_count=gold_count,
        silver_count=silver_count,
        bronze_count=bronze_count,
        average_hndl_score=result.average_hndl_score,
    )
    
    # Calculate enterprise score
    total = result.assets_scanned or 1
    safe_ratio = (result.quantum_safe_count + hybrid_count * 0.5) / total
    summary.enterprise_score = int(400 + safe_ratio * 600)
    
    if summary.enterprise_score >= 700:
        summary.rating_category = "Elite"
    elif summary.enterprise_score >= 400:
        summary.rating_category = "Standard"
    else:
        summary.rating_category = "Legacy"
    
    # Count certificate expiry
    certs = db.query(Certificate).join(Asset).filter(Asset.scan_id == scan.id).all()
    summary.expiring_certs_30d = sum(1 for c in certs if c.days_until_expiry and 0 < c.days_until_expiry <= 30)
    summary.expiring_certs_60d = sum(1 for c in certs if c.days_until_expiry and 30 < c.days_until_expiry <= 60)
    summary.expiring_certs_90d = sum(1 for c in certs if c.days_until_expiry and 60 < c.days_until_expiry <= 90)
    summary.expired_certs = sum(1 for c in certs if c.is_expired)
    
    # Count IPs
    assets_with_ipv4 = db.query(Asset).filter(Asset.scan_id == scan.id, Asset.ipv4_address.isnot(None)).count()
    assets_with_ipv6 = db.query(Asset).filter(Asset.scan_id == scan.id, Asset.ipv6_address.isnot(None)).count()
    summary.ipv4_count = assets_with_ipv4
    summary.ipv6_count = assets_with_ipv6
    
    db.add(summary)
    db.commit()
