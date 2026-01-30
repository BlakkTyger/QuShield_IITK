"""
Discovery Routes

Asset discovery endpoints.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.api.deps import get_db, get_current_active_user
from app.models.user import User
from app.models.scan import Scan, ScanSummary
from app.models.asset import Asset
from app.models.graph import GraphNode, GraphEdge
from app.schemas.discovery import (
    DiscoverySummary, DomainList, DomainItem, GraphData,
    GraphNode as GraphNodeSchema, GraphEdge as GraphEdgeSchema
)

router = APIRouter(prefix="/discovery", tags=["Discovery"])


@router.get("/summary", response_model=DiscoverySummary)
def get_discovery_summary(
    scan_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get discovery summary counts."""
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
        return DiscoverySummary()
    
    summary = scan.summary
    
    # Count SSL certs
    ssl_count = db.query(func.count()).select_from(Asset).filter(
        Asset.scan_id == scan.id
    ).join(Asset.certificates).scalar() or 0
    
    # Count unique IPs
    ip_count = db.query(func.count(func.distinct(Asset.ipv4_address))).filter(
        Asset.scan_id == scan.id,
        Asset.ipv4_address.isnot(None)
    ).scalar() or 0
    
    return DiscoverySummary(
        domains_count=summary.total_assets,
        ssl_certs_count=ssl_count,
        ip_subnets_count=ip_count,
        quantum_safe=summary.quantum_safe_count,
        hybrid=summary.hybrid_count,
        vulnerable=summary.vulnerable_count,
        critical=summary.critical_count,
    )


@router.get("/domains", response_model=DomainList)
def get_domains(
    scan_id: Optional[str] = None,
    page: int = 1,
    size: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get list of discovered domains."""
    # Get latest scan or specific scan
    if scan_id:
        query = db.query(Asset).join(Scan).filter(
            Asset.scan_id == scan_id,
            Scan.user_id == current_user.id
        )
    else:
        # Get assets from latest completed scan
        latest_scan = db.query(Scan).filter(
            Scan.user_id == current_user.id,
            Scan.status == "completed"
        ).order_by(Scan.completed_at.desc()).first()
        
        if not latest_scan:
            return DomainList(items=[], total=0)
        
        query = db.query(Asset).filter(Asset.scan_id == latest_scan.id)
    
    total = query.count()
    assets = query.order_by(Asset.fqdn).offset((page - 1) * size).limit(size).all()
    
    return DomainList(
        items=[
            DomainItem(
                id=a.id,
                fqdn=a.fqdn,
                detection_date=a.detection_date.isoformat() if a.detection_date else "",
                status=a.status,
                ipv4_address=a.ipv4_address,
                ipv6_address=a.ipv6_address,
                asset_type=a.asset_type,
                risk_level=a.risk_level,
            )
            for a in assets
        ],
        total=total
    )


@router.get("/graph", response_model=GraphData)
def get_graph_data(
    scan_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get graph data for asset relationship visualization."""
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
        return GraphData(nodes=[], edges=[])
    
    # Get nodes
    nodes = db.query(GraphNode).filter(GraphNode.scan_id == scan.id).all()
    
    # Get edges
    edges = db.query(GraphEdge).filter(GraphEdge.scan_id == scan.id).all()
    
    return GraphData(
        nodes=[
            GraphNodeSchema(
                id=n.node_id,
                type=n.node_type,
                label=n.label or n.node_id,
                properties=n.properties,
            )
            for n in nodes
        ],
        edges=[
            GraphEdgeSchema(
                source=e.source_id,
                target=e.target_id,
                relationship=e.edge_type,
                properties=e.properties,
            )
            for e in edges
        ]
    )
