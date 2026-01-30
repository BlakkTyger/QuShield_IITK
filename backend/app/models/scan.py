"""Scan Models"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, DateTime, ForeignKey, Text
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import relationship
from app.database import Base


class Scan(Base):
    """Scan job model."""
    
    __tablename__ = "scans"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    domain = Column(String(255), nullable=False, index=True)
    status = Column(String(50), default="pending", index=True)  # pending, running, completed, failed
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    duration_ms = Column(Integer)
    assets_discovered = Column(Integer, default=0)
    assets_scanned = Column(Integer, default=0)
    scan_failures = Column(Integer, default=0)
    output_file = Column(String(500))
    error_message = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="scans")
    assets = relationship("Asset", back_populates="scan", cascade="all, delete-orphan")
    dns_records = relationship("DNSRecord", back_populates="scan", cascade="all, delete-orphan")
    graph_nodes = relationship("GraphNode", back_populates="scan", cascade="all, delete-orphan")
    graph_edges = relationship("GraphEdge", back_populates="scan", cascade="all, delete-orphan")
    whois_info = relationship("WhoisInfo", back_populates="scan", cascade="all, delete-orphan")
    summary = relationship("ScanSummary", back_populates="scan", uselist=False, cascade="all, delete-orphan")


class ScanSummary(Base):
    """Scan summary/dashboard data model."""
    
    __tablename__ = "scan_summaries"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"), unique=True, nullable=False)
    
    # Asset counts
    total_assets = Column(Integer, default=0)
    public_web_apps = Column(Integer, default=0)
    apis = Column(Integer, default=0)
    servers = Column(Integer, default=0)
    gateways = Column(Integer, default=0)
    cdns = Column(Integer, default=0)
    
    # Quantum safety counts
    quantum_safe_count = Column(Integer, default=0)
    hybrid_count = Column(Integer, default=0)
    vulnerable_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    
    # Certificate counts
    expiring_certs_30d = Column(Integer, default=0)
    expiring_certs_60d = Column(Integer, default=0)
    expiring_certs_90d = Column(Integer, default=0)
    expired_certs = Column(Integer, default=0)
    
    # IP counts
    ipv4_count = Column(Integer, default=0)
    ipv6_count = Column(Integer, default=0)
    
    # Scores
    enterprise_score = Column(Integer)
    rating_category = Column(String(50))
    average_hndl_score = Column(Float)
    
    # CBOM
    cbom_components = Column(Integer, default=0)
    weak_crypto_count = Column(Integer, default=0)
    
    # Certification counts
    platinum_count = Column(Integer, default=0)
    gold_count = Column(Integer, default=0)
    silver_count = Column(Integer, default=0)
    bronze_count = Column(Integer, default=0)
    
    # Extended metrics
    cloud_assets = Column(Integer, default=0)
    iot_devices = Column(Integer, default=0)
    login_forms = Column(Integer, default=0)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan = relationship("Scan", back_populates="summary")
