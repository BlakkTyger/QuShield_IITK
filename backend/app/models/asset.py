"""Asset Model"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from app.database import Base


class Asset(Base):
    """Discovered asset model."""
    
    __tablename__ = "assets"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    
    # Basic info
    fqdn = Column(String(255), nullable=False, index=True)
    ipv4_address = Column(String(45))
    ipv6_address = Column(String(45))
    port = Column(Integer, default=443)
    
    # Classification
    asset_type = Column(String(50))  # web_app, api, server, gateway, cdn, load_balancer
    discovery_source = Column(String(50))  # ct_logs, subdomain_enum, manual
    status = Column(String(50), default="confirmed")  # new, confirmed, false_positive
    owner = Column(String(255))
    
    # Risk assessment
    risk_level = Column(String(20), index=True)  # critical, high, medium, low
    quantum_safety = Column(String(50))  # FULLY_SAFE, HYBRID, VULNERABLE, CRITICAL
    hndl_score = Column(Float)
    hndl_label = Column(String(50))
    recommended_action = Column(String(500))
    
    # Certification
    cert_tier = Column(String(50))  # PLATINUM, GOLD, SILVER, BRONZE
    
    # Scan result
    scan_success = Column(Boolean, default=False)
    scan_error = Column(String(500))
    
    # Timestamps
    detection_date = Column(DateTime, default=datetime.utcnow)
    last_scan_time = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan = relationship("Scan", back_populates="assets")
    certificates = relationship("Certificate", back_populates="asset", cascade="all, delete-orphan")
    crypto_security = relationship("CryptoSecurity", back_populates="asset", cascade="all, delete-orphan")
    port_scans = relationship("PortScanResult", back_populates="asset", cascade="all, delete-orphan")
    pqc_certifications = relationship("PQCCertification", back_populates="asset", cascade="all, delete-orphan")
