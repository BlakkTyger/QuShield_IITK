"""Certificate Model"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Boolean, Text
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import relationship
from app.database import Base


class Certificate(Base):
    """SSL/TLS certificate model."""
    
    __tablename__ = "certificates"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id = Column(String(36), ForeignKey("assets.id"), nullable=False, index=True)
    
    # Certificate identifiers
    sha256_fingerprint = Column(String(64), index=True)
    serial_number = Column(String(100))
    
    # Subject info
    subject_cn = Column(String(255))
    subject_org = Column(String(255))
    subject_ou = Column(String(255))
    subject_country = Column(String(10))
    
    # Issuer info
    issuer_cn = Column(String(255))
    issuer_org = Column(String(255))
    certificate_authority = Column(String(255))
    
    # Validity
    valid_from = Column(DateTime)
    valid_until = Column(DateTime, index=True)
    is_expired = Column(Boolean, default=False)
    days_until_expiry = Column(Integer)
    
    # Key info
    key_algorithm = Column(String(100))
    key_size = Column(Integer)
    signature_algorithm = Column(String(100))
    
    # Extensions
    san_entries = Column(JSON)  # List of Subject Alternative Names
    
    # Flags
    is_self_signed = Column(Boolean, default=False)
    is_wildcard = Column(Boolean, default=False)
    is_ev = Column(Boolean, default=False)  # Extended Validation
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    asset = relationship("Asset", back_populates="certificates")
