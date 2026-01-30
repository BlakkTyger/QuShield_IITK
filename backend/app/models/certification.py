"""PQC Certification Model"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import relationship
from app.database import Base


class PQCCertification(Base):
    """PQC certification model."""
    
    __tablename__ = "pqc_certifications"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id = Column(String(36), ForeignKey("assets.id"), nullable=False, index=True)
    
    # Certification info
    cert_tier = Column(String(50), nullable=False)  # PLATINUM, GOLD, SILVER, BRONZE
    certification_level = Column(String(50))  # FULLY_QUANTUM_SAFE, PQC_READY, QUANTUM_VULNERABLE
    score = Column(Float)
    
    # Validity
    issued_at = Column(DateTime, default=datetime.utcnow)
    valid_until = Column(DateTime)
    
    # Signature
    signature = Column(Text)  # ML-DSA signature
    signature_algorithm = Column(String(50), default="ML-DSA-87")
    
    # Policy evaluation results
    policy_results = Column(JSON)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    asset = relationship("Asset", back_populates="pqc_certifications")
