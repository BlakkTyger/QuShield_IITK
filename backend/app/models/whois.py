"""WHOIS Info Model"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import relationship
from app.database import Base


class WhoisInfo(Base):
    """WHOIS information model."""
    
    __tablename__ = "whois_info"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    
    # Domain info
    domain = Column(String(255), nullable=False, index=True)
    registrar = Column(String(255))
    
    # Dates
    registration_date = Column(DateTime)
    expiry_date = Column(DateTime)
    updated_date = Column(DateTime)
    
    # Name servers
    name_servers = Column(JSON)  # List of name servers
    
    # Status
    status = Column(JSON)  # List of domain statuses
    
    # Raw data
    raw_data = Column(JSON)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan = relationship("Scan", back_populates="whois_info")
