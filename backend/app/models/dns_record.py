"""DNS Record Model"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base


class DNSRecord(Base):
    """DNS record model."""
    
    __tablename__ = "dns_records"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    
    # Record info
    hostname = Column(String(255), nullable=False, index=True)
    record_type = Column(String(10), nullable=False, index=True)  # A, AAAA, NS, MX, TXT, CNAME
    value = Column(Text, nullable=False)
    ttl = Column(Integer)
    priority = Column(Integer)  # For MX records
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan = relationship("Scan", back_populates="dns_records")
