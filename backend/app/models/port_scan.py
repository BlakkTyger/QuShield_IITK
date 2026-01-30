"""Port Scan Result Model"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base


class PortScanResult(Base):
    """Port scan result model."""
    
    __tablename__ = "port_scan_results"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id = Column(String(36), ForeignKey("assets.id"), nullable=False, index=True)
    
    # Port info
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp")
    state = Column(String(20))  # open, closed, filtered
    
    # Service info
    service_name = Column(String(100))
    service_version = Column(String(100))
    banner = Column(Text)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    asset = relationship("Asset", back_populates="port_scans")
