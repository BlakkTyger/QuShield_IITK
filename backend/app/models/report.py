"""Report Models"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import relationship
from app.database import Base


class ScheduledReport(Base):
    """Scheduled report model."""
    
    __tablename__ = "scheduled_reports"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    
    # Schedule info
    report_type = Column(String(50), nullable=False)
    frequency = Column(String(50), nullable=False)  # daily, weekly, monthly
    cron_expression = Column(String(100))
    
    # Scope
    selected_scans = Column(JSON)  # List of scan IDs
    included_sections = Column(JSON)  # List of sections to include
    
    # Delivery
    delivery_email = Column(String(255))
    
    # Status
    is_active = Column(Boolean, default=True)
    last_run_at = Column(DateTime)
    next_run_at = Column(DateTime)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="scheduled_reports")


class GeneratedReport(Base):
    """Generated report model."""
    
    __tablename__ = "generated_reports"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    scan_id = Column(String(36), ForeignKey("scans.id"))
    
    # Report info
    report_type = Column(String(50), nullable=False)
    file_path = Column(String(500))
    file_format = Column(String(20), default="pdf")
    file_size = Column(Integer)
    
    # Status
    generated_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    download_count = Column(Integer, default=0)
    
    # Relationships
    user = relationship("User", back_populates="generated_reports")
