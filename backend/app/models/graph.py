"""Graph Models"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import relationship as orm_relationship
from app.database import Base


class GraphNode(Base):
    """Graph node model for asset relationships."""
    
    __tablename__ = "graph_nodes"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    
    node_id = Column(String(255), nullable=False, index=True)
    node_type = Column(String(50), nullable=False, index=True)  # domain, subdomain, ip, certificate, service, organization
    label = Column(String(255))
    properties = Column(JSON)  # Additional node properties
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan = orm_relationship("Scan", back_populates="graph_nodes")


class GraphEdge(Base):
    """Graph edge model for asset relationships."""
    
    __tablename__ = "graph_edges"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    
    source_id = Column(String(255), nullable=False, index=True)
    target_id = Column(String(255), nullable=False, index=True)
    edge_type = Column(String(100))  # resolves_to, has_cert, runs_service, owns
    properties = Column(JSON)  # Additional edge properties
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan = orm_relationship("Scan", back_populates="graph_edges")
