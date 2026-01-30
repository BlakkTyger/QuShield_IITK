"""Discovery Schemas"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel


class DiscoverySummary(BaseModel):
    """Schema for discovery summary."""
    domains_count: int = 0
    ssl_certs_count: int = 0
    ip_subnets_count: int = 0
    quantum_safe: int = 0
    hybrid: int = 0
    vulnerable: int = 0
    critical: int = 0


class DomainItem(BaseModel):
    """Schema for domain list item."""
    id: str
    fqdn: str
    detection_date: str
    status: str
    ipv4_address: Optional[str]
    ipv6_address: Optional[str]
    asset_type: Optional[str]
    risk_level: Optional[str]


class DomainList(BaseModel):
    """Schema for domain list response."""
    items: List[DomainItem]
    total: int


class GraphNode(BaseModel):
    """Schema for graph node."""
    id: str
    type: str
    label: str
    properties: Optional[Dict[str, Any]] = None


class GraphEdge(BaseModel):
    """Schema for graph edge."""
    source: str
    target: str
    relationship: str
    properties: Optional[Dict[str, Any]] = None


class GraphData(BaseModel):
    """Schema for graph data response."""
    nodes: List[GraphNode]
    edges: List[GraphEdge]
