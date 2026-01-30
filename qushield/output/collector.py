"""
Output Collector Service

Collects, structures, and stores all pipeline outputs in a comprehensive format.
Provides structured JSON output for frontend consumption and logging.

Sections:
- Homepage Dashboard Data
- Assets Inventory
- Asset Directory (Graph Data)
- CBOM Summary
- PQC Compliance Dashboard
- Cyber Rating
- Summary Metrics
"""

import json
import hashlib
import socket
import asyncio
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple
from pathlib import Path
from enum import Enum

from qushield.utils.logging import get_logger, timed
from qushield.services.extended import (
    ExtendedDiscoveryService,
    NameserverRecord,
    MXRecord,
    TXTRecord,
    WHOISInfo,
    PortScanResult,
    ASNInfo,
    GeoIPInfo,
    ServiceInfo,
    FormInfo,
    CloudInfo,
    IoTInfo,
)

logger = get_logger("output_collector")


# ============================================================================
# Asset Type Classification
# ============================================================================

class AssetType(str, Enum):
    """Asset type categories"""
    WEB_APP = "Web Application"
    API = "API"
    SERVER = "Server"
    GATEWAY = "Gateway"
    LOAD_BALANCER = "Load Balancer"
    CDN = "CDN"
    MAIL_SERVER = "Mail Server"
    VPN = "VPN"
    OTHER = "Other"


class AssetTypeClassifier:
    """Classifies assets based on subdomain patterns"""
    
    PATTERNS = {
        AssetType.API: ["api", "api-", "rest", "graphql", "grpc", "ws", "websocket"],
        AssetType.GATEWAY: ["gateway", "gw", "proxy", "edge"],
        AssetType.LOAD_BALANCER: ["lb", "loadbalancer", "haproxy", "nginx-lb"],
        AssetType.CDN: ["cdn", "static", "assets", "img", "images", "media"],
        AssetType.MAIL_SERVER: ["mail", "smtp", "imap", "pop", "mx", "email", "webmail"],
        AssetType.VPN: ["vpn", "remote", "ras", "ssl-vpn"],
        AssetType.WEB_APP: ["www", "web", "app", "portal", "login", "secure", "online",
                           "netbanking", "ibanking", "ebanking", "corporate", "retail"],
    }
    
    @classmethod
    def classify(cls, fqdn: str) -> AssetType:
        """Classify asset type based on FQDN patterns"""
        fqdn_lower = fqdn.lower()
        subdomain = fqdn_lower.split('.')[0] if '.' in fqdn_lower else fqdn_lower
        
        for asset_type, patterns in cls.PATTERNS.items():
            for pattern in patterns:
                if pattern in subdomain:
                    return asset_type
        
        # Default classification
        if subdomain in ["www", ""] or fqdn_lower.count('.') == 1:
            return AssetType.WEB_APP
        
        return AssetType.SERVER


# ============================================================================
# Structured Output Data Models
# ============================================================================

@dataclass
class IPInfo:
    """IP address information"""
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    resolved_at: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "ipv4": self.ipv4,
            "ipv6": self.ipv6,
            "resolved_at": self.resolved_at,
        }


@dataclass
class CertificateOutput:
    """Certificate information for output"""
    detection_date: str = ""
    sha256_fingerprint: str = ""
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    common_name: str = ""
    organization: str = ""
    certificate_authority: str = ""
    public_key_algorithm: str = ""
    public_key_size: Optional[int] = None
    signature_algorithm: str = ""
    san_entries: List[str] = field(default_factory=list)
    is_expired: bool = False
    is_self_signed: bool = False
    days_until_expiry: Optional[int] = None
    expiry_bucket: str = ""  # 0-30, 30-60, 60-90, 90+
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AssetStatus(str, Enum):
    """Asset status classifications"""
    NEW = "New"
    CONFIRMED = "Confirmed"
    IGNORED = "Ignored"
    FALSE_POSITIVE = "False Positive"


class CertificateStatus(str, Enum):
    """Certificate status classifications"""
    VALID = "Valid"
    EXPIRED = "Expired"
    EXPIRING_SOON = "Expiring Soon"
    SELF_SIGNED = "Self-Signed"
    UNKNOWN = "Unknown"


@dataclass
class AssetInventoryItem:
    """Single asset in the inventory"""
    # Core identification
    asset_name: str
    url: str
    fqdn: str
    port: int = 443
    
    # IP information
    ipv4_address: Optional[str] = None
    ipv6_address: Optional[str] = None
    
    # ASN/GeoIP information
    asn: Optional[int] = None
    asn_name: str = ""
    country: str = ""
    country_code: str = ""
    city: str = ""
    isp: str = ""
    
    # Classification
    asset_type: str = "Other"
    owner: str = ""
    status: str = "Confirmed"  # Default status
    
    # Cloud/IoT detection
    is_cloud_hosted: bool = False
    cloud_provider: str = ""
    cdn_provider: str = ""
    is_iot_device: bool = False
    iot_device_type: str = ""
    
    # Open ports and services
    open_ports: List[int] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    
    # Risk assessment
    risk_level: str = "Unknown"
    hndl_score: Optional[float] = None
    quantum_safety: str = "Unknown"
    
    # Certificate info
    certificate_status: str = "Unknown"
    key_length: Optional[int] = None
    
    # Timing
    detection_date: str = ""
    last_scan_time: str = ""
    
    # Discovery source
    discovery_source: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DNSRecord:
    """DNS record information"""
    hostname: str
    record_type: str  # A, AAAA, NS, MX, CNAME, TXT
    value: str
    ipv4_address: Optional[str] = None
    ipv6_address: Optional[str] = None
    ttl: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass 
class CryptoSecurityItem:
    """Crypto & Security table item"""
    asset: str
    key_length: Optional[int] = None
    cipher_suite: str = ""
    tls_version: str = ""
    certificate_authority: str = ""
    last_scan_time: str = ""
    quantum_safety: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GraphNode:
    """Node in the asset relationship graph"""
    id: str
    label: str
    node_type: str  # domain, subdomain, ip, certificate, service, organization
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GraphEdge:
    """Edge in the asset relationship graph"""
    source: str
    target: str
    relationship: str  # resolves_to, has_certificate, runs_service, owns
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CyberRating:
    """Cyber rating calculation"""
    enterprise_score: int = 0  # 0-1000
    category: str = "Legacy"  # Legacy, Standard, Elite
    per_url_scores: Dict[str, int] = field(default_factory=dict)
    factors: Dict[str, float] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ============================================================================
# Dashboard Summary Models
# ============================================================================

@dataclass
class DashboardSummary:
    """Homepage dashboard summary data"""
    # Counts
    total_assets: int = 0
    public_web_apps: int = 0
    apis: int = 0
    servers: int = 0
    expiring_certificates: int = 0
    high_risk_assets: int = 0
    
    # Distributions
    asset_type_distribution: Dict[str, int] = field(default_factory=dict)
    risk_distribution: Dict[str, int] = field(default_factory=dict)
    certificate_expiry_timeline: Dict[str, int] = field(default_factory=dict)
    ip_version_breakdown: Dict[str, float] = field(default_factory=dict)
    
    # Lists for detailed views
    asset_list: List[str] = field(default_factory=list)
    web_app_list: List[str] = field(default_factory=list)
    api_list: List[str] = field(default_factory=list)
    server_list: List[str] = field(default_factory=list)
    expiring_cert_list: List[Dict] = field(default_factory=list)
    high_risk_list: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "counts": {
                "total_assets": self.total_assets,
                "public_web_apps": self.public_web_apps,
                "apis": self.apis,
                "servers": self.servers,
                "expiring_certificates": self.expiring_certificates,
                "high_risk_assets": self.high_risk_assets,
            },
            "distributions": {
                "asset_type": self.asset_type_distribution,
                "risk": self.risk_distribution,
                "certificate_expiry_timeline": self.certificate_expiry_timeline,
                "ip_version_breakdown": self.ip_version_breakdown,
            },
            "lists": {
                "all_assets": self.asset_list,
                "web_apps": self.web_app_list,
                "apis": self.api_list,
                "servers": self.server_list,
                "expiring_certificates": self.expiring_cert_list,
                "high_risk_assets": self.high_risk_list,
            }
        }


@dataclass
class CBOMSummary:
    """CBOM dashboard summary"""
    total_applications: int = 0
    active_certificates: int = 0
    weak_cryptography_count: int = 0
    certificate_issues: int = 0
    key_length_distribution: Dict[str, int] = field(default_factory=dict)
    cipher_usage_distribution: Dict[str, int] = field(default_factory=dict)
    top_certificate_authorities: List[Dict[str, Any]] = field(default_factory=list)
    protocol_distribution: Dict[str, int] = field(default_factory=dict)
    per_app_crypto: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PQCComplianceSummary:
    """PQC Compliance dashboard summary"""
    assets_with_pqc_support: List[Dict[str, Any]] = field(default_factory=list)
    classification_counts: Dict[str, int] = field(default_factory=dict)
    status_distribution: Dict[str, int] = field(default_factory=dict)
    risk_heatmap: List[Dict[str, Any]] = field(default_factory=list)
    pqc_adoption_progress: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SummaryMetrics:
    """Overall summary metrics"""
    total_domains: int = 0
    total_subdomains: int = 0
    cloud_assets_count: int = 0
    ssl_certificates_count: int = 0
    software_count: int = 0
    iot_devices_count: int = 0
    login_forms_count: int = 0
    vulnerable_components_count: int = 0
    pqc_adoption_progress: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ============================================================================
# Main Output Collector
# ============================================================================

@dataclass
class StructuredOutput:
    """Complete structured output for the pipeline"""
    # Metadata
    scan_id: str = ""
    domain: str = ""
    scan_start: str = ""
    scan_end: str = ""
    duration_ms: float = 0.0
    
    # Dashboard
    dashboard: DashboardSummary = field(default_factory=DashboardSummary)
    
    # Inventory
    asset_inventory: List[AssetInventoryItem] = field(default_factory=list)
    certificates: List[CertificateOutput] = field(default_factory=list)
    dns_records: List[DNSRecord] = field(default_factory=list)
    crypto_security: List[CryptoSecurityItem] = field(default_factory=list)
    
    # Extended DNS records (NS, MX, TXT)
    ns_records: List[Dict[str, Any]] = field(default_factory=list)
    mx_records: List[Dict[str, Any]] = field(default_factory=list)
    txt_records: List[Dict[str, Any]] = field(default_factory=list)
    
    # WHOIS information
    whois_info: Optional[Dict[str, Any]] = None
    
    # Port scan and services
    port_scan_results: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    
    # Cloud and IoT detection
    cloud_assets: List[Dict[str, Any]] = field(default_factory=list)
    iot_devices: List[Dict[str, Any]] = field(default_factory=list)
    
    # Form detection
    forms_detected: List[Dict[str, Any]] = field(default_factory=list)
    
    # Graph data
    graph_nodes: List[GraphNode] = field(default_factory=list)
    graph_edges: List[GraphEdge] = field(default_factory=list)
    
    # Summaries
    cbom_summary: CBOMSummary = field(default_factory=CBOMSummary)
    pqc_compliance: PQCComplianceSummary = field(default_factory=PQCComplianceSummary)
    cyber_rating: CyberRating = field(default_factory=CyberRating)
    summary_metrics: SummaryMetrics = field(default_factory=SummaryMetrics)
    
    # Raw layer outputs
    layer1_output: Dict[str, Any] = field(default_factory=dict)
    layer2_output: Dict[str, Any] = field(default_factory=dict)
    layer3_output: Dict[str, Any] = field(default_factory=dict)
    layer4_output: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "metadata": {
                "scan_id": self.scan_id,
                "domain": self.domain,
                "scan_start": self.scan_start,
                "scan_end": self.scan_end,
                "duration_ms": self.duration_ms,
            },
            "dashboard": self.dashboard.to_dict(),
            "inventory": {
                "assets": [a.to_dict() for a in self.asset_inventory],
                "certificates": [c.to_dict() for c in self.certificates],
                "dns_records": [d.to_dict() for d in self.dns_records],
                "crypto_security": [c.to_dict() for c in self.crypto_security],
            },
            "nameserver_records": {
                "ns_records": self.ns_records,
                "mx_records": self.mx_records,
                "txt_records": self.txt_records,
            },
            "whois": self.whois_info,
            "port_scan": {
                "results": self.port_scan_results,
                "services": self.services,
            },
            "detection": {
                "cloud_assets": self.cloud_assets,
                "iot_devices": self.iot_devices,
                "forms": self.forms_detected,
            },
            "graph": {
                "nodes": [n.to_dict() for n in self.graph_nodes],
                "edges": [e.to_dict() for e in self.graph_edges],
            },
            "summaries": {
                "cbom": self.cbom_summary.to_dict(),
                "pqc_compliance": self.pqc_compliance.to_dict(),
                "cyber_rating": self.cyber_rating.to_dict(),
                "metrics": self.summary_metrics.to_dict(),
            },
            "layer_outputs": {
                "layer1_discovery": self.layer1_output,
                "layer2_scanning": self.layer2_output,
                "layer3_analysis": self.layer3_output,
                "layer4_certification": self.layer4_output,
            }
        }
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


class OutputCollector:
    """
    Collects and structures all pipeline outputs.
    
    Integrates with all 4 layers to gather comprehensive data
    for frontend consumption.
    """
    
    OUTPUT_DIR = Path("outputs")
    
    def __init__(self, enable_extended_discovery: bool = True):
        self.output = StructuredOutput()
        self.ip_cache: Dict[str, IPInfo] = {}
        self.enable_extended_discovery = enable_extended_discovery
        self.extended_discovery = ExtendedDiscoveryService() if enable_extended_discovery else None
        self._ensure_output_dir()
        logger.info("OutputCollector initialized", extra={
            "extended_discovery": enable_extended_discovery
        })
    
    def _ensure_output_dir(self):
        """Ensure output directory exists"""
        self.OUTPUT_DIR.mkdir(exist_ok=True)
    
    def start_scan(self, domain: str):
        """Initialize a new scan"""
        import uuid
        self.output = StructuredOutput(
            scan_id=str(uuid.uuid4()),
            domain=domain,
            scan_start=datetime.now(timezone.utc).isoformat(),
        )
        logger.info(f"Started output collection for {domain}", extra={
            "data": {"scan_id": self.output.scan_id}
        })
    
    def end_scan(self):
        """Finalize the scan"""
        self.output.scan_end = datetime.now(timezone.utc).isoformat()
        # Calculate duration
        start = datetime.fromisoformat(self.output.scan_start.replace('Z', '+00:00'))
        end = datetime.fromisoformat(self.output.scan_end.replace('Z', '+00:00'))
        self.output.duration_ms = (end - start).total_seconds() * 1000
        logger.info(f"Completed output collection", extra={
            "data": {"duration_ms": self.output.duration_ms}
        })
    
    # ========================================================================
    # IP Resolution
    # ========================================================================
    
    async def resolve_ip(self, hostname: str) -> IPInfo:
        """Resolve hostname to IP addresses"""
        if hostname in self.ip_cache:
            return self.ip_cache[hostname]
        
        ip_info = IPInfo(resolved_at=datetime.now(timezone.utc).isoformat())
        
        try:
            loop = asyncio.get_event_loop()
            # Get IPv4
            try:
                task = loop.getaddrinfo(hostname, 443, family=socket.AF_INET)
                results = await asyncio.wait_for(task, timeout=2.0)
                if results:
                    ip_info.ipv4 = results[0][4][0]
            except (socket.gaierror, asyncio.TimeoutError):
                pass
            
            # Get IPv6
            try:
                task = loop.getaddrinfo(hostname, 443, family=socket.AF_INET6)
                results = await asyncio.wait_for(task, timeout=2.0)
                if results:
                    ip_info.ipv6 = results[0][4][0]
            except (socket.gaierror, asyncio.TimeoutError):
                pass
                
        except Exception as e:
            logger.debug(f"IP resolution failed for {hostname}: {e}")
        
        self.ip_cache[hostname] = ip_info
        return ip_info
    
    # ========================================================================
    # DNS Record Extraction
    # ========================================================================
    
    async def resolve_dns_records(self, domain: str) -> List[DNSRecord]:
        """Resolve DNS records for a domain (A, AAAA, NS, MX)"""
        records = []
        loop = asyncio.get_event_loop()
        
        try:
            # A records (IPv4)
            try:
                results = await loop.getaddrinfo(domain, None, family=socket.AF_INET)
                for result in results[:5]:  # Limit to 5
                    ip = result[4][0]
                    records.append(DNSRecord(
                        hostname=domain,
                        record_type="A",
                        value=ip,
                        ipv4_address=ip,
                    ))
            except socket.gaierror:
                pass
            
            # AAAA records (IPv6)
            try:
                results = await loop.getaddrinfo(domain, None, family=socket.AF_INET6)
                for result in results[:5]:
                    ip = result[4][0]
                    records.append(DNSRecord(
                        hostname=domain,
                        record_type="AAAA",
                        value=ip,
                        ipv6_address=ip,
                    ))
            except socket.gaierror:
                pass
                
        except Exception as e:
            logger.debug(f"DNS record extraction failed for {domain}: {e}")
        
        return records
    
    # ========================================================================
    # Organization Extraction
    # ========================================================================
    
    def _extract_organization_from_cert(self, cert: Any) -> Optional[str]:
        """Extract organization name from certificate subject"""
        if not cert or not cert.subject:
            return None
        
        subject = cert.subject
        # Parse O= field from subject
        if "O=" in subject:
            parts = subject.split(",")
            for part in parts:
                part = part.strip()
                if part.startswith("O="):
                    return part[2:].strip()
        return None
    
    def _add_organization_node(self, org_name: str, cert_node_id: str):
        """Add organization node and edge to graph"""
        if not org_name:
            return
        
        org_node_id = f"org:{org_name.lower().replace(' ', '_')[:30]}"
        
        # Add org node if not exists
        if not any(n.id == org_node_id for n in self.output.graph_nodes):
            self.output.graph_nodes.append(GraphNode(
                id=org_node_id,
                label=org_name,
                node_type="organization",
                metadata={"name": org_name}
            ))
        
        # Add edge from org to cert
        self.output.graph_edges.append(GraphEdge(
            source=org_node_id,
            target=cert_node_id,
            relationship="owns_certificate"
        ))
    
    # ========================================================================
    # Layer 1: Discovery Output Collection
    # ========================================================================
    
    @timed(logger=logger, layer=1)
    async def collect_layer1(self, assets: List[Any]):
        """Collect Layer 1 discovery outputs"""
        logger.info(f"Collecting Layer 1 outputs for {len(assets)} assets")
        
        # Resolve all IPs concurrently with a semaphore
        semaphore = asyncio.Semaphore(15)
        
        async def resolve_with_sem(hostname):
            async with semaphore:
                return await self.resolve_ip(hostname)
                
        ip_infos = await asyncio.gather(*[resolve_with_sem(a.fqdn) for a in assets])
        
        discovered_assets = []
        for asset, ip_info in zip(assets, ip_infos):
            
            # Classify asset type
            asset_type = AssetTypeClassifier.classify(asset.fqdn)
            
            # Create inventory item
            inventory_item = AssetInventoryItem(
                asset_name=asset.fqdn.split('.')[0],
                url=f"https://{asset.fqdn}:{asset.port}",
                fqdn=asset.fqdn,
                port=asset.port,
                ipv4_address=ip_info.ipv4,
                ipv6_address=ip_info.ipv6,
                asset_type=asset_type.value,
                detection_date=asset.discovered_at.isoformat() if asset.discovered_at else "",
                discovery_source=asset.source,
            )
            self.output.asset_inventory.append(inventory_item)
            
            discovered_assets.append({
                "fqdn": asset.fqdn,
                "port": asset.port,
                "source": asset.source,
                "discovered_at": asset.discovered_at.isoformat() if asset.discovered_at else "",
                "ipv4": ip_info.ipv4,
                "ipv6": ip_info.ipv6,
                "asset_type": asset_type.value,
            })
            
            # Add graph nodes
            self._add_discovery_graph_nodes(asset, ip_info, asset_type)
        
        # Extract DNS records for base domain
        if assets:
            base_domain = self.output.domain
            dns_records = await self.resolve_dns_records(base_domain)
            self.output.dns_records.extend(dns_records)
        
        # Store raw layer output
        self.output.layer1_output = {
            "total_discovered": len(assets),
            "sources": list(set(a.source for a in assets)),
            "assets": discovered_assets,
            "dns_records": [r.to_dict() for r in self.output.dns_records],
        }
        
        # Update dashboard counts
        self._update_dashboard_from_layer1(assets)
        
        logger.info(f"Layer 1 collection complete: {len(assets)} assets, {len(self.output.dns_records)} DNS records")
    
    def _add_discovery_graph_nodes(self, asset: Any, ip_info: IPInfo, asset_type: AssetType):
        """Add graph nodes for discovered assets"""
        # Domain node
        domain_parts = asset.fqdn.split('.')
        base_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) >= 2 else asset.fqdn
        
        # Add domain node if not exists
        domain_node_id = f"domain:{base_domain}"
        if not any(n.id == domain_node_id for n in self.output.graph_nodes):
            self.output.graph_nodes.append(GraphNode(
                id=domain_node_id,
                label=base_domain,
                node_type="domain",
                metadata={"fqdn": base_domain}
            ))
        
        # Add subdomain node
        if asset.fqdn != base_domain:
            subdomain_node_id = f"subdomain:{asset.fqdn}"
            self.output.graph_nodes.append(GraphNode(
                id=subdomain_node_id,
                label=asset.fqdn,
                node_type="subdomain",
                metadata={
                    "fqdn": asset.fqdn,
                    "asset_type": asset_type.value,
                }
            ))
            # Add edge from domain to subdomain
            self.output.graph_edges.append(GraphEdge(
                source=domain_node_id,
                target=subdomain_node_id,
                relationship="has_subdomain"
            ))
        
        # Add IP nodes and edges
        if ip_info.ipv4:
            ip_node_id = f"ip:{ip_info.ipv4}"
            if not any(n.id == ip_node_id for n in self.output.graph_nodes):
                self.output.graph_nodes.append(GraphNode(
                    id=ip_node_id,
                    label=ip_info.ipv4,
                    node_type="ip",
                    metadata={"version": "IPv4"}
                ))
            self.output.graph_edges.append(GraphEdge(
                source=f"subdomain:{asset.fqdn}" if asset.fqdn != base_domain else domain_node_id,
                target=ip_node_id,
                relationship="resolves_to"
            ))
    
    def _update_dashboard_from_layer1(self, assets: List[Any]):
        """Update dashboard summary from Layer 1 data"""
        self.output.dashboard.total_assets = len(assets)
        self.output.dashboard.asset_list = [a.fqdn for a in assets]
        
        # Count by type
        type_counts: Dict[str, int] = {}
        for item in self.output.asset_inventory:
            type_counts[item.asset_type] = type_counts.get(item.asset_type, 0) + 1
        
        self.output.dashboard.asset_type_distribution = type_counts
        self.output.dashboard.public_web_apps = type_counts.get(AssetType.WEB_APP.value, 0)
        self.output.dashboard.apis = type_counts.get(AssetType.API.value, 0)
        self.output.dashboard.servers = type_counts.get(AssetType.SERVER.value, 0)
        
        self.output.dashboard.web_app_list = [
            i.fqdn for i in self.output.asset_inventory 
            if i.asset_type == AssetType.WEB_APP.value
        ]
        self.output.dashboard.api_list = [
            i.fqdn for i in self.output.asset_inventory 
            if i.asset_type == AssetType.API.value
        ]
        self.output.dashboard.server_list = [
            i.fqdn for i in self.output.asset_inventory 
            if i.asset_type == AssetType.SERVER.value
        ]
        
        # IP version breakdown
        ipv4_count = sum(1 for i in self.output.asset_inventory if i.ipv4_address)
        ipv6_count = sum(1 for i in self.output.asset_inventory if i.ipv6_address)
        total_ips = ipv4_count + ipv6_count
        if total_ips > 0:
            self.output.dashboard.ip_version_breakdown = {
                "IPv4": round(ipv4_count / total_ips * 100, 1),
                "IPv6": round(ipv6_count / total_ips * 100, 1),
            }
        
        # Update summary metrics
        self.output.summary_metrics.total_domains = 1
        self.output.summary_metrics.total_subdomains = len(assets) - 1
    
    # ========================================================================
    # Extended Discovery Collection
    # ========================================================================
    
    async def collect_extended_discovery(self, assets: List[Any]):
        """Collect extended discovery data: WHOIS, NS/MX/TXT, ports, ASN/GeoIP, services, cloud/IoT"""
        if not self.extended_discovery:
            logger.info("Extended discovery disabled, skipping")
            return
        
        logger.info(f"Starting extended discovery for {len(assets)} assets")
        
        # Collect WHOIS info for base domain
        await self._collect_whois()
        
        # Collect NS, MX, TXT records
        await self._collect_nameserver_records()
        
        # Collect port scans, ASN/GeoIP, services, cloud/IoT for each asset
        await self._collect_asset_details(assets)
        
        # Update summary metrics
        self._update_extended_metrics()
        
        logger.info("Extended discovery collection complete")
    
    async def _collect_whois(self):
        """Collect WHOIS information for domain"""
        try:
            whois_info = await self.extended_discovery.whois_lookup(self.output.domain)
            if whois_info:
                self.output.whois_info = whois_info.to_dict()
                logger.info(f"WHOIS collected for {self.output.domain}", extra={
                    "registrar": whois_info.registrar,
                    "organization": whois_info.organization
                })
        except Exception as e:
            logger.warning(f"WHOIS collection failed: {e}")
    
    async def _collect_nameserver_records(self):
        """Collect NS, MX, TXT records"""
        try:
            dns_data = await self.extended_discovery.resolve_all_dns_records(self.output.domain)
            
            # NS records
            for ns in dns_data.get("ns_records", []):
                self.output.ns_records.append(ns.to_dict())
                # Add NS node to graph
                ns_node_id = f"ns:{ns.nameserver}"
                if not any(n.id == ns_node_id for n in self.output.graph_nodes):
                    self.output.graph_nodes.append(GraphNode(
                        id=ns_node_id,
                        label=ns.nameserver,
                        node_type="nameserver",
                        metadata={"ip": ns.ip_address}
                    ))
                    self.output.graph_edges.append(GraphEdge(
                        source=f"domain:{self.output.domain.split('.')[-2]}.{self.output.domain.split('.')[-1]}",
                        target=ns_node_id,
                        relationship="uses_nameserver"
                    ))
            
            # MX records
            for mx in dns_data.get("mx_records", []):
                self.output.mx_records.append(mx.to_dict())
                # Add MX node to graph
                mx_node_id = f"mx:{mx.mail_server}"
                if not any(n.id == mx_node_id for n in self.output.graph_nodes):
                    self.output.graph_nodes.append(GraphNode(
                        id=mx_node_id,
                        label=mx.mail_server,
                        node_type="mail_server",
                        metadata={"priority": mx.priority, "ip": mx.ip_address}
                    ))
                    self.output.graph_edges.append(GraphEdge(
                        source=f"domain:{self.output.domain.split('.')[-2]}.{self.output.domain.split('.')[-1]}",
                        target=mx_node_id,
                        relationship="uses_mail_server"
                    ))
            
            # TXT records
            for txt in dns_data.get("txt_records", []):
                self.output.txt_records.append(txt.to_dict())
            
            logger.info(f"DNS records collected: {len(self.output.ns_records)} NS, {len(self.output.mx_records)} MX, {len(self.output.txt_records)} TXT")
            
        except Exception as e:
            logger.warning(f"Nameserver records collection failed: {e}")
    
    async def _collect_asset_details(self, assets: List[Any]):
        """Collect detailed info for each asset: ports, ASN/GeoIP, services, cloud/IoT"""
        # Process all assets concurrently with semaphore for rate limiting
        semaphore = asyncio.Semaphore(10)  # Limit concurrent lookups
        
        async def process_asset(item):
            async with semaphore:
                await self._collect_single_asset_details(item)
        
        tasks = [process_asset(item) for item in self.output.asset_inventory]
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _collect_single_asset_details(self, item):
        """Collect detailed info for a single asset"""
        try:
            # Try to resolve IP if not already resolved
            ip = item.ipv4_address
            if not ip:
                ip_info = await self.resolve_ip(item.fqdn)
                item.ipv4_address = ip_info.ipv4
                item.ipv6_address = ip_info.ipv6
                ip = ip_info.ipv4
            
            if not ip:
                return  # Skip if still no IP
                
            # ASN lookup
            asn_info = await self.extended_discovery.asn_lookup(ip)
            if asn_info:
                item.asn = asn_info.asn
                item.asn_name = asn_info.asn_name
                item.country_code = asn_info.country
            
            # GeoIP lookup
            geoip_info = await self.extended_discovery.geoip_lookup(ip)
            if geoip_info:
                item.country = geoip_info.country
                item.country_code = geoip_info.country_code or item.country_code
                item.city = geoip_info.city
                item.isp = geoip_info.isp or geoip_info.organization
            
            # Skip port scan for performance - just check 443
            # Port scan is very slow and most banking sites only expose 443
            item.open_ports = [443]
            
            # Cloud detection
            cloud_info = await self.extended_discovery.detect_cloud(item.fqdn, ip)
            if cloud_info and cloud_info.is_cloud_hosted:
                item.is_cloud_hosted = True
                item.cloud_provider = cloud_info.cloud_provider
                item.cdn_provider = cloud_info.cdn_provider
                self.output.cloud_assets.append(cloud_info.to_dict())
            
        except Exception as e:
            logger.debug(f"Extended discovery failed for {item.fqdn}: {e}")
    
    async def collect_form_detection(self, assets: List[Any]):
        """Detect forms on web assets"""
        if not self.extended_discovery:
            return
        
        for item in self.output.asset_inventory[:10]:  # Limit for performance
            if item.asset_type in ["Web Application", "Server"]:
                try:
                    url = f"https://{item.fqdn}"
                    form_info = await self.extended_discovery.detect_forms(url)
                    if form_info and form_info.form_count > 0:
                        self.output.forms_detected.append(form_info.to_dict())
                        if form_info.has_login_form:
                            self.output.summary_metrics.login_forms_count += 1
                except Exception as e:
                    logger.debug(f"Form detection failed for {item.fqdn}: {e}")
    
    def _update_extended_metrics(self):
        """Update summary metrics from extended discovery"""
        self.output.summary_metrics.cloud_assets_count = len(self.output.cloud_assets)
        self.output.summary_metrics.iot_devices_count = len(self.output.iot_devices)
        self.output.summary_metrics.software_count = len(self.output.services)
    
    # ========================================================================
    # Layer 2: TLS Scanning Output Collection
    # ========================================================================
    
    @timed(logger=logger, layer=2)
    def collect_layer2(self, scan_results: List[Tuple[str, Any]]):
        """Collect Layer 2 TLS scanning outputs"""
        logger.info(f"Collecting Layer 2 outputs for {len(scan_results)} scans")
        
        scan_outputs = []
        cert_count = 0
        weak_crypto_count = 0
        cert_issues = 0
        key_lengths: Dict[str, int] = {}
        cipher_usage: Dict[str, int] = {}
        cas: Dict[str, int] = {}
        tls_versions: Dict[str, int] = {"TLS 1.0": 0, "TLS 1.1": 0, "TLS 1.2": 0, "TLS 1.3": 0}
        
        for fqdn, scan_result in scan_results:
            if scan_result is None or scan_result.status.value != "success":
                continue
            
            # Process certificate
            if scan_result.certificate:
                cert = scan_result.certificate
                cert_count += 1
                
                # Calculate fingerprint
                fingerprint = self._calculate_cert_fingerprint(cert)
                
                # Calculate days until expiry and bucket
                days_until_expiry, expiry_bucket = self._calculate_expiry_info(cert.not_after)
                
                # Parse organization from subject
                org = self._parse_org_from_subject(cert.subject)
                
                cert_output = CertificateOutput(
                    detection_date=scan_result.scan_time,
                    sha256_fingerprint=fingerprint,
                    valid_from=cert.not_before,
                    valid_until=cert.not_after,
                    common_name=cert.subject,
                    organization=org,
                    certificate_authority=cert.issuer,
                    public_key_algorithm=cert.public_key_algorithm,
                    public_key_size=cert.public_key_size,
                    signature_algorithm=cert.signature_algorithm,
                    san_entries=cert.san_entries,
                    is_expired=cert.is_expired,
                    is_self_signed=cert.is_self_signed,
                    days_until_expiry=days_until_expiry,
                    expiry_bucket=expiry_bucket,
                )
                self.output.certificates.append(cert_output)
                
                # Track issues
                if cert.is_expired or cert.is_self_signed:
                    cert_issues += 1
                
                # Track key lengths
                if cert.public_key_size:
                    key_str = f"{cert.public_key_size}-bit"
                    key_lengths[key_str] = key_lengths.get(key_str, 0) + 1
                
                # Track CAs
                ca_name = self._extract_ca_name(cert.issuer)
                cas[ca_name] = cas.get(ca_name, 0) + 1
                
                # Add certificate graph node
                cert_node_id = f"cert:{fingerprint[:16]}"
                self.output.graph_nodes.append(GraphNode(
                    id=cert_node_id,
                    label=cert.subject[:50],
                    node_type="certificate",
                    metadata={
                        "issuer": cert.issuer,
                        "valid_until": cert.not_after,
                        "algorithm": cert.public_key_algorithm,
                        "organization": org,
                    }
                ))
                # Edge from domain to cert
                self.output.graph_edges.append(GraphEdge(
                    source=f"subdomain:{fqdn}",
                    target=cert_node_id,
                    relationship="has_certificate"
                ))
                
                # Add organization node from certificate
                if org:
                    self._add_organization_node(org, cert_node_id)
            
            # Track TLS versions
            if scan_result.supports_tls10:
                tls_versions["TLS 1.0"] += 1
            if scan_result.supports_tls11:
                tls_versions["TLS 1.1"] += 1
            if scan_result.supports_tls12:
                tls_versions["TLS 1.2"] += 1
            if scan_result.supports_tls13:
                tls_versions["TLS 1.3"] += 1
            
            # Check for weak crypto
            if scan_result.supports_tls10 or scan_result.supports_tls11:
                weak_crypto_count += 1
            
            # Track cipher usage
            for cipher in scan_result.tls12_cipher_suites + scan_result.tls13_cipher_suites:
                cipher_base = cipher.split('_')[1] if '_' in cipher else cipher
                cipher_usage[cipher_base] = cipher_usage.get(cipher_base, 0) + 1
            
            # Create crypto security item
            best_tls = "TLS 1.3" if scan_result.supports_tls13 else \
                       "TLS 1.2" if scan_result.supports_tls12 else \
                       "TLS 1.1" if scan_result.supports_tls11 else "TLS 1.0"
            
            crypto_item = CryptoSecurityItem(
                asset=fqdn,
                key_length=scan_result.certificate.public_key_size if scan_result.certificate else None,
                cipher_suite=scan_result.tls12_cipher_suites[0] if scan_result.tls12_cipher_suites else "",
                tls_version=best_tls,
                certificate_authority=self._extract_ca_name(scan_result.certificate.issuer) if scan_result.certificate else "",
                last_scan_time=scan_result.scan_time,
            )
            self.output.crypto_security.append(crypto_item)
            
            # Update inventory item
            for item in self.output.asset_inventory:
                if item.fqdn == fqdn:
                    item.last_scan_time = scan_result.scan_time
                    if scan_result.certificate:
                        item.key_length = scan_result.certificate.public_key_size
                        item.certificate_status = "Expired" if scan_result.certificate.is_expired else "Valid"
                    break
            
            scan_outputs.append(scan_result.to_dict())
        
        # Store raw layer output
        self.output.layer2_output = {
            "total_scanned": len(scan_results),
            "successful_scans": len([s for _, s in scan_results if s and s.status.value == "success"]),
            "certificates_found": cert_count,
            "scans": scan_outputs,
        }
        
        # Update CBOM summary
        self.output.cbom_summary.total_applications = len(scan_results)
        self.output.cbom_summary.active_certificates = cert_count
        self.output.cbom_summary.weak_cryptography_count = weak_crypto_count
        self.output.cbom_summary.certificate_issues = cert_issues
        self.output.cbom_summary.key_length_distribution = key_lengths
        self.output.cbom_summary.cipher_usage_distribution = dict(sorted(cipher_usage.items(), key=lambda x: x[1], reverse=True)[:10])
        self.output.cbom_summary.protocol_distribution = tls_versions
        
        # Top CAs
        self.output.cbom_summary.top_certificate_authorities = [
            {"name": ca, "count": count}
            for ca, count in sorted(cas.items(), key=lambda x: x[1], reverse=True)[:5]
        ]
        
        # Update dashboard certificate expiry timeline
        self._update_cert_expiry_timeline()
        
        # Update summary metrics
        self.output.summary_metrics.ssl_certificates_count = cert_count
        
        logger.info(f"Layer 2 collection complete: {cert_count} certificates")
    
    def _calculate_cert_fingerprint(self, cert: Any) -> str:
        """Calculate SHA256 fingerprint for certificate"""
        cert_data = f"{cert.subject}:{cert.issuer}:{cert.serial_number}:{cert.not_after}"
        return hashlib.sha256(cert_data.encode()).hexdigest()
    
    def _calculate_expiry_info(self, not_after: Optional[str]) -> Tuple[Optional[int], str]:
        """Calculate days until expiry and bucket"""
        if not not_after:
            return None, "Unknown"
        
        try:
            expiry = datetime.fromisoformat(not_after.replace('Z', '+00:00'))
            now = datetime.now(timezone.utc)
            days = (expiry - now).days
            
            if days < 0:
                bucket = "Expired"
            elif days <= 30:
                bucket = "0-30 days"
            elif days <= 60:
                bucket = "30-60 days"
            elif days <= 90:
                bucket = "60-90 days"
            else:
                bucket = "90+ days"
            
            return days, bucket
        except:
            return None, "Unknown"
    
    def _parse_org_from_subject(self, subject: str) -> str:
        """Parse organization from certificate subject"""
        if "O=" in subject:
            parts = subject.split(",")
            for part in parts:
                if part.strip().startswith("O="):
                    return part.strip()[2:]
        return ""
    
    def _extract_ca_name(self, issuer: str) -> str:
        """Extract CA name from issuer string"""
        if "CN=" in issuer:
            parts = issuer.split(",")
            for part in parts:
                if part.strip().startswith("CN="):
                    return part.strip()[3:]
        return issuer[:30] if issuer else "Unknown"
    
    def _update_cert_expiry_timeline(self):
        """Update certificate expiry timeline in dashboard"""
        timeline = {"0-30 days": 0, "30-60 days": 0, "60-90 days": 0, "90+ days": 0, "Expired": 0}
        expiring_list = []
        
        for cert in self.output.certificates:
            if cert.expiry_bucket in timeline:
                timeline[cert.expiry_bucket] += 1
            
            if cert.expiry_bucket in ["0-30 days", "30-60 days", "60-90 days", "Expired"]:
                expiring_list.append({
                    "common_name": cert.common_name,
                    "days_until_expiry": cert.days_until_expiry,
                    "bucket": cert.expiry_bucket,
                })
        
        self.output.dashboard.certificate_expiry_timeline = timeline
        self.output.dashboard.expiring_certificates = timeline["0-30 days"] + timeline["Expired"]
        self.output.dashboard.expiring_cert_list = expiring_list
    
    # ========================================================================
    # Layer 3: PQC Analysis Output Collection
    # ========================================================================
    
    @timed(logger=logger, layer=3)
    def collect_layer3(self, analysis_results: List[Any], cbom: Any = None):
        """Collect Layer 3 PQC analysis outputs"""
        logger.info(f"Collecting Layer 3 outputs for {len(analysis_results)} analyses")
        
        analysis_outputs = []
        risk_distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        pqc_assets = []
        risk_heatmap = []
        
        for asset in analysis_results:
            if not asset.scan_success:
                continue
            
            # Update inventory item
            for item in self.output.asset_inventory:
                if item.fqdn == asset.fqdn:
                    item.risk_level = asset.hndl_score.label.value if asset.hndl_score else "Unknown"
                    item.hndl_score = asset.hndl_score.score if asset.hndl_score else None
                    item.quantum_safety = asset.quantum_safety
                    break
            
            # Update crypto security item
            for item in self.output.crypto_security:
                if item.asset == asset.fqdn:
                    item.quantum_safety = asset.quantum_safety
                    break
            
            # Track risk distribution
            if asset.hndl_score:
                risk_distribution[asset.hndl_score.label.value] = \
                    risk_distribution.get(asset.hndl_score.label.value, 0) + 1
                
                # Risk heatmap entry
                risk_heatmap.append({
                    "asset": asset.fqdn,
                    "risk_score": asset.hndl_score.score,
                    "risk_label": asset.hndl_score.label.value,
                })
            
            # PQC compliance info
            pqc_support = asset.quantum_safety in ["FULLY_SAFE", "HYBRID"]
            pqc_assets.append({
                "asset_name": asset.fqdn,
                "ip": next((i.ipv4_address for i in self.output.asset_inventory if i.fqdn == asset.fqdn), None),
                "pqc_support": pqc_support,
                "quantum_safety": asset.quantum_safety,
            })
            
            analysis_outputs.append(asset.to_dict())
        
        # Store raw layer output
        self.output.layer3_output = {
            "total_analyzed": len(analysis_results),
            "risk_distribution": risk_distribution,
            "analyses": analysis_outputs,
        }
        
        # Update dashboard
        self.output.dashboard.risk_distribution = risk_distribution
        self.output.dashboard.high_risk_assets = risk_distribution["CRITICAL"] + risk_distribution["HIGH"]
        self.output.dashboard.high_risk_list = [
            {"fqdn": h["asset"], "score": h["risk_score"], "label": h["risk_label"]}
            for h in risk_heatmap if h["risk_label"] in ["CRITICAL", "HIGH"]
        ]
        
        # Update PQC compliance
        self.output.pqc_compliance.assets_with_pqc_support = pqc_assets
        self.output.pqc_compliance.classification_counts = {
            "Elite": sum(1 for a in pqc_assets if a["quantum_safety"] == "FULLY_SAFE"),
            "Critical": sum(1 for a in pqc_assets if a["quantum_safety"] == "CRITICAL"),
            "Standard": sum(1 for a in pqc_assets if a["quantum_safety"] in ["HYBRID", "VULNERABLE"]),
        }
        self.output.pqc_compliance.status_distribution = {
            "PQC Ready": sum(1 for a in pqc_assets if a["quantum_safety"] == "FULLY_SAFE"),
            "Standard": sum(1 for a in pqc_assets if a["quantum_safety"] == "HYBRID"),
            "Legacy": sum(1 for a in pqc_assets if a["quantum_safety"] == "VULNERABLE"),
            "Critical": sum(1 for a in pqc_assets if a["quantum_safety"] == "CRITICAL"),
        }
        self.output.pqc_compliance.risk_heatmap = risk_heatmap
        
        # Calculate PQC adoption progress
        total = len(pqc_assets)
        if total > 0:
            pqc_count = sum(1 for a in pqc_assets if a["pqc_support"])
            self.output.pqc_compliance.pqc_adoption_progress = round(pqc_count / total * 100, 1)
        
        # Update summary metrics
        self.output.summary_metrics.vulnerable_components_count = risk_distribution["CRITICAL"] + risk_distribution["HIGH"]
        self.output.summary_metrics.pqc_adoption_progress = self.output.pqc_compliance.pqc_adoption_progress
        
        logger.info(f"Layer 3 collection complete")
    
    # ========================================================================
    # Layer 4: Certification Output Collection
    # ========================================================================
    
    @timed(logger=logger, layer=4)
    def collect_layer4(self, certified_assets: List[Any], cyber_score: int = 0):
        """Collect Layer 4 certification outputs"""
        logger.info(f"Collecting Layer 4 outputs for {len(certified_assets)} certifications")
        
        cert_outputs = []
        per_url_scores = {}
        
        for asset in certified_assets:
            # Calculate per-URL score (0-1000 scale)
            url_score = self._calculate_url_score(asset)
            per_url_scores[asset.fqdn] = url_score
            
            cert_outputs.append({
                "fqdn": asset.fqdn,
                "cert_tier": asset.cert_tier,
                "cert_issued": asset.cert_issued,
                "url_score": url_score,
            })
        
        # Store raw layer output
        self.output.layer4_output = {
            "total_certified": sum(1 for a in certified_assets if a.cert_issued),
            "certifications": cert_outputs,
        }
        
        # Calculate enterprise score
        if per_url_scores:
            enterprise_score = int(sum(per_url_scores.values()) / len(per_url_scores))
        else:
            enterprise_score = 0
        
        # Determine category
        if enterprise_score < 400:
            category = "Legacy"
        elif enterprise_score < 700:
            category = "Standard"
        else:
            category = "Elite"
        
        self.output.cyber_rating = CyberRating(
            enterprise_score=enterprise_score,
            category=category,
            per_url_scores=per_url_scores,
            factors={
                "pqc_readiness": self.output.pqc_compliance.pqc_adoption_progress,
                "certificate_health": 100 - (self.output.cbom_summary.certificate_issues / max(1, self.output.cbom_summary.active_certificates) * 100),
                "crypto_strength": 100 - (self.output.cbom_summary.weak_cryptography_count / max(1, self.output.cbom_summary.total_applications) * 100),
            }
        )
        
        logger.info(f"Layer 4 collection complete: Enterprise score {enterprise_score}")
    
    def _calculate_url_score(self, asset: Any) -> int:
        """Calculate individual URL cyber score (0-1000)"""
        base_score = 500
        
        # Quantum safety bonus/penalty
        if asset.quantum_safety == "FULLY_SAFE":
            base_score += 300
        elif asset.quantum_safety == "HYBRID":
            base_score += 150
        elif asset.quantum_safety == "VULNERABLE":
            base_score -= 100
        elif asset.quantum_safety == "CRITICAL":
            base_score -= 300
        
        # HNDL score impact
        if asset.hndl_score:
            # Lower HNDL score is better (less risk)
            risk_penalty = int(asset.hndl_score.score * 200)
            base_score -= risk_penalty
        
        # Certification bonus
        if asset.cert_issued:
            base_score += 100
        
        return max(0, min(1000, base_score))
    
    # ========================================================================
    # Output Storage
    # ========================================================================
    
    def save(self, filename: Optional[str] = None) -> Path:
        """Save structured output to JSON file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_{self.output.domain.replace('.', '_')}_{timestamp}.json"
        
        output_path = self.OUTPUT_DIR / filename
        
        with open(output_path, 'w') as f:
            f.write(self.output.to_json(indent=2))
        
        logger.info(f"Output saved to {output_path}")
        return output_path
    
    def get_output(self) -> StructuredOutput:
        """Get the structured output object"""
        return self.output
    
    def get_json(self) -> str:
        """Get output as JSON string"""
        return self.output.to_json()


# ============================================================================
# Convenience Functions
# ============================================================================

def create_collector() -> OutputCollector:
    """Create a new output collector"""
    return OutputCollector()
