"""
Extended Discovery Service

Provides extended asset discovery capabilities including:
- DNS record queries (NS, MX, TXT, SOA, CNAME)
- WHOIS lookups for domain registration info
- Port scanning and service detection
- ASN/GeoIP lookup for IP analysis
- Banner grabbing for service identification
- Form detection, IoT detection, cloud detection

Integrated into Layer 1 discovery for comprehensive asset inventory.
"""

import asyncio
import socket
import ssl
import re
import struct
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple, Set
from concurrent.futures import ThreadPoolExecutor
import ipaddress

from qushield.utils.logging import get_logger, timed

logger = get_logger("extended_discovery")


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class NameserverRecord:
    """Nameserver (NS) record information"""
    hostname: str
    nameserver: str
    ip_address: Optional[str] = None
    ttl: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MXRecord:
    """Mail Exchange record information"""
    hostname: str
    mail_server: str
    priority: int = 0
    ip_address: Optional[str] = None
    ttl: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TXTRecord:
    """TXT record information"""
    hostname: str
    value: str
    record_type: str = "TXT"  # SPF, DKIM, DMARC, etc.
    ttl: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WHOISInfo:
    """WHOIS domain registration information"""
    domain: str
    registrar: str = ""
    registration_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    organization: str = ""
    registrant_name: str = ""
    registrant_country: str = ""
    name_servers: List[str] = field(default_factory=list)
    dnssec: bool = False
    status: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PortScanResult:
    """Port scan result for a single port"""
    port: int
    state: str  # open, closed, filtered
    service: str = ""
    version: str = ""
    banner: str = ""
    protocol: str = "tcp"
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ASNInfo:
    """Autonomous System Number information"""
    ip_address: str
    asn: int = 0
    asn_name: str = ""
    asn_description: str = ""
    network: str = ""
    country: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GeoIPInfo:
    """Geographic IP information"""
    ip_address: str
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    isp: str = ""
    organization: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ServiceInfo:
    """Detected service information"""
    host: str
    port: int
    service_name: str
    service_type: str  # http, https, ssh, ftp, smtp, etc.
    version: str = ""
    banner: str = ""
    is_encrypted: bool = False
    detected_tech: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FormInfo:
    """Detected form information for web assets"""
    url: str
    form_count: int = 0
    has_login_form: bool = False
    has_search_form: bool = False
    has_contact_form: bool = False
    form_actions: List[str] = field(default_factory=list)
    input_fields: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CloudInfo:
    """Cloud provider detection information"""
    host: str
    is_cloud_hosted: bool = False
    cloud_provider: str = ""  # AWS, Azure, GCP, Cloudflare, Akamai, etc.
    cdn_provider: str = ""
    waf_detected: bool = False
    waf_provider: str = ""
    confidence: float = 0.0
    indicators: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IoTInfo:
    """IoT device detection information"""
    host: str
    is_iot_device: bool = False
    device_type: str = ""  # camera, router, sensor, etc.
    manufacturer: str = ""
    model: str = ""
    firmware_version: str = ""
    confidence: float = 0.0
    indicators: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ============================================================================
# Extended Discovery Service
# ============================================================================

class ExtendedDiscoveryService:
    """
    Extended discovery service for comprehensive asset information gathering.
    """
    
    # Common ports for scanning
    COMMON_PORTS = [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        80,    # HTTP
        110,   # POP3
        143,   # IMAP
        443,   # HTTPS
        465,   # SMTPS
        587,   # SMTP Submission
        993,   # IMAPS
        995,   # POP3S
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        8080,  # HTTP Alt
        8443,  # HTTPS Alt
    ]
    
    # Service port mappings
    SERVICE_PORTS = {
        21: ("FTP", "ftp"),
        22: ("SSH", "ssh"),
        23: ("Telnet", "telnet"),
        25: ("SMTP", "smtp"),
        53: ("DNS", "dns"),
        80: ("HTTP", "http"),
        110: ("POP3", "pop3"),
        143: ("IMAP", "imap"),
        443: ("HTTPS", "https"),
        465: ("SMTPS", "smtps"),
        587: ("SMTP Submission", "smtp"),
        993: ("IMAPS", "imaps"),
        995: ("POP3S", "pop3s"),
        3306: ("MySQL", "mysql"),
        3389: ("RDP", "rdp"),
        5432: ("PostgreSQL", "postgresql"),
        8080: ("HTTP Alt", "http"),
        8443: ("HTTPS Alt", "https"),
    }
    
    # Cloud provider IP ranges and indicators
    CLOUD_INDICATORS = {
        "AWS": {
            "headers": ["x-amz-", "x-amzn-"],
            "domains": ["amazonaws.com", "aws.amazon.com", "cloudfront.net"],
            "asn_names": ["AMAZON", "AWS", "CLOUDFRONT"],
        },
        "Azure": {
            "headers": ["x-ms-", "x-azure-"],
            "domains": ["azure.com", "azurewebsites.net", "windows.net", "azureedge.net"],
            "asn_names": ["MICROSOFT", "AZURE"],
        },
        "GCP": {
            "headers": ["x-goog-", "x-cloud-"],
            "domains": ["googleapis.com", "cloud.google.com", "appspot.com"],
            "asn_names": ["GOOGLE", "GCP"],
        },
        "Cloudflare": {
            "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
            "domains": ["cloudflare.com", "cloudflaressl.com"],
            "asn_names": ["CLOUDFLARE"],
        },
        "Akamai": {
            "headers": ["x-akamai-"],
            "domains": ["akamai.net", "akamaiedge.net", "akamaized.net"],
            "asn_names": ["AKAMAI"],
        },
    }
    
    # IoT device indicators
    IOT_INDICATORS = {
        "camera": ["camera", "cam", "ipcam", "webcam", "dvr", "nvr", "hikvision", "dahua"],
        "router": ["router", "gateway", "modem", "netgear", "tplink", "dlink", "asus-router"],
        "sensor": ["sensor", "iot", "arduino", "raspberry", "esp32", "esp8266"],
        "smart_device": ["smart", "alexa", "google-home", "hue", "nest"],
        "industrial": ["plc", "scada", "modbus", "siemens", "schneider"],
    }
    
    def __init__(self, timeout: float = 5.0, max_workers: int = 20):
        self.timeout = timeout
        self.max_workers = max_workers
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        logger.info("ExtendedDiscoveryService initialized", extra={
            "timeout": timeout,
            "max_workers": max_workers
        })
    
    # ========================================================================
    # DNS Record Queries
    # ========================================================================
    
    async def resolve_ns_records(self, domain: str) -> List[NameserverRecord]:
        """Resolve NS (nameserver) records for a domain"""
        records = []
        try:
            import dns.resolver
            try:
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(self._executor, lambda: dns.resolver.resolve(domain, 'NS'))
                for rdata in answers:
                    ns_name = str(rdata.target).rstrip('.')
                    # Try to resolve NS IP
                    ns_ip = None
                    try:
                        ns_answers = await loop.run_in_executor(self._executor, lambda h=ns_name: dns.resolver.resolve(h, 'A'))
                        ns_ip = str(ns_answers[0])
                    except Exception:
                        pass
                    
                    records.append(NameserverRecord(
                        hostname=domain,
                        nameserver=ns_name,
                        ip_address=ns_ip,
                        ttl=answers.rrset.ttl if answers.rrset else None
                    ))
                logger.info(f"Resolved {len(records)} NS records for {domain}")
            except dns.resolver.NXDOMAIN:
                logger.warning(f"Domain {domain} does not exist")
            except dns.resolver.NoAnswer:
                logger.debug(f"No NS records for {domain}")
            except dns.resolver.NoNameservers:
                logger.warning(f"No nameservers available for {domain}")
        except ImportError:
            logger.warning("dnspython not installed, using fallback NS resolution")
            # Fallback using socket
            try:
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    self._executor,
                    lambda: socket.gethostbyname_ex(domain)
                )
                # Limited info available via socket
            except Exception as e:
                logger.debug(f"Fallback NS resolution failed: {e}")
        except Exception as e:
            logger.error(f"NS resolution error for {domain}: {e}")
        
        return records
    
    async def resolve_mx_records(self, domain: str) -> List[MXRecord]:
        """Resolve MX (mail exchange) records for a domain"""
        records = []
        try:
            import dns.resolver
            try:
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(self._executor, lambda: dns.resolver.resolve(domain, 'MX'))
                for rdata in answers:
                    mx_host = str(rdata.exchange).rstrip('.')
                    # Try to resolve MX IP
                    mx_ip = None
                    try:
                        mx_answers = await loop.run_in_executor(self._executor, lambda h=mx_host: dns.resolver.resolve(h, 'A'))
                        mx_ip = str(mx_answers[0])
                    except Exception:
                        pass
                    
                    records.append(MXRecord(
                        hostname=domain,
                        mail_server=mx_host,
                        priority=rdata.preference,
                        ip_address=mx_ip,
                        ttl=answers.rrset.ttl if answers.rrset else None
                    ))
                logger.info(f"Resolved {len(records)} MX records for {domain}")
            except dns.resolver.NXDOMAIN:
                logger.warning(f"Domain {domain} does not exist")
            except dns.resolver.NoAnswer:
                logger.debug(f"No MX records for {domain}")
        except ImportError:
            logger.warning("dnspython not installed for MX resolution")
        except Exception as e:
            logger.error(f"MX resolution error for {domain}: {e}")
        
        return records
    
    async def resolve_txt_records(self, domain: str) -> List[TXTRecord]:
        """Resolve TXT records for a domain (SPF, DKIM, DMARC, etc.)"""
        records = []
        try:
            import dns.resolver
            try:
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(self._executor, lambda: dns.resolver.resolve(domain, 'TXT'))
                for rdata in answers:
                    txt_value = str(rdata).strip('"')
                    
                    # Classify TXT record type
                    record_type = "TXT"
                    if txt_value.startswith("v=spf1"):
                        record_type = "SPF"
                    elif txt_value.startswith("v=DKIM1"):
                        record_type = "DKIM"
                    elif txt_value.startswith("v=DMARC1"):
                        record_type = "DMARC"
                    elif "google-site-verification" in txt_value:
                        record_type = "Google Verification"
                    elif "MS=" in txt_value:
                        record_type = "Microsoft Verification"
                    
                    records.append(TXTRecord(
                        hostname=domain,
                        value=txt_value,
                        record_type=record_type,
                        ttl=answers.rrset.ttl if answers.rrset else None
                    ))
                logger.info(f"Resolved {len(records)} TXT records for {domain}")
            except dns.resolver.NXDOMAIN:
                logger.warning(f"Domain {domain} does not exist")
            except dns.resolver.NoAnswer:
                logger.debug(f"No TXT records for {domain}")
        except ImportError:
            logger.warning("dnspython not installed for TXT resolution")
        except Exception as e:
            logger.error(f"TXT resolution error for {domain}: {e}")
        
        # Also check for DMARC specifically at _dmarc subdomain
        try:
            import dns.resolver
            dmarc_domain = f"_dmarc.{domain}"
            try:
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(self._executor, lambda: dns.resolver.resolve(dmarc_domain, 'TXT'))
                for rdata in answers:
                    txt_value = str(rdata).strip('"')
                    records.append(TXTRecord(
                        hostname=dmarc_domain,
                        value=txt_value,
                        record_type="DMARC",
                        ttl=answers.rrset.ttl if answers.rrset else None
                    ))
            except Exception:
                pass
        except ImportError:
            pass
        
        return records
    
    async def resolve_all_dns_records(self, domain: str) -> Dict[str, List]:
        """Resolve all DNS record types for comprehensive nameserver table"""
        ns_records, mx_records, txt_records = await asyncio.gather(
            self.resolve_ns_records(domain),
            self.resolve_mx_records(domain),
            self.resolve_txt_records(domain),
            return_exceptions=True
        )
        
        return {
            "ns_records": ns_records if isinstance(ns_records, list) else [],
            "mx_records": mx_records if isinstance(mx_records, list) else [],
            "txt_records": txt_records if isinstance(txt_records, list) else [],
        }
    
    # ========================================================================
    # WHOIS Lookup
    # ========================================================================
    
    async def whois_lookup(self, domain: str) -> Optional[WHOISInfo]:
        """Perform WHOIS lookup for domain registration information"""
        try:
            import whois
            loop = asyncio.get_event_loop()
            
            def _do_whois():
                try:
                    w = whois.whois(domain)
                    return w
                except Exception as e:
                    logger.debug(f"WHOIS query failed: {e}")
                    return None
            
            try:
                task = loop.run_in_executor(self._executor, _do_whois)
                result = await asyncio.wait_for(task, timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning(f"WHOIS lookup timed out for {domain}")
                return None
            
            if result:
                # Parse dates
                def parse_date(date_val):
                    if date_val is None:
                        return None
                    if isinstance(date_val, list):
                        date_val = date_val[0]
                    if isinstance(date_val, datetime):
                        return date_val.isoformat()
                    return str(date_val)
                
                # Parse name servers
                name_servers = []
                if result.name_servers:
                    if isinstance(result.name_servers, list):
                        name_servers = [str(ns).lower() for ns in result.name_servers]
                    else:
                        name_servers = [str(result.name_servers).lower()]
                
                # Parse status
                status = []
                if result.status:
                    if isinstance(result.status, list):
                        status = result.status
                    else:
                        status = [result.status]
                
                whois_info = WHOISInfo(
                    domain=domain,
                    registrar=str(result.registrar or ""),
                    registration_date=parse_date(result.creation_date),
                    expiration_date=parse_date(result.expiration_date),
                    updated_date=parse_date(result.updated_date),
                    organization=str(result.org or ""),
                    registrant_name=str(getattr(result, 'name', '') or ""),
                    registrant_country=str(getattr(result, 'country', '') or ""),
                    name_servers=name_servers,
                    dnssec=bool(getattr(result, 'dnssec', False)),
                    status=status,
                )
                
                logger.info(f"WHOIS lookup successful for {domain}", extra={
                    "registrar": whois_info.registrar,
                    "organization": whois_info.organization
                })
                return whois_info
                
        except ImportError:
            logger.warning("python-whois not installed, skipping WHOIS lookup")
        except Exception as e:
            logger.error(f"WHOIS lookup error for {domain}: {e}")
        
        return None
    
    # ========================================================================
    # Port Scanning
    # ========================================================================
    
    async def _scan_port(self, host: str, port: int) -> Optional[PortScanResult]:
        """Scan a single port"""
        try:
            loop = asyncio.get_event_loop()
            
            def _connect():
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                if result == 0:
                    # Port is open, try to grab banner
                    banner = ""
                    try:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    except Exception:
                        pass
                    sock.close()
                    return ("open", banner)
                sock.close()
                return ("closed", "")
            
            try:
                task = loop.run_in_executor(self._executor, _connect)
                state, banner = await asyncio.wait_for(task, timeout=self.timeout + 1.0)
            except asyncio.TimeoutError:
                return PortScanResult(port=port, state="filtered", protocol="tcp")
            
            if state == "open":
                service_info = self.SERVICE_PORTS.get(port, ("Unknown", "unknown"))
                return PortScanResult(
                    port=port,
                    state=state,
                    service=service_info[0],
                    banner=banner[:500] if banner else "",
                    protocol="tcp"
                )
        except socket.timeout:
            return PortScanResult(port=port, state="filtered", protocol="tcp")
        except Exception as e:
            logger.debug(f"Port scan error for {host}:{port}: {e}")
        
        return None
    
    async def scan_ports(self, host: str, ports: List[int] = None) -> List[PortScanResult]:
        """Scan multiple ports on a host"""
        if ports is None:
            ports = self.COMMON_PORTS
        
        logger.info(f"Scanning {len(ports)} ports on {host}")
        
        # Resolve hostname to IP first
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            logger.warning(f"Could not resolve {host} for port scanning")
            return []
        
        # Scan ports concurrently
        tasks = [self._scan_port(ip, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        open_ports = []
        for result in results:
            if isinstance(result, PortScanResult) and result.state == "open":
                open_ports.append(result)
        
        logger.info(f"Found {len(open_ports)} open ports on {host}")
        return open_ports
    
    # ========================================================================
    # Banner Grabbing
    # ========================================================================
    
    async def grab_banner(self, host: str, port: int) -> Optional[str]:
        """Grab service banner from a specific port"""
        try:
            loop = asyncio.get_event_loop()
            
            def _grab():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((host, port))
                    
                    # Send appropriate probe based on port
                    if port in [80, 8080]:
                        sock.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                    elif port == 443:
                        # For HTTPS, we need SSL
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        ssock = context.wrap_socket(sock, server_hostname=host)
                        ssock.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                        banner = ssock.recv(2048).decode('utf-8', errors='ignore')
                        ssock.close()
                        return banner.strip()
                    elif port == 22:
                        # SSH banner is sent immediately
                        pass
                    elif port == 25:
                        # SMTP sends banner on connect
                        pass
                    else:
                        sock.send(b"\r\n")
                    
                    banner = sock.recv(2048).decode('utf-8', errors='ignore')
                    sock.close()
                    return banner.strip()
                except Exception as e:
                    return None
            
            try:
                task = loop.run_in_executor(self._executor, _grab)
                banner = await asyncio.wait_for(task, timeout=self.timeout + 1.0)
            except asyncio.TimeoutError:
                return None
            if banner:
                logger.debug(f"Banner grabbed from {host}:{port}: {banner[:100]}...")
            return banner
            
        except Exception as e:
            logger.debug(f"Banner grab error for {host}:{port}: {e}")
            return None
    
    # ========================================================================
    # ASN Lookup
    # ========================================================================
    
    async def asn_lookup(self, ip_address: str) -> Optional[ASNInfo]:
        """Lookup ASN information for an IP address"""
        try:
            # Validate IP
            ipaddress.ip_address(ip_address)
        except ValueError:
            logger.warning(f"Invalid IP address for ASN lookup: {ip_address}")
            return None
        
        try:
            import dns.resolver
            
            # Reverse IP for DNS query
            reversed_ip = '.'.join(reversed(ip_address.split('.')))
            
            # Query Team Cymru DNS
            asn_query = f"{reversed_ip}.origin.asn.cymru.com"
            
            loop = asyncio.get_event_loop()
            
            def _query_asn():
                try:
                    answers = dns.resolver.resolve(asn_query, 'TXT')
                    for rdata in answers:
                        txt = str(rdata).strip('"')
                        # Format: "ASN | IP | Country | Registry | Allocated"
                        parts = [p.strip() for p in txt.split('|')]
                        if len(parts) >= 3:
                            return {
                                "asn": int(parts[0]) if parts[0].isdigit() else 0,
                                "network": parts[1],
                                "country": parts[2],
                            }
                except Exception as e:
                    logger.debug(f"ASN DNS query failed: {e}")
                return None
            
            try:
                task = loop.run_in_executor(self._executor, _query_asn)
                result = await asyncio.wait_for(task, timeout=3.0)
            except asyncio.TimeoutError:
                logger.warning(f"ASN DNS query timed out for {asn_query}")
                return None
            
            if result:
                # Query ASN name
                asn_name = ""
                try:
                    name_query = f"AS{result['asn']}.asn.cymru.com"
                    answers = dns.resolver.resolve(name_query, 'TXT')
                    for rdata in answers:
                        txt = str(rdata).strip('"')
                        parts = [p.strip() for p in txt.split('|')]
                        if len(parts) >= 5:
                            asn_name = parts[4]
                except Exception:
                    pass
                
                asn_info = ASNInfo(
                    ip_address=ip_address,
                    asn=result["asn"],
                    asn_name=asn_name,
                    network=result["network"],
                    country=result["country"],
                )
                logger.info(f"ASN lookup successful for {ip_address}: AS{asn_info.asn}")
                return asn_info
                
        except ImportError:
            logger.warning("dnspython not installed for ASN lookup")
        except Exception as e:
            logger.error(f"ASN lookup error for {ip_address}: {e}")
        
        return None
    
    # ========================================================================
    # GeoIP Lookup
    # ========================================================================
    
    async def geoip_lookup(self, ip_address: str) -> Optional[GeoIPInfo]:
        """Lookup geographic information for an IP address"""
        try:
            # Validate IP
            ipaddress.ip_address(ip_address)
        except ValueError:
            logger.warning(f"Invalid IP address for GeoIP lookup: {ip_address}")
            return None
        
        # Check if private IP
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private:
                return GeoIPInfo(
                    ip_address=ip_address,
                    country="Private Network",
                    country_code="PRIV",
                )
        except Exception:
            pass
        
        try:
            import geoip2.database
            
            # Try to use local MaxMind database if available
            db_paths = [
                "/usr/share/GeoIP/GeoLite2-City.mmdb",
                "/var/lib/GeoIP/GeoLite2-City.mmdb",
                "./GeoLite2-City.mmdb",
            ]
            
            for db_path in db_paths:
                try:
                    reader = geoip2.database.Reader(db_path)
                    response = reader.city(ip_address)
                    
                    geoip_info = GeoIPInfo(
                        ip_address=ip_address,
                        country=response.country.name or "",
                        country_code=response.country.iso_code or "",
                        region=response.subdivisions.most_specific.name if response.subdivisions else "",
                        city=response.city.name or "",
                        latitude=response.location.latitude,
                        longitude=response.location.longitude,
                    )
                    reader.close()
                    logger.info(f"GeoIP lookup successful for {ip_address}: {geoip_info.country}")
                    return geoip_info
                except FileNotFoundError:
                    continue
                except Exception as e:
                    logger.debug(f"GeoIP database error: {e}")
                    continue
            
            logger.warning("No GeoIP database found")
            
        except ImportError:
            logger.warning("geoip2 not installed for GeoIP lookup")
        except Exception as e:
            logger.error(f"GeoIP lookup error for {ip_address}: {e}")
        
        # Fallback: Return basic info based on ASN lookup
        asn_info = await self.asn_lookup(ip_address)
        if asn_info and asn_info.country:
            return GeoIPInfo(
                ip_address=ip_address,
                country_code=asn_info.country,
                organization=asn_info.asn_name,
            )
        
        return GeoIPInfo(ip_address=ip_address)
    
    # ========================================================================
    # Service Detection
    # ========================================================================
    
    async def detect_services(self, host: str, open_ports: List[PortScanResult] = None) -> List[ServiceInfo]:
        """Detect services running on open ports"""
        services = []
        
        if open_ports is None:
            open_ports = await self.scan_ports(host)
        
        for port_result in open_ports:
            service_info = ServiceInfo(
                host=host,
                port=port_result.port,
                service_name=port_result.service,
                service_type=self.SERVICE_PORTS.get(port_result.port, ("Unknown", "unknown"))[1],
                banner=port_result.banner,
                is_encrypted=port_result.port in [443, 465, 993, 995, 8443],
            )
            
            # Parse banner for version info
            if port_result.banner:
                # Extract server version from HTTP response
                if "Server:" in port_result.banner:
                    match = re.search(r'Server:\s*([^\r\n]+)', port_result.banner)
                    if match:
                        service_info.version = match.group(1).strip()
                        service_info.detected_tech.append(match.group(1).strip())
                
                # Detect technologies
                tech_patterns = {
                    "nginx": r'nginx[/\s]*([\d.]+)?',
                    "Apache": r'Apache[/\s]*([\d.]+)?',
                    "IIS": r'Microsoft-IIS[/\s]*([\d.]+)?',
                    "OpenSSH": r'OpenSSH[_\s]*([\d.]+)?',
                    "Postfix": r'Postfix',
                    "Exim": r'Exim',
                }
                
                for tech, pattern in tech_patterns.items():
                    if re.search(pattern, port_result.banner, re.IGNORECASE):
                        if tech not in service_info.detected_tech:
                            service_info.detected_tech.append(tech)
            
            services.append(service_info)
        
        logger.info(f"Detected {len(services)} services on {host}")
        return services
    
    # ========================================================================
    # Cloud Detection
    # ========================================================================
    
    async def detect_cloud(self, host: str, ip_address: str = None, 
                           headers: Dict[str, str] = None) -> CloudInfo:
        """Detect if host is cloud-hosted and identify provider"""
        cloud_info = CloudInfo(host=host)
        indicators = []
        
        # Resolve IP if not provided
        if not ip_address:
            try:
                ip_address = socket.gethostbyname(host)
            except Exception:
                return cloud_info
        
        # Check ASN for cloud providers
        asn_info = await self.asn_lookup(ip_address)
        if asn_info and asn_info.asn_name:
            asn_upper = asn_info.asn_name.upper()
            for provider, data in self.CLOUD_INDICATORS.items():
                for asn_pattern in data["asn_names"]:
                    if asn_pattern in asn_upper:
                        cloud_info.is_cloud_hosted = True
                        cloud_info.cloud_provider = provider
                        indicators.append(f"ASN: {asn_info.asn_name}")
                        break
        
        # Check domain patterns
        host_lower = host.lower()
        for provider, data in self.CLOUD_INDICATORS.items():
            for domain in data["domains"]:
                if domain in host_lower:
                    cloud_info.is_cloud_hosted = True
                    if not cloud_info.cloud_provider:
                        cloud_info.cloud_provider = provider
                    if provider in ["Cloudflare", "Akamai"]:
                        cloud_info.cdn_provider = provider
                    indicators.append(f"Domain: {domain}")
        
        # Check headers if provided
        if headers:
            for provider, data in self.CLOUD_INDICATORS.items():
                for header_prefix in data["headers"]:
                    for header_name in headers:
                        if header_name.lower().startswith(header_prefix):
                            cloud_info.is_cloud_hosted = True
                            if provider in ["Cloudflare", "Akamai"]:
                                cloud_info.cdn_provider = provider
                                cloud_info.waf_detected = True
                                cloud_info.waf_provider = provider
                            elif not cloud_info.cloud_provider:
                                cloud_info.cloud_provider = provider
                            indicators.append(f"Header: {header_name}")
        
        cloud_info.indicators = indicators
        cloud_info.confidence = min(len(indicators) * 0.3, 1.0)
        
        if cloud_info.is_cloud_hosted:
            logger.info(f"Cloud detected for {host}: {cloud_info.cloud_provider}", extra={
                "cdn": cloud_info.cdn_provider,
                "waf": cloud_info.waf_provider
            })
        
        return cloud_info
    
    # ========================================================================
    # IoT Detection
    # ========================================================================
    
    async def detect_iot(self, host: str, banner: str = None, 
                         open_ports: List[int] = None) -> IoTInfo:
        """Detect if host is an IoT device"""
        iot_info = IoTInfo(host=host)
        indicators = []
        
        host_lower = host.lower()
        
        # Check hostname for IoT patterns
        for device_type, patterns in self.IOT_INDICATORS.items():
            for pattern in patterns:
                if pattern in host_lower:
                    iot_info.is_iot_device = True
                    iot_info.device_type = device_type
                    indicators.append(f"Hostname: {pattern}")
        
        # Check banner for IoT signatures
        if banner:
            banner_lower = banner.lower()
            
            # Camera signatures
            camera_sigs = ["hikvision", "dahua", "axis", "foscam", "vivotek", "amcrest"]
            for sig in camera_sigs:
                if sig in banner_lower:
                    iot_info.is_iot_device = True
                    iot_info.device_type = "camera"
                    iot_info.manufacturer = sig.capitalize()
                    indicators.append(f"Banner: {sig}")
            
            # Router signatures
            router_sigs = ["dd-wrt", "openwrt", "tomato", "mikrotik", "ubiquiti"]
            for sig in router_sigs:
                if sig in banner_lower:
                    iot_info.is_iot_device = True
                    iot_info.device_type = "router"
                    iot_info.manufacturer = sig.capitalize()
                    indicators.append(f"Banner: {sig}")
        
        # Check ports for IoT patterns
        iot_ports = {554: "camera", 8554: "camera", 37777: "camera",  # RTSP/Dahua
                     1883: "iot", 8883: "iot",  # MQTT
                     502: "industrial", 102: "industrial"}  # Modbus/S7
        
        if open_ports:
            for port in open_ports:
                if port in iot_ports:
                    iot_info.is_iot_device = True
                    if not iot_info.device_type:
                        iot_info.device_type = iot_ports[port]
                    indicators.append(f"Port: {port}")
        
        iot_info.indicators = indicators
        iot_info.confidence = min(len(indicators) * 0.4, 1.0)
        
        if iot_info.is_iot_device:
            logger.info(f"IoT device detected: {host}", extra={
                "device_type": iot_info.device_type,
                "manufacturer": iot_info.manufacturer
            })
        
        return iot_info
    
    # ========================================================================
    # Form Detection
    # ========================================================================
    
    async def detect_forms(self, url: str, html_content: str = None) -> FormInfo:
        """Detect forms on a web page"""
        form_info = FormInfo(url=url)
        
        if not html_content:
            # Fetch HTML content
            try:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout),
                                          ssl=False) as response:
                        html_content = await response.text()
            except ImportError:
                logger.warning("aiohttp not installed for form detection")
                return form_info
            except Exception as e:
                logger.debug(f"Failed to fetch {url} for form detection: {e}")
                return form_info
        
        if not html_content:
            return form_info
        
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_content, 'html.parser')
            
            forms = soup.find_all('form')
            form_info.form_count = len(forms)
            
            for form in forms:
                # Get form action
                action = form.get('action', '')
                if action:
                    form_info.form_actions.append(action)
                
                # Get input fields
                inputs = form.find_all('input')
                for inp in inputs:
                    input_type = inp.get('type', 'text')
                    input_name = inp.get('name', '')
                    if input_name:
                        form_info.input_fields.append(f"{input_name}:{input_type}")
                    
                    # Detect login forms
                    if input_type == 'password':
                        form_info.has_login_form = True
                    
                    # Detect search forms
                    if input_type == 'search' or input_name in ['q', 'query', 'search', 's']:
                        form_info.has_search_form = True
                
                # Detect contact forms
                textareas = form.find_all('textarea')
                if textareas and any(inp.get('type') == 'email' for inp in inputs):
                    form_info.has_contact_form = True
            
            if form_info.form_count > 0:
                logger.info(f"Detected {form_info.form_count} forms on {url}", extra={
                    "login_form": form_info.has_login_form,
                    "search_form": form_info.has_search_form
                })
                
        except ImportError:
            logger.warning("BeautifulSoup not installed for form detection")
        except Exception as e:
            logger.debug(f"Form detection error for {url}: {e}")
        
        return form_info
    
    # ========================================================================
    # Comprehensive Asset Analysis
    # ========================================================================
    
    async def analyze_asset(self, host: str, scan_ports: bool = True) -> Dict[str, Any]:
        """Perform comprehensive analysis on a single asset"""
        logger.info(f"Starting comprehensive analysis for {host}")
        
        result = {
            "host": host,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        
        # Resolve IP
        try:
            ip_address = socket.gethostbyname(host)
            result["ip_address"] = ip_address
        except Exception:
            ip_address = None
            result["ip_address"] = None
        
        # Run analyses concurrently
        tasks = []
        
        if scan_ports and ip_address:
            tasks.append(("port_scan", self.scan_ports(host)))
        
        if ip_address:
            tasks.append(("asn_info", self.asn_lookup(ip_address)))
            tasks.append(("geoip_info", self.geoip_lookup(ip_address)))
            tasks.append(("cloud_info", self.detect_cloud(host, ip_address)))
        
        tasks.append(("iot_info", self.detect_iot(host)))
        
        # Execute tasks
        task_names = [t[0] for t in tasks]
        task_coros = [t[1] for t in tasks]
        results = await asyncio.gather(*task_coros, return_exceptions=True)
        
        for name, res in zip(task_names, results):
            if isinstance(res, Exception):
                logger.debug(f"{name} failed for {host}: {res}")
                result[name] = None
            else:
                result[name] = res
        
        # Detect services from port scan
        if "port_scan" in result and result["port_scan"]:
            services = await self.detect_services(host, result["port_scan"])
            result["services"] = services
        
        return result
