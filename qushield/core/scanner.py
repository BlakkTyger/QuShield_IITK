"""
TLS Scanner Service (Standalone)

Performs TLS/SSL scanning using a fast nmap+pqcscan_bin pipeline,
falling back to SSLyze without database dependencies.
"""

import time
import os
import ssl
import json
import socket
import shutil
import tempfile
import subprocess
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Any, Optional
from enum import Enum

from qushield.utils.logging import get_logger, timed

logger = get_logger("scanner")

def _find_nmap() -> Optional[str]:
    found = shutil.which("nmap")
    if found:
        return found
    for candidate in ["/usr/bin/nmap", "/usr/sbin/nmap", "/usr/local/bin/nmap", "/bin/nmap"]:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None

_NMAP_BIN = _find_nmap()

# Local helper to find the PQC scanner binary
def _find_pqc_scanner() -> Optional[str]:
    """Finds the PQC scanning binary (pqcscan_bin, pqcscan.exe, or pqscan.exe)"""
    bin_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "bin"))
    
    # Selection of possible binary names
    # We prioritize .exe on Windows and generic names on Linux/Unix
    if os.name == 'nt':
        candidates = ["pqcscan.exe", "pqscan.exe", "pqcscan_bin"]
    else:
        candidates = ["pqcscan_bin", "pqcscan", "pqscan"]
        
    for c in candidates:
        path = os.path.join(bin_dir, c)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
            
    # Also check system PATH as a fallback
    for c in ["pqscan", "pqcscan"]:
        found = shutil.which(c)
        if found:
            return found
            
    return None

_PQCSCAN_BIN = _find_pqc_scanner()
if not _PQCSCAN_BIN:
    logger.warning("No PQC scanner binary (pqcscan_bin/pqscan.exe) found. PQC detection will be disabled.")

# PQC detection regex patterns (matching pnb/ implementation)
_PQC_KEM_RE = re.compile(
    r'\b(x25519mlkem\d*|secp256r1mlkem\d*|secp384r1mlkem\d*|mlkem\d+|kyber\d+)\b',
    re.IGNORECASE,
)
_PQC_SIG_RE = re.compile(
    r'\b(dilithium\d*|falcon\d*|sphincsplus|sphincs\+?|mldsa\d*|slhdsa\d*)\b',
    re.IGNORECASE,
)
_NMAP_CIPHER_LINE_RE = re.compile(
    r'^\s*\|.*(?:TLS_[A-Z_]+|x25519|secp\d+|mlkem|kyber)',
    re.IGNORECASE,
)


class ScanStatus(str, Enum):
    """Scan result status"""
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"


@dataclass
class CertificateInfo:
    """Parsed certificate information"""
    subject: str = ""
    issuer: str = ""
    serial_number: str = ""
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    public_key_algorithm: str = ""
    public_key_size: Optional[int] = None
    signature_algorithm: str = ""
    san_entries: List[str] = field(default_factory=list)
    is_self_signed: bool = False
    is_expired: bool = False


@dataclass
class TLSScanResult:
    """Complete TLS scan result"""
    target: str
    port: int
    status: ScanStatus
    scan_time: str
    duration_ms: float
    
    # TLS versions supported
    supports_tls10: bool = False
    supports_tls11: bool = False
    supports_tls12: bool = False
    supports_tls13: bool = False
    
    # Cipher suites
    tls12_cipher_suites: List[str] = field(default_factory=list)
    tls13_cipher_suites: List[str] = field(default_factory=list)
    
    # Key exchange algorithms (extracted from cipher suites)
    key_exchange_algorithms: List[str] = field(default_factory=list)
    
    # Certificate
    certificate: Optional[CertificateInfo] = None
    certificate_chain_length: int = 0
    
    # PQC specifics
    cert_is_pqc: bool = False
    cert_pqc_algorithm: Optional[str] = None
    
    # Vulnerabilities
    vulnerable_to_heartbleed: bool = False
    supports_fallback_scsv: bool = True
    
    # Errors
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "target": self.target,
            "port": self.port,
            "status": self.status.value,
            "scan_time": self.scan_time,
            "duration_ms": self.duration_ms,
            "tls_versions": {
                "tls_1_0": self.supports_tls10,
                "tls_1_1": self.supports_tls11,
                "tls_1_2": self.supports_tls12,
                "tls_1_3": self.supports_tls13,
            },
            "cipher_suites": {
                "tls_1_2": self.tls12_cipher_suites,
                "tls_1_3": self.tls13_cipher_suites,
            },
            "key_exchange_algorithms": self.key_exchange_algorithms,
            "certificate": {
                "subject": self.certificate.subject if self.certificate else None,
                "issuer": self.certificate.issuer if self.certificate else None,
                "not_after": self.certificate.not_after if self.certificate else None,
                "public_key_algorithm": self.certificate.public_key_algorithm if self.certificate else None,
                "public_key_size": self.certificate.public_key_size if self.certificate else None,
                "signature_algorithm": self.certificate.signature_algorithm if self.certificate else None,
            } if self.certificate else None,
            "pqc_assessment": {
                "is_pqc": self.cert_is_pqc,
                "pqc_algorithm": self.cert_pqc_algorithm,
            },
            "vulnerabilities": {
                "heartbleed": self.vulnerable_to_heartbleed,
                "downgrade_prevention": self.supports_fallback_scsv,
            },
            "error": self.error_message,
        }


class TLSScanner:
    """
    TLS Scanner using nmap + pqcscan_bin with SSLyze fallback.
    """
    
    KEY_EXCHANGE_PATTERNS = {
        "ECDHE": "ECDHE",
        "DHE": "DHE", 
        "ECDH": "ECDH",
        "DH": "DH",
        "RSA": "RSA",
        "PSK": "PSK",
    }
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self._sslyze_available = self._check_sslyze()
    
    def _check_sslyze(self) -> bool:
        try:
            from sslyze import Scanner
            return True
        except ImportError:
            logger.warning("SSLyze not installed. TLS scanning will lack certain deep insights if fast-path fails.")
            return False
            
    @timed(logger=logger, layer=2)
    def scan(self, target: str, port: int = 443) -> TLSScanResult:
        start_time = time.perf_counter()
        scan_timestamp = datetime.utcnow().isoformat()
        
        logger.info(f"Starting TLS scan", extra={"layer": 2, "target": target, "data": {"port": port}})
        
        # Determine if we should use fast path
        if _NMAP_BIN:
            try:
                result = self._fast_scan(target, port, scan_timestamp)
                result.duration_ms = (time.perf_counter() - start_time) * 1000
                if result.status == ScanStatus.SUCCESS:
                    return result
            except Exception as e:
                logger.warning(f"Fast scan failed for {target}:{port}: {e}. Falling back to SSLyze.")

        if not self._sslyze_available:
            return TLSScanResult(
                target=target, port=port, status=ScanStatus.FAILED,
                scan_time=scan_timestamp, duration_ms=(time.perf_counter() - start_time) * 1000,
                error_message="Fast scan failed and SSLyze not installed",
            )
            
        # Fall back to SSLyze
        try:
            return self._sslyze_scan(target, port, start_time, scan_timestamp)
        except Exception as e:
            duration = (time.perf_counter() - start_time) * 1000
            error_msg = str(e)
            logger.error(f"Scan failed for {target}:{port}: {error_msg}", extra={"layer": 2, "target": target})
            
            status = ScanStatus.CONNECTION_ERROR
            if "timeout" in error_msg.lower():
                status = ScanStatus.TIMEOUT
            
            return TLSScanResult(
                target=target, port=port, status=status,
                scan_time=scan_timestamp, duration_ms=duration,
                error_message=error_msg,
            )

    def _fast_scan(self, target: str, port: int, scan_timestamp: str) -> TLSScanResult:
        """
        Primary scan path. Uses:
          1. nmap ssl-enum-ciphers  -> TLS versions + cipher suites
          2. Python ssl module      -> cert metadata
          3. pqcscan_bin            -> PQC detection
        """
        result = TLSScanResult(
            target=target, port=port, status=ScanStatus.SUCCESS,
            scan_time=scan_timestamp, duration_ms=0
        )
        
        # 1. Nmap probe
        self._nmap_tls_scan(target, port, result)
        
        # 2. SSL Module Probe
        ssl_info = self._ssl_module_probe(target, port)
        if ssl_info["connected"]:
            if not any([result.supports_tls10, result.supports_tls11, result.supports_tls12, result.supports_tls13]):
                version = ssl_info["tls_version"] or ""
                result.supports_tls13 = "1.3" in version
                result.supports_tls12 = "1.2" in version
                result.supports_tls11 = "1.1" in version
                result.supports_tls10 = "1.0" in version
            self._parse_cert_into_result(result, ssl_info)
        else:
            # SSL probe failed, but nmap may have succeeded.
            # Only mark as error if nmap also found nothing.
            has_nmap_data = any([result.supports_tls10, result.supports_tls11, result.supports_tls12, result.supports_tls13])
            if not has_nmap_data:
                result.status = ScanStatus.CONNECTION_ERROR
                result.error_message = "Fast scan: Could not connect via Python SSL proxy"
                # Still try PQC probe before returning — the server may accept
                # pqcscan_bin's ClientHello even if Python ssl module was rejected.
                self._apply_pqc_probe(result, target, port)
                return result
        
        # 3. PQC Probe
        self._apply_pqc_probe(result, target, port)
        
        logger.info(f"Fast scan completed for {target}:{port}", extra={
            "layer": 2,
            "target": target,
            "data": {
                "tls_versions": [
                    v for v, s in [("1.0", result.supports_tls10), ("1.1", result.supports_tls11),
                                   ("1.2", result.supports_tls12), ("1.3", result.supports_tls13)] if s
                ],
                "key_exchanges": result.key_exchange_algorithms
            }
        })
        
        return result

    def _nmap_tls_scan(self, host: str, port: int, result: TLSScanResult):
        if not _NMAP_BIN:
            return
        
        try:
            cmd = [_NMAP_BIN, "--script", "ssl-enum-ciphers", "-p", str(port), host, "--script-timeout", "10s"]
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=20, stdin=subprocess.DEVNULL)
            output = proc.stdout
            
            if "TLSv1.0" in output: result.supports_tls10 = True
            if "TLSv1.1" in output: result.supports_tls11 = True
            if "TLSv1.2" in output: result.supports_tls12 = True
            if "TLSv1.3" in output: result.supports_tls13 = True
            
            cipher_suites = []
            for line in output.splitlines():
                stripped = line.strip().lstrip("|").strip()
                if stripped.startswith("TLS_"):
                    suite_name = stripped.split()[0]
                    cipher_suites.append(suite_name)
                    if "TLSv1.2" in output: # Approximation since nmap splits by version
                        if suite_name not in result.tls12_cipher_suites:
                            result.tls12_cipher_suites.append(suite_name)
                    if "TLSv1.3" in output:
                        if suite_name not in result.tls13_cipher_suites:
                            result.tls13_cipher_suites.append(suite_name)
            
            all_ciphers = result.tls12_cipher_suites + result.tls13_cipher_suites
            result.key_exchange_algorithms = self._extract_key_exchanges(all_ciphers, has_tls13=result.supports_tls13)
        except Exception as e:
            logger.warning(f"nmap probe failed for {host}:{port}: {e}")

    def _ssl_module_probe(self, host: str, port: int) -> dict:
        info = {"connected": False, "tls_version": None, "cipher": None, "cert_der": None}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    info["connected"] = True
                    info["tls_version"] = ssock.version()
                    info["cipher"] = ssock.cipher()[0]
                    info["cert_der"] = ssock.getpeercert(binary_form=True)
        except Exception as e:
            logger.warning(f"ssl probe failed for {host}:{port}: {e}")
        return info

    def _parse_cert_into_result(self, db_result: TLSScanResult, ssl_info: dict):
        if not ssl_info.get("cert_der"):
            return
        cert = CertificateInfo()
        try:
            from cryptography import x509 as crypto_x509
            from cryptography.x509.oid import ExtensionOID
            c = crypto_x509.load_der_x509_certificate(ssl_info["cert_der"])
            
            cert.subject = c.subject.rfc4514_string()
            cert.issuer = c.issuer.rfc4514_string()
            cert.serial_number = format(c.serial_number, 'x')
            
            try:
                cert.not_after = c.not_valid_after_utc.isoformat()
                cert.not_before = c.not_valid_before_utc.isoformat()
            except AttributeError:
                cert.not_after = str(c.not_valid_after)
                cert.not_before = str(c.not_valid_before)
                
            pub_key = c.public_key()
            cert.public_key_algorithm = type(pub_key).__name__.replace("PublicKey", "").replace("_", "-")
            cert.public_key_size = getattr(pub_key, "key_size", None)
            
            cert.signature_algorithm = c.signature_algorithm_oid._name if hasattr(c.signature_algorithm_oid, '_name') else str(c.signature_algorithm_oid)
            cert.is_self_signed = cert.subject == cert.issuer
            
            try:
                san_ext = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                cert.san_entries = [name.value for name in san_ext.value if hasattr(name, 'value') and isinstance(name.value, str)]
            except Exception:
                pass
                
            db_result.certificate = cert
            db_result.certificate_chain_length = 1 
        except Exception as e:
            logger.warning(f"DER cert parse failed: {e}")

    def _apply_pqc_probe(self, db_result: TLSScanResult, host: str, port: int):
        is_pqc = False
        pqc_algo = None
        
        logger.info(f"PQC probe: {host}:{port}")
        
        # Priority 1: pqcscan_bin (Rust binary with real PQC ClientHello)
        try:
            if _PQCSCAN_BIN:
                with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
                    tmp_path = tmp.name
                try:
                    subprocess.run(
                        [_PQCSCAN_BIN, "tls-scan", "-t", f"{host}:{port}", "-o", tmp_path, "--num-threads", "1"],
                        capture_output=True, text=True, check=False, timeout=15, stdin=subprocess.DEVNULL
                    )
                    with open(tmp_path) as f:
                        data = json.load(f)
                    tls = data["results"][0]["Tls"]
                    is_pqc = tls.get("pqc_supported", False)
                    hybrid_algos = tls.get("hybrid_algos", [])
                    pqc_algos = tls.get("pqc_algos", [])
                    
                    if hybrid_algos:
                        pqc_algo = hybrid_algos[0]
                    elif pqc_algos:
                        pqc_algo = pqc_algos[0]
                except (json.JSONDecodeError, KeyError, IndexError) as e:
                    logger.warning(f"pqcscan_bin parse failed for {host}: {e}")
                except subprocess.TimeoutExpired:
                    logger.warning(f"pqcscan_bin timed out for {host}:{port}")
                finally:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
        except PermissionError:
            logger.error(f"Permission denied: {_PQCSCAN_BIN} — run: chmod +x {_PQCSCAN_BIN}")
        except Exception as e:
            logger.error(f"PQC probe pqcscan_bin error for {host}: {e}")
        
        # Priority 2: nmap fallback — grep ssl-enum-ciphers output for PQC patterns
        if not is_pqc and _NMAP_BIN:
            try:
                result = subprocess.run(
                    [_NMAP_BIN, "--script", "ssl-enum-ciphers",
                     "-p", str(port), host,
                     "--script-timeout", "10s"],
                    capture_output=True, text=True,
                    check=False, timeout=20, stdin=subprocess.DEVNULL,
                )
                for line in result.stdout.splitlines():
                    if not _NMAP_CIPHER_LINE_RE.match(line):
                        continue
                    m = _PQC_KEM_RE.search(line)
                    if m:
                        is_pqc = True
                        pqc_algo = f"Hybrid ML-KEM ({m.group(0)})"
                        break
                    m = _PQC_SIG_RE.search(line)
                    if m:
                        is_pqc = True
                        pqc_algo = f"PQC Signature ({m.group(0)})"
                        break
            except subprocess.TimeoutExpired:
                logger.warning(f"PQC nmap probe timed out for {host}:{port}")
            except Exception as e:
                logger.error(f"PQC nmap probe error for {host}: {e}")
        
        logger.info(f"PQC result: {host} → pqc={is_pqc} algo={pqc_algo}")
        
        db_result.cert_is_pqc = is_pqc
        db_result.cert_pqc_algorithm = pqc_algo
        
        # Merge this into key exchanges if we found one so the Classifier picks it up
        if pqc_algo and pqc_algo not in db_result.key_exchange_algorithms:
            db_result.key_exchange_algorithms.append(pqc_algo)

    def _sslyze_scan(self, target: str, port: int, start_time: float, scan_timestamp: str) -> TLSScanResult:
        """Original SSLyze scanning functionality as a fallback"""
        from sslyze import Scanner as SslyzeScanner, ServerNetworkLocation, ServerScanRequest, ScanCommand
        
        server_location = ServerNetworkLocation(hostname=target, port=port)
        scan_request = ServerScanRequest(
            server_location=server_location,
            scan_commands={
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.HEARTBLEED,
                ScanCommand.TLS_FALLBACK_SCSV,
            }
        )
        
        scanner = SslyzeScanner()
        scanner.queue_scans([scan_request])
        
        for result in scanner.get_results():
            duration = (time.perf_counter() - start_time) * 1000
            
            parsed = self._parse_sslyze_result(target, port, result, scan_timestamp, duration)
            self._apply_pqc_probe(parsed, target, port)
            return parsed

    def _parse_sslyze_result(self, target: str, port: int, scan_result, scan_time: str, duration: float) -> TLSScanResult:
        results = scan_result.scan_result
        result = TLSScanResult(target=target, port=port, status=ScanStatus.SUCCESS, scan_time=scan_time, duration_ms=duration)
        
        if results is None:
            result.status = ScanStatus.FAILED
            result.error_message = "Scan returned no results"
            return result
        
        result.supports_tls10 = self._check_tls_support(getattr(results, 'tls_1_0_cipher_suites', None))
        result.supports_tls11 = self._check_tls_support(getattr(results, 'tls_1_1_cipher_suites', None))
        result.supports_tls12 = self._check_tls_support(getattr(results, 'tls_1_2_cipher_suites', None))
        result.supports_tls13 = self._check_tls_support(getattr(results, 'tls_1_3_cipher_suites', None))
        
        result.tls12_cipher_suites = self._extract_cipher_suites(getattr(results, 'tls_1_2_cipher_suites', None))
        result.tls13_cipher_suites = self._extract_cipher_suites(getattr(results, 'tls_1_3_cipher_suites', None))
        
        all_ciphers = result.tls12_cipher_suites + result.tls13_cipher_suites
        result.key_exchange_algorithms = self._extract_key_exchanges(all_ciphers, has_tls13=result.supports_tls13)
        
        cert_info = getattr(results, 'certificate_info', None)
        if cert_info and getattr(cert_info, 'result', None):
            result.certificate = self._parse_certificate(cert_info.result)
            if getattr(cert_info.result, 'certificate_deployments', None):
                result.certificate_chain_length = len(cert_info.result.certificate_deployments[0].received_certificate_chain)
        
        heartbleed = getattr(results, 'heartbleed', None)
        if heartbleed and getattr(heartbleed, 'result', None):
            result.vulnerable_to_heartbleed = getattr(heartbleed.result, 'is_vulnerable_to_heartbleed', False)
        
        fallback = getattr(results, 'tls_fallback_scsv', None)
        if fallback and getattr(fallback, 'result', None):
            result.supports_fallback_scsv = getattr(fallback.result, 'supports_fallback_scsv', True)
            
        return result

    def _check_tls_support(self, cipher_result) -> bool:
        if not cipher_result or not cipher_result.result:
            return False
        return len(cipher_result.result.accepted_cipher_suites) > 0
    
    def _extract_cipher_suites(self, cipher_result) -> List[str]:
        if not cipher_result or not cipher_result.result:
            return []
        return [cs.cipher_suite.name for cs in cipher_result.result.accepted_cipher_suites]
    
    def _extract_key_exchanges(self, cipher_suites: List[str], has_tls13: bool = False) -> List[str]:
        key_exchanges = set()
        for cipher in cipher_suites:
            cipher_upper = cipher.upper()
            if "TLS_AES" in cipher_upper or "TLS_CHACHA" in cipher_upper:
                key_exchanges.add("X25519")
                key_exchanges.add("ECDHE")
                continue
            for pattern, kex_name in self.KEY_EXCHANGE_PATTERNS.items():
                if pattern in cipher_upper:
                    key_exchanges.add(kex_name)
                    break
            if "P256" in cipher_upper or "SECP256R1" in cipher_upper:
                key_exchanges.add("ECDHE-P256")
            elif "P384" in cipher_upper or "SECP384R1" in cipher_upper:
                key_exchanges.add("ECDHE-P384")
            elif "X25519" in cipher_upper:
                key_exchanges.add("X25519")
        if has_tls13 and not key_exchanges:
            key_exchanges.add("X25519")
            key_exchanges.add("ECDHE")
        return list(key_exchanges)
    
    def _parse_certificate(self, cert_info) -> CertificateInfo:
        cert = CertificateInfo()
        try:
            deployments = cert_info.certificate_deployments
            if not deployments: return cert
            leaf_cert = deployments[0].received_certificate_chain[0]
            cert.subject = leaf_cert.subject.rfc4514_string()
            cert.issuer = leaf_cert.issuer.rfc4514_string()
            cert.serial_number = format(leaf_cert.serial_number, 'x')
            cert.not_before = leaf_cert.not_valid_before_utc.isoformat() if hasattr(leaf_cert, 'not_valid_before_utc') else str(leaf_cert.not_valid_before)
            cert.not_after = leaf_cert.not_valid_after_utc.isoformat() if hasattr(leaf_cert, 'not_valid_after_utc') else str(leaf_cert.not_valid_after)
            from datetime import timezone
            now = datetime.now(timezone.utc)
            expiry = leaf_cert.not_valid_after_utc if hasattr(leaf_cert, 'not_valid_after_utc') else leaf_cert.not_valid_after
            if expiry.tzinfo is None: expiry = expiry.replace(tzinfo=timezone.utc)
            cert.is_expired = now > expiry
            public_key = leaf_cert.public_key()
            cert.public_key_algorithm = public_key.__class__.__name__.replace("PublicKey", "").replace("_", "-")
            cert.public_key_size = getattr(public_key, 'key_size', None)
            cert.signature_algorithm = leaf_cert.signature_algorithm_oid._name if hasattr(leaf_cert.signature_algorithm_oid, '_name') else str(leaf_cert.signature_algorithm_oid)
            cert.is_self_signed = cert.subject == cert.issuer
            try:
                from cryptography.x509 import SubjectAlternativeName, DNSName
                san_ext = leaf_cert.extensions.get_extension_for_class(SubjectAlternativeName)
                cert.san_entries = [name.value for name in san_ext.value if isinstance(name, DNSName)]
            except Exception:
                pass
        except Exception as e:
            logger.warning(f"Error parsing certificate: {e}")
        return cert


_scanner = None

def get_scanner(timeout: int = 30) -> TLSScanner:
    global _scanner
    if _scanner is None:
        _scanner = TLSScanner(timeout=timeout)
    return _scanner

def scan_target(target: str, port: int = 443) -> TLSScanResult:
    return get_scanner().scan(target, port)
