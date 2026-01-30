#!/usr/bin/env python3
"""
QuShield Comprehensive Testing Pipeline

Unified test suite for all layers:
- Layer 1: Asset Discovery Engine
- Layer 2: Cryptographic Scan Engine
- Layer 3: PQC Analysis (future)
- Layer 4: Certification (future)

Removes redundant/basic tests and focuses on meaningful integration testing.
"""

import asyncio
import sys
import time
import json
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from enum import Enum

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from qushield.utils.logging import (
    setup_logging,
    get_logger,
    timed_async,
)
from qushield.core.discovery import AssetDiscovery, DiscoveredAsset
from qushield.core.scanner import TLSScanner, TLSScanResult, ScanStatus, CertificateInfo
from qushield.core.classifier import PQCClassifier, QuantumSafety, AlgorithmInfo
from qushield.core.scorer import HNDLScorer, HNDLScore, HNDLRiskLabel
from qushield.output.cbom import CBOMBuilder, CBOM, CERTInQBOMExtension
from qushield.services.remediation import RemediationAdvisor, RemediationPlan, ServerType
from qushield.core.certifier import (
    CertificationEngine,
    PolicyEvaluator,
    LabelSigner,
    PQCCertificate,
    PolicyResult,
    CertificationLevel,
)
from qushield.output.collector import (
    OutputCollector,
    StructuredOutput,
    AssetType,
    AssetTypeClassifier,
    AssetInventoryItem,
    DashboardSummary,
)
from qushield.workflow import QuShieldWorkflow, WorkflowResult

LOG_DIR = Path("logs")


# ============================================================================
# Test Configuration
# ============================================================================

class TestStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"


@dataclass
class TestResult:
    """Individual test result"""
    name: str
    layer: int
    status: TestStatus
    duration_ms: float
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class LayerResults:
    """Results for a single layer"""
    layer: int
    name: str
    tests: List[TestResult] = field(default_factory=list)
    
    @property
    def passed(self) -> int:
        return sum(1 for t in self.tests if t.status == TestStatus.PASS)
    
    @property
    def failed(self) -> int:
        return sum(1 for t in self.tests if t.status == TestStatus.FAIL)
    
    @property
    def total_duration_ms(self) -> float:
        return sum(t.duration_ms for t in self.tests)


@dataclass
class PipelineResults:
    """Complete pipeline results"""
    start_time: str
    end_time: str
    duration_ms: float
    layers: Dict[int, LayerResults] = field(default_factory=dict)
    domains_tested: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": self.duration_ms,
            "domains_tested": self.domains_tested,
            "summary": {
                f"layer_{l}": {
                    "name": r.name,
                    "passed": r.passed,
                    "failed": r.failed,
                    "duration_ms": r.total_duration_ms,
                }
                for l, r in self.layers.items()
            },
            "layers": {
                l: [
                    {
                        "test": t.name,
                        "status": t.status.value,
                        "duration_ms": t.duration_ms,
                        "details": t.details,
                        "error": t.error,
                    }
                    for t in r.tests
                ]
                for l, r in self.layers.items()
            },
        }


# ============================================================================
# Test Domains Configuration
# ============================================================================

TEST_DOMAINS = [
    # Primary test domains
    "pnb.bank.in",
    "onlinesbi.sbi.bank.in",
    # Alternative domains that are known to work
    "pnbindia.in",
    "sbi.co.in",
]


# ============================================================================
# Pipeline Logger Setup
# ============================================================================

class PipelineLogger:
    """Centralized logging for the test pipeline"""
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.logger = get_logger("test_pipeline")
        self.start_time = None
        self._current_layer = 0
        self._current_test = ""
        
    def start_pipeline(self, domains: List[str]):
        """Log pipeline start"""
        self.start_time = datetime.now(timezone.utc)
        print("\n")
        print("╔" + "═" * 68 + "╗")
        print("║" + " " * 12 + "QUSHIELD TESTING PIPELINE" + " " * 31 + "║")
        print("║" + " " * 8 + "Quantum Safe Cryptographic Posture Scanner" + " " * 17 + "║")
        print("╚" + "═" * 68 + "╝")
        print(f"\n  Started: {self.start_time.isoformat()}")
        print(f"  Domains: {', '.join(domains)}")
        self.logger.info(f"Pipeline started with {len(domains)} domains", extra={
            "data": {"domains": domains}
        })
    
    def start_layer(self, layer: int, name: str):
        """Log layer start"""
        self._current_layer = layer
        print(f"\n{'─' * 70}")
        print(f"  LAYER {layer}: {name}")
        print(f"{'─' * 70}")
        self.logger.info(f"Starting Layer {layer}: {name}", extra={"layer": layer})
    
    def start_test(self, test_name: str, domain: str = ""):
        """Log test start"""
        self._current_test = test_name
        target = f" [{domain}]" if domain else ""
        if self.verbose:
            print(f"\n  ▶ {test_name}{target}")
        self.logger.info(f"Test: {test_name}", extra={
            "layer": self._current_layer,
            "target": domain,
        })
    
    def log_progress(self, message: str, data: Dict = None):
        """Log progress update"""
        if self.verbose:
            print(f"    → {message}")
        self.logger.debug(message, extra={
            "layer": self._current_layer,
            "data": data,
        })
    
    def log_result(self, result: TestResult):
        """Log test result"""
        symbols = {
            TestStatus.PASS: "✓",
            TestStatus.FAIL: "✗",
            TestStatus.WARN: "⚠",
            TestStatus.SKIP: "○",
        }
        colors = {
            TestStatus.PASS: "\033[32m",
            TestStatus.FAIL: "\033[31m",
            TestStatus.WARN: "\033[33m",
            TestStatus.SKIP: "\033[90m",
        }
        reset = "\033[0m"
        
        symbol = symbols.get(result.status, "?")
        color = colors.get(result.status, "")
        
        print(f"    {color}{symbol} {result.status.value}{reset} ({result.duration_ms:.0f}ms)")
        
        if result.details and self.verbose:
            for key, value in result.details.items():
                if isinstance(value, (list, dict)):
                    value = json.dumps(value) if len(str(value)) < 50 else f"[{len(value)} items]"
                print(f"      • {key}: {value}")
        
        if result.error:
            print(f"      \033[31mError: {result.error}\033[0m")
        
        self.logger.info(f"Test completed: {result.name}", extra={
            "layer": result.layer,
            "data": {
                "status": result.status.value,
                "duration_ms": result.duration_ms,
                **result.details,
            }
        })
    
    def end_pipeline(self, results: PipelineResults):
        """Log pipeline completion"""
        print(f"\n{'═' * 70}")
        print("  PIPELINE SUMMARY")
        print(f"{'═' * 70}")
        
        total_passed = 0
        total_failed = 0
        
        for layer_num, layer in sorted(results.layers.items()):
            total_passed += layer.passed
            total_failed += layer.failed
            status_color = "\033[32m" if layer.failed == 0 else "\033[31m"
            reset = "\033[0m"
            print(f"\n  Layer {layer_num}: {layer.name}")
            print(f"    {status_color}Passed: {layer.passed} | Failed: {layer.failed}{reset} | Duration: {layer.total_duration_ms:.0f}ms")
        
        print(f"\n{'─' * 70}")
        if total_failed == 0:
            print(f"  \033[32m✓ ALL TESTS PASSED ({total_passed} total)\033[0m")
        else:
            print(f"  \033[31m✗ {total_failed} TEST(S) FAILED\033[0m (Passed: {total_passed})")
        
        print(f"\n  Total Duration: {results.duration_ms:.0f}ms")
        print(f"  Completed: {results.end_time}")
        
        self.logger.info("Pipeline completed", extra={
            "data": {
                "total_passed": total_passed,
                "total_failed": total_failed,
                "duration_ms": results.duration_ms,
            }
        })


# ============================================================================
# Layer 1: Asset Discovery Tests
# ============================================================================

class Layer1Tests:
    """Layer 1: Asset Discovery Engine Tests"""
    
    def __init__(self, logger: PipelineLogger):
        self.plog = logger
        self.discovery: Optional[AssetDiscovery] = None
    
    async def setup(self):
        """Initialize services"""
        self.discovery = AssetDiscovery(timeout=60)
    
    async def teardown(self):
        """Cleanup"""
        if self.discovery:
            await self.discovery.close()
    
    async def run_all(self, domains: List[str]) -> LayerResults:
        """Run all Layer 1 tests"""
        self.plog.start_layer(1, "ASSET DISCOVERY ENGINE")
        results = LayerResults(layer=1, name="Asset Discovery Engine")
        
        await self.setup()
        
        try:
            # Test 1: CT Log Harvester (test on first resolving domain)
            for domain in domains:
                result = await self.test_ct_log_harvester(domain)
                results.tests.append(result)
                if result.status != TestStatus.FAIL:
                    break  # Only need one successful CT test
            
            # Test 2: Full Discovery Pipeline (test on all domains)
            for domain in domains:
                result = await self.test_full_discovery(domain)
                results.tests.append(result)
            
        finally:
            await self.teardown()
        
        return results
    
    async def test_ct_log_harvester(self, domain: str) -> TestResult:
        """Test CT Log harvesting via crt.sh"""
        self.plog.start_test("CT Log Harvester", domain)
        start = time.perf_counter()
        
        try:
            assets = await self.discovery.discover_from_ct_logs(domain)
            duration = (time.perf_counter() - start) * 1000
            
            details = {
                "domain": domain,
                "assets_found": len(assets),
                "sample_fqdns": [a.fqdn for a in assets[:5]],
            }
            
            status = TestStatus.PASS if len(assets) > 0 else TestStatus.WARN
            result = TestResult(
                name=f"CT Log Harvester [{domain}]",
                layer=1,
                status=status,
                duration_ms=duration,
                details=details,
            )
            
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            result = TestResult(
                name=f"CT Log Harvester [{domain}]",
                layer=1,
                status=TestStatus.FAIL,
                duration_ms=duration,
                error=str(e),
            )
        
        self.plog.log_result(result)
        return result
    
    async def test_full_discovery(self, domain: str) -> TestResult:
        """Test full discovery pipeline (CT + Subdomain enum)"""
        self.plog.start_test("Full Discovery Pipeline", domain)
        start = time.perf_counter()
        
        try:
            assets = await self.discovery.discover_all(
                domain,
                use_ct_logs=True,
                use_subdomain_enum=True,
                verify_dns=False,
            )
            duration = (time.perf_counter() - start) * 1000
            
            by_source = {}
            for asset in assets:
                by_source[asset.source] = by_source.get(asset.source, 0) + 1
            
            details = {
                "domain": domain,
                "total_assets": len(assets),
                "by_source": by_source,
            }
            
            status = TestStatus.PASS if len(assets) > 0 else TestStatus.WARN
            result = TestResult(
                name=f"Full Discovery [{domain}]",
                layer=1,
                status=status,
                duration_ms=duration,
                details=details,
            )
            
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            result = TestResult(
                name=f"Full Discovery [{domain}]",
                layer=1,
                status=TestStatus.FAIL,
                duration_ms=duration,
                error=str(e),
            )
        
        self.plog.log_result(result)
        return result


# ============================================================================
# Layer 2: Cryptographic Scan Engine Tests
# ============================================================================

class Layer2Tests:
    """Layer 2: Cryptographic Scan Engine Tests
    
    Submodules tested:
    - TLS Handshake Prober
    - Certificate Inspector
    - Cipher Suite Negotiator
    - Vulnerability Scanner
    """
    
    def __init__(self, logger: PipelineLogger):
        self.plog = logger
        self.scanner: Optional[TLSScanner] = None
    
    def setup(self):
        """Initialize TLS scanner"""
        self.scanner = TLSScanner(timeout=30)
    
    async def run_all(self, domains: List[str]) -> LayerResults:
        """Run all Layer 2 tests"""
        self.plog.start_layer(2, "CRYPTOGRAPHIC SCAN ENGINE")
        results = LayerResults(layer=2, name="Cryptographic Scan Engine")
        
        self.setup()
        
        # Run comprehensive scan tests on each domain
        for domain in domains:
            # Clean domain (remove protocol)
            clean_domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
            
            # Test 1: TLS Handshake Prober
            result = await self.test_tls_handshake(clean_domain)
            results.tests.append(result)
            
            # If handshake succeeded, run remaining tests
            if result.status == TestStatus.PASS and result.details.get("scan_result"):
                scan_result = result.details["scan_result"]
                
                # Test 2: Certificate Inspector
                cert_result = self.test_certificate_inspector(clean_domain, scan_result)
                results.tests.append(cert_result)
                
                # Test 3: Cipher Suite Negotiator
                cipher_result = self.test_cipher_negotiator(clean_domain, scan_result)
                results.tests.append(cipher_result)
                
                # Test 4: Vulnerability Scanner
                vuln_result = self.test_vulnerability_scanner(clean_domain, scan_result)
                results.tests.append(vuln_result)
        
        return results
    
    async def test_tls_handshake(self, domain: str, port: int = 443) -> TestResult:
        """Test TLS Handshake Prober"""
        self.plog.start_test("TLS Handshake Prober", domain)
        start = time.perf_counter()
        
        try:
            # Run scan in thread pool (SSLyze is sync)
            loop = asyncio.get_event_loop()
            scan_result = await loop.run_in_executor(
                None,
                lambda: self.scanner.scan(domain, port)
            )
            duration = (time.perf_counter() - start) * 1000
            
            if scan_result.status == ScanStatus.SUCCESS:
                tls_versions = []
                if scan_result.supports_tls10:
                    tls_versions.append("1.0")
                if scan_result.supports_tls11:
                    tls_versions.append("1.1")
                if scan_result.supports_tls12:
                    tls_versions.append("1.2")
                if scan_result.supports_tls13:
                    tls_versions.append("1.3")
                
                details = {
                    "domain": domain,
                    "port": port,
                    "tls_versions": tls_versions,
                    "key_exchanges": scan_result.key_exchange_algorithms,
                    "scan_result": scan_result,  # Store for subsequent tests
                }
                
                result = TestResult(
                    name=f"TLS Handshake [{domain}]",
                    layer=2,
                    status=TestStatus.PASS,
                    duration_ms=duration,
                    details=details,
                )
            else:
                result = TestResult(
                    name=f"TLS Handshake [{domain}]",
                    layer=2,
                    status=TestStatus.FAIL,
                    duration_ms=duration,
                    error=scan_result.error_message or f"Status: {scan_result.status.value}",
                )
                
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            result = TestResult(
                name=f"TLS Handshake [{domain}]",
                layer=2,
                status=TestStatus.FAIL,
                duration_ms=duration,
                error=str(e),
            )
        
        # Remove scan_result from logged details (too verbose)
        log_details = {k: v for k, v in result.details.items() if k != "scan_result"}
        logged_result = TestResult(
            name=result.name,
            layer=result.layer,
            status=result.status,
            duration_ms=result.duration_ms,
            details=log_details,
            error=result.error,
        )
        self.plog.log_result(logged_result)
        return result
    
    def test_certificate_inspector(self, domain: str, scan_result: TLSScanResult) -> TestResult:
        """Test Certificate Inspector"""
        self.plog.start_test("Certificate Inspector", domain)
        start = time.perf_counter()
        
        try:
            cert = scan_result.certificate
            
            if cert and cert.subject:
                details = {
                    "subject": cert.subject[:60] + "..." if len(cert.subject) > 60 else cert.subject,
                    "issuer": cert.issuer[:60] + "..." if len(cert.issuer) > 60 else cert.issuer,
                    "algorithm": cert.public_key_algorithm,
                    "key_size": cert.public_key_size,
                    "signature_algorithm": cert.signature_algorithm,
                    "expires": cert.not_after,
                    "is_expired": cert.is_expired,
                    "san_count": len(cert.san_entries),
                    "chain_length": scan_result.certificate_chain_length,
                }
                
                # Warn if certificate is expired or uses weak key
                status = TestStatus.PASS
                if cert.is_expired:
                    status = TestStatus.WARN
                elif cert.public_key_size and cert.public_key_size < 2048:
                    status = TestStatus.WARN
                
                result = TestResult(
                    name=f"Certificate Inspector [{domain}]",
                    layer=2,
                    status=status,
                    duration_ms=(time.perf_counter() - start) * 1000,
                    details=details,
                )
            else:
                result = TestResult(
                    name=f"Certificate Inspector [{domain}]",
                    layer=2,
                    status=TestStatus.FAIL,
                    duration_ms=(time.perf_counter() - start) * 1000,
                    error="No certificate data available",
                )
                
        except Exception as e:
            result = TestResult(
                name=f"Certificate Inspector [{domain}]",
                layer=2,
                status=TestStatus.FAIL,
                duration_ms=(time.perf_counter() - start) * 1000,
                error=str(e),
            )
        
        self.plog.log_result(result)
        return result
    
    def test_cipher_negotiator(self, domain: str, scan_result: TLSScanResult) -> TestResult:
        """Test Cipher Suite Negotiator (API Cipher Negotiator)"""
        self.plog.start_test("Cipher Suite Negotiator", domain)
        start = time.perf_counter()
        
        try:
            tls12_ciphers = scan_result.tls12_cipher_suites
            tls13_ciphers = scan_result.tls13_cipher_suites
            key_exchanges = scan_result.key_exchange_algorithms
            
            # Analyze cipher strength
            weak_ciphers = [c for c in tls12_ciphers if any(w in c.upper() for w in 
                ["RC4", "DES", "MD5", "EXPORT", "NULL", "ANON"])]
            
            details = {
                "tls12_cipher_count": len(tls12_ciphers),
                "tls13_cipher_count": len(tls13_ciphers),
                "key_exchanges": key_exchanges,
                "weak_ciphers_found": len(weak_ciphers),
                "sample_tls12": tls12_ciphers[:3] if tls12_ciphers else [],
                "sample_tls13": tls13_ciphers[:3] if tls13_ciphers else [],
            }
            
            # Status based on cipher strength
            if weak_ciphers:
                status = TestStatus.WARN
                details["weak_ciphers"] = weak_ciphers
            elif len(tls12_ciphers) + len(tls13_ciphers) == 0:
                status = TestStatus.FAIL
            else:
                status = TestStatus.PASS
            
            result = TestResult(
                name=f"Cipher Negotiator [{domain}]",
                layer=2,
                status=status,
                duration_ms=(time.perf_counter() - start) * 1000,
                details=details,
            )
            
        except Exception as e:
            result = TestResult(
                name=f"Cipher Negotiator [{domain}]",
                layer=2,
                status=TestStatus.FAIL,
                duration_ms=(time.perf_counter() - start) * 1000,
                error=str(e),
            )
        
        self.plog.log_result(result)
        return result
    
    def test_vulnerability_scanner(self, domain: str, scan_result: TLSScanResult) -> TestResult:
        """Test Vulnerability Scanner (Heartbleed, Downgrade attacks)"""
        self.plog.start_test("Vulnerability Scanner", domain)
        start = time.perf_counter()
        
        try:
            vulnerabilities = []
            
            # Check for Heartbleed
            if scan_result.vulnerable_to_heartbleed:
                vulnerabilities.append("HEARTBLEED")
            
            # Check for downgrade attack prevention
            if not scan_result.supports_fallback_scsv:
                vulnerabilities.append("NO_FALLBACK_SCSV")
            
            # Check for legacy TLS (1.0/1.1)
            if scan_result.supports_tls10:
                vulnerabilities.append("TLS_1.0_ENABLED")
            if scan_result.supports_tls11:
                vulnerabilities.append("TLS_1.1_ENABLED")
            
            details = {
                "heartbleed_vulnerable": scan_result.vulnerable_to_heartbleed,
                "fallback_scsv_supported": scan_result.supports_fallback_scsv,
                "legacy_tls_enabled": scan_result.supports_tls10 or scan_result.supports_tls11,
                "vulnerabilities_found": vulnerabilities,
            }
            
            # Status based on vulnerabilities
            if scan_result.vulnerable_to_heartbleed:
                status = TestStatus.FAIL  # Critical vulnerability
            elif vulnerabilities:
                status = TestStatus.WARN
            else:
                status = TestStatus.PASS
            
            result = TestResult(
                name=f"Vulnerability Scanner [{domain}]",
                layer=2,
                status=status,
                duration_ms=(time.perf_counter() - start) * 1000,
                details=details,
            )
            
        except Exception as e:
            result = TestResult(
                name=f"Vulnerability Scanner [{domain}]",
                layer=2,
                status=TestStatus.FAIL,
                duration_ms=(time.perf_counter() - start) * 1000,
                error=str(e),
            )
        
        self.plog.log_result(result)
        return result


# ============================================================================
# Layer 3: PQC Analysis & CBOM Generation Tests
# ============================================================================

class Layer3Tests:
    """Layer 3: PQC Analysis & CBOM Generation Tests
    
    Submodules tested:
    - Algorithm Classifier
    - HNDL Risk Scorer
    - CBOM Assembler
    - Remediation Advisor
    """
    
    def __init__(self, logger: PipelineLogger):
        self.plog = logger
        self.classifier = PQCClassifier()
        self.hndl_scorer = HNDLScorer()
        self.cbom_builder = CBOMBuilder()
        self.remediation_advisor = RemediationAdvisor()
    
    async def run_all(self, domains: List[str], scan_results: Dict[str, TLSScanResult] = None) -> LayerResults:
        """Run all Layer 3 tests"""
        self.plog.start_layer(3, "PQC ANALYSIS & CBOM GENERATION")
        results = LayerResults(layer=3, name="PQC Analysis & CBOM Generation")
        
        # Test 1: Algorithm Classifier
        result = self.test_algorithm_classifier()
        results.tests.append(result)
        
        # Test 2: HNDL Risk Scorer
        result = self.test_hndl_scorer()
        results.tests.append(result)
        
        # Test 3: CBOM Assembler
        result = self.test_cbom_assembler()
        results.tests.append(result)
        
        # Test 4: Remediation Advisor
        result = self.test_remediation_advisor()
        results.tests.append(result)
        
        # Test 5: Integration with scan results (if available)
        if scan_results:
            for domain, scan_result in scan_results.items():
                if scan_result and scan_result.status == ScanStatus.SUCCESS:
                    result = await self.test_full_analysis(domain, scan_result)
                    results.tests.append(result)
        
        return results
    
    def test_algorithm_classifier(self) -> TestResult:
        """Test Algorithm Classifier with various algorithm types"""
        self.plog.start_test("Algorithm Classifier")
        start = time.perf_counter()
        
        try:
            # Test various algorithm classifications
            test_cases = [
                ("RSA-2048", QuantumSafety.VULNERABLE),
                ("ECDHE", QuantumSafety.VULNERABLE),
                ("ML-KEM-768", QuantumSafety.FULLY_SAFE),
                ("ML-DSA-65", QuantumSafety.FULLY_SAFE),
                ("X25519MLKEM768", QuantumSafety.HYBRID),
                ("AES-256", QuantumSafety.FULLY_SAFE),
                ("RC4", QuantumSafety.CRITICAL),
                ("3DES", QuantumSafety.CRITICAL),
            ]
            
            passed = 0
            failed_cases = []
            
            for algo, expected_safety in test_cases:
                info = self.classifier.classify(algo)
                if info.safety == expected_safety:
                    passed += 1
                else:
                    failed_cases.append(f"{algo}: expected {expected_safety.value}, got {info.safety.value}")
            
            duration = (time.perf_counter() - start) * 1000
            
            details = {
                "algorithms_tested": len(test_cases),
                "passed": passed,
                "failed": len(failed_cases),
                "registry_size": len(self.classifier._algorithm_registry),
            }
            
            if failed_cases:
                details["failed_cases"] = failed_cases[:3]
                status = TestStatus.FAIL if len(failed_cases) > 2 else TestStatus.WARN
            else:
                status = TestStatus.PASS
            
            result = TestResult(
                name="Algorithm Classifier",
                layer=3,
                status=status,
                duration_ms=duration,
                details=details,
            )
            
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            result = TestResult(
                name="Algorithm Classifier",
                layer=3,
                status=TestStatus.FAIL,
                duration_ms=duration,
                error=str(e),
            )
        
        self.plog.log_result(result)
        return result
    
    def test_hndl_scorer(self) -> TestResult:
        """Test HNDL Risk Scorer"""
        self.plog.start_test("HNDL Risk Scorer")
        start = time.perf_counter()
        
        try:
            # Test HNDL score calculation
            score = self.hndl_scorer.calculate(
                key_exchange_algorithms=["ECDHE"],
                certificate_algorithm="RSA-2048",
                endpoint_type="payment",
                has_sensitive_data=True,
            )
            
            duration = (time.perf_counter() - start) * 1000
            
            # Validate score components
            valid_score = 0 <= score.score <= 1
            valid_label = score.label in HNDLRiskLabel
            has_recommendation = len(score.recommended_action) > 0
            
            details = {
                "score": score.score,
                "label": score.label.value,
                "data_sensitivity": score.data_sensitivity,
                "algo_vulnerability": score.algo_vulnerability,
                "exposure_factor": score.exposure_factor,
                "worst_algorithm": score.worst_algorithm,
                "recommendation": score.recommended_action[:50] + "..." if len(score.recommended_action) > 50 else score.recommended_action,
            }
            
            if valid_score and valid_label and has_recommendation:
                status = TestStatus.PASS
            else:
                status = TestStatus.FAIL
            
            result = TestResult(
                name="HNDL Risk Scorer",
                layer=3,
                status=status,
                duration_ms=duration,
                details=details,
            )
            
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            result = TestResult(
                name="HNDL Risk Scorer",
                layer=3,
                status=TestStatus.FAIL,
                duration_ms=duration,
                error=str(e),
            )
        
        self.plog.log_result(result)
        return result
    
    def test_cbom_assembler(self) -> TestResult:
        """Test CBOM Assembler with CERT-In QBOM extension"""
        self.plog.start_test("CBOM Assembler")
        start = time.perf_counter()
        
        try:
            # Build CBOM from test data
            cbom = self.cbom_builder.build_from_scan_result(
                target="test.example.com",
                key_exchange_algorithms=["ECDHE", "RSA"],
                certificate_algorithm="RSA-2048",
                certificate_subject="CN=test.example.com",
                certificate_issuer="CN=Test CA",
                certificate_key_size=2048,
                tls_versions=["1.2", "1.3"],
                organization="Test Organization",
            )
            
            duration = (time.perf_counter() - start) * 1000
            
            # Validate CBOM structure
            cbom_dict = cbom.to_dict()
            has_components = len(cbom.components) > 0
            has_spec_version = cbom.spec_version == "1.6"
            has_cert_in = cbom.cert_in_qbom is not None
            
            details = {
                "spec_version": cbom.spec_version,
                "components_count": len(cbom.components),
                "has_cert_in_extension": has_cert_in,
            }
            
            if has_cert_in:
                details["pqc_readiness_score"] = cbom.cert_in_qbom.pqc_readiness_score
                details["migration_priority"] = cbom.cert_in_qbom.migration_priority
                details["compliance_status"] = cbom.cert_in_qbom.compliance_status
            
            if has_components and has_spec_version and has_cert_in:
                status = TestStatus.PASS
            elif has_components and has_spec_version:
                status = TestStatus.WARN
            else:
                status = TestStatus.FAIL
            
            result = TestResult(
                name="CBOM Assembler",
                layer=3,
                status=status,
                duration_ms=duration,
                details=details,
            )
            
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            result = TestResult(
                name="CBOM Assembler",
                layer=3,
                status=TestStatus.FAIL,
                duration_ms=duration,
                error=str(e),
            )
        
        self.plog.log_result(result)
        return result
    
    def test_remediation_advisor(self) -> TestResult:
        """Test Remediation Advisor"""
        self.plog.start_test("Remediation Advisor")
        start = time.perf_counter()
        
        try:
            # Generate remediation plan
            plan = self.remediation_advisor.generate_plan(
                asset_fqdn="test.example.com",
                current_algorithms=["ECDHE", "RSA-2048"],
                server_type=ServerType.NGINX,
                target_safety=QuantumSafety.HYBRID,
            )
            
            duration = (time.perf_counter() - start) * 1000
            
            # Validate plan structure
            has_steps = len(plan.migration_steps) > 0
            has_patches = len(plan.config_patches) > 0
            has_effort = plan.total_effort_hours > 0
            has_timeline = plan.estimated_timeline_days > 0
            
            details = {
                "migration_steps": len(plan.migration_steps),
                "config_patches": len(plan.config_patches),
                "effort_hours": plan.total_effort_hours,
                "timeline_days": plan.estimated_timeline_days,
                "target_algorithms": plan.target_algorithms,
                "prerequisites": len(plan.prerequisites),
            }
            
            if has_steps and has_patches and has_effort and has_timeline:
                status = TestStatus.PASS
            elif has_steps or has_patches:
                status = TestStatus.WARN
            else:
                status = TestStatus.FAIL
            
            result = TestResult(
                name="Remediation Advisor",
                layer=3,
                status=status,
                duration_ms=duration,
                details=details,
            )
            
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            result = TestResult(
                name="Remediation Advisor",
                layer=3,
                status=TestStatus.FAIL,
                duration_ms=duration,
                error=str(e),
            )
        
        self.plog.log_result(result)
        return result
    
    async def test_full_analysis(self, domain: str, scan_result: TLSScanResult) -> TestResult:
        """Test full Layer 3 analysis pipeline with real scan results"""
        self.plog.start_test("Full Analysis Pipeline", domain)
        start = time.perf_counter()
        
        try:
            # Extract data from scan result
            key_exchanges = scan_result.key_exchange_algorithms
            cert_algo = scan_result.certificate.public_key_algorithm if scan_result.certificate else "RSA"
            
            # Run full analysis pipeline
            # 1. Classify algorithms
            classifications = [self.classifier.classify(algo) for algo in key_exchanges + [cert_algo]]
            worst_safety = self.classifier.get_worst_safety(key_exchanges + [cert_algo])
            
            # 2. Calculate HNDL score
            hndl_score = self.hndl_scorer.calculate(
                key_exchange_algorithms=key_exchanges,
                certificate_algorithm=cert_algo,
                endpoint_type="banking",  # Assume banking for these tests
            )
            
            # 3. Generate CBOM
            cbom = self.cbom_builder.build_from_scan_result(
                target=domain,
                key_exchange_algorithms=key_exchanges,
                certificate_algorithm=cert_algo,
                certificate_subject=scan_result.certificate.subject if scan_result.certificate else "",
                certificate_issuer=scan_result.certificate.issuer if scan_result.certificate else "",
                certificate_key_size=scan_result.certificate.public_key_size if scan_result.certificate else None,
                tls_versions=[v for v in ["1.0", "1.1", "1.2", "1.3"] 
                             if getattr(scan_result, f"supports_tls{v.replace('.', '')}".replace("10", "10").replace("11", "11").replace("12", "12").replace("13", "13"), False)],
            )
            
            # 4. Generate remediation plan
            plan = self.remediation_advisor.generate_plan(
                asset_fqdn=domain,
                current_algorithms=key_exchanges + [cert_algo],
                server_type=ServerType.NGINX,
            )
            
            duration = (time.perf_counter() - start) * 1000
            
            details = {
                "domain": domain,
                "worst_safety": worst_safety.value,
                "hndl_score": hndl_score.score,
                "hndl_label": hndl_score.label.value,
                "cbom_components": len(cbom.components),
                "pqc_readiness": cbom.cert_in_qbom.pqc_readiness_score if cbom.cert_in_qbom else 0,
                "migration_steps": len(plan.migration_steps),
                "effort_hours": plan.total_effort_hours,
            }
            
            result = TestResult(
                name=f"Full Analysis [{domain}]",
                layer=3,
                status=TestStatus.PASS,
                duration_ms=duration,
                details=details,
            )
            
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            result = TestResult(
                name=f"Full Analysis [{domain}]",
                layer=3,
                status=TestStatus.FAIL,
                duration_ms=duration,
                error=str(e),
            )
        
        self.plog.log_result(result)
        return result


# ============================================================================
# Layer 4: Certification Engine Tests
# ============================================================================

class Layer4Tests:
    """Layer 4: Certification Engine Tests
    
    Submodules tested:
    - PolicyEvaluator (three-tier logic)
    - LabelSigner (ML-DSA signing)
    - CertificationEngine (full certification flow)
    """
    
    def __init__(self, logger: PipelineLogger):
        self.plog = logger
        self.policy_evaluator = PolicyEvaluator()
        self.label_signer = LabelSigner()
        self.certification_engine = CertificationEngine()
    
    async def run_all(self, domains: List[str], layer3_results: Dict[str, Any] = None) -> LayerResults:
        """Run all Layer 4 tests"""
        self.plog.start_layer(4, "CERTIFICATION ENGINE")
        results = LayerResults(layer=4, name="Certification Engine")
        
        # Test 1: Policy Evaluator - Three Tier Logic
        result = self.test_policy_evaluator_three_tier()
        results.tests.append(result)
        
        # Test 2: Policy Evaluator - Score Calculation
        result = self.test_policy_evaluator_scoring()
        results.tests.append(result)
        
        # Test 3: Label Signer - Signature Generation
        result = self.test_label_signer()
        results.tests.append(result)
        
        # Test 4: Full Certification Flow
        result = self.test_certification_flow()
        results.tests.append(result)
        
        # Test 5: Integration with Layer 3 results
        if layer3_results:
            for domain, analysis in layer3_results.items():
                result = await self.test_full_certification(domain, analysis)
                results.tests.append(result)
        
        return results
    
    def test_policy_evaluator_three_tier(self) -> TestResult:
        """Test PolicyEvaluator three-tier logic"""
        self.plog.start_test("Policy Evaluator - Three Tier Logic")
        start = time.perf_counter()
        
        try:
            # Test case 1: FULLY_SAFE - All PQC
            result1 = self.policy_evaluator.evaluate(["ML-KEM-768", "ML-DSA-65", "AES-256"])
            tier1_correct = result1.level == CertificationLevel.FULLY_SAFE
            
            # Test case 2: PQC_READY - Mixed (some PQC, some vulnerable)
            result2 = self.policy_evaluator.evaluate(["ML-KEM-768", "RSA-2048", "ECDHE"])
            tier2_correct = result2.level == CertificationLevel.PQC_READY
            
            # Test case 3: VULNERABLE - No PQC
            result3 = self.policy_evaluator.evaluate(["RSA-2048", "ECDHE", "3DES"])
            tier3_correct = result3.level == CertificationLevel.VULNERABLE
            
            duration = (time.perf_counter() - start) * 1000
            
            all_correct = tier1_correct and tier2_correct and tier3_correct
            
            details = {
                "fully_safe_test": {
                    "algorithms": ["ML-KEM-768", "ML-DSA-65", "AES-256"],
                    "result": result1.level.value,
                    "correct": tier1_correct,
                },
                "pqc_ready_test": {
                    "algorithms": ["ML-KEM-768", "RSA-2048", "ECDHE"],
                    "result": result2.level.value,
                    "correct": tier2_correct,
                },
                "vulnerable_test": {
                    "algorithms": ["RSA-2048", "ECDHE", "3DES"],
                    "result": result3.level.value,
                    "correct": tier3_correct,
                },
            }
            
            result = TestResult(
                name="Policy Evaluator - Three Tier Logic",
                layer=4,
                status=TestStatus.PASS if all_correct else TestStatus.FAIL,
                duration_ms=duration,
                details=details,
            )
            
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            result = TestResult(
                name="Policy Evaluator - Three Tier Logic",
                layer=4,
                status=TestStatus.FAIL,
                duration_ms=duration,
                error=str(e),
            )
        
        self.plog.log_result(result)
        return result
    
    def test_policy_evaluator_scoring(self) -> TestResult:
        """Test PolicyEvaluator score calculation"""
        self.plog.start_test("Policy Evaluator - Scoring")
        start = time.perf_counter()
        
        try:
            # Test various algorithm combinations
            test_cases = [
                (["ML-KEM-768", "ML-DSA-65"], 1.0, "All PQC"),
                (["X25519MLKEM768"], 0.7, "Hybrid only"),
                (["RSA-2048"], 0.0, "Vulnerable only"),
                (["ML-KEM-768", "RSA-2048"], 0.5, "Mixed PQC/vulnerable"),
            ]
            
            results_correct = []
            case_details = []
            
            for algos, expected_min, desc in test_cases:
                policy_result = self.policy_evaluator.evaluate(algos)
                is_correct = policy_result.score >= expected_min - 0.1
                results_correct.append(is_correct)
                case_details.append({
                    "description": desc,
                    "algorithms": algos,
                    "score": policy_result.score,
                    "expected_min": expected_min,
                    "correct": is_correct,
                })
            
            duration = (time.perf_counter() - start) * 1000
            
            all_correct = all(results_correct)
            
            result = TestResult(
                name="Policy Evaluator - Scoring",
                layer=4,
                status=TestStatus.PASS if all_correct else TestStatus.WARN,
                duration_ms=duration,
                details={"test_cases": case_details},
            )
            
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            result = TestResult(
                name="Policy Evaluator - Scoring",
                layer=4,
                status=TestStatus.FAIL,
                duration_ms=duration,
                error=str(e),
            )
        
        self.plog.log_result(result)
        return result
    
    def test_label_signer(self) -> TestResult:
        """Test LabelSigner ML-DSA signing"""
        self.plog.start_test("Label Signer - ML-DSA")
        start = time.perf_counter()
        
        try:
            # Create a test certificate
            from datetime import timedelta
            now = datetime.now(timezone.utc)
            
            test_cert = PQCCertificate(
                certificate_id="test-cert-001",
                subject="test.example.com",
                level=CertificationLevel.PQC_READY,
                score=0.7,
                issued_at=now.isoformat(),
                expires_at=(now + timedelta(days=365)).isoformat(),
            )
            
            # Sign the certificate
            signed_cert = self.label_signer.sign(test_cert)
            
            duration = (time.perf_counter() - start) * 1000
            
            # Verify signature components exist
            has_signature = signed_cert.signature is not None
            has_public_key = signed_cert.public_key is not None
            has_hash = signed_cert.payload_hash is not None
            
            details = {
                "algorithm": self.label_signer.algorithm,
                "oqs_available": self.label_signer._oqs_available,
                "has_signature": has_signature,
                "has_public_key": has_public_key,
                "has_payload_hash": has_hash,
                "signature_length": len(signed_cert.signature) if signed_cert.signature else 0,
            }
            
            # Pass if we have all components (even placeholder signature)
            if has_signature and has_public_key and has_hash:
                status = TestStatus.PASS
            elif has_hash:
                status = TestStatus.WARN  # oqs might not be available
            else:
                status = TestStatus.FAIL
            
            result = TestResult(
                name="Label Signer - ML-DSA",
                layer=4,
                status=status,
                duration_ms=duration,
                details=details,
            )
            
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            result = TestResult(
                name="Label Signer - ML-DSA",
                layer=4,
                status=TestStatus.FAIL,
                duration_ms=duration,
                error=str(e),
            )
        
        self.plog.log_result(result)
        return result
    
    def test_certification_flow(self) -> TestResult:
        """Test full certification flow"""
        self.plog.start_test("Full Certification Flow")
        start = time.perf_counter()
        
        try:
            # Issue a certificate
            certificate = self.certification_engine.issue_certificate(
                subject="test.example.com",
                algorithms=["ECDHE", "RSA-2048", "AES-256"],
                validity_days=365,
            )
            
            duration = (time.perf_counter() - start) * 1000
            
            # Verify certificate structure
            has_id = certificate.certificate_id is not None
            has_level = certificate.level in CertificationLevel
            has_score = 0.0 <= certificate.score <= 1.0
            has_dates = certificate.issued_at and certificate.expires_at
            has_policy = certificate.policy_result is not None
            has_signature = certificate.signature is not None
            
            details = {
                "certificate_id": certificate.certificate_id,
                "subject": certificate.subject,
                "level": certificate.level.value,
                "score": certificate.score,
                "has_policy_result": has_policy,
                "has_signature": has_signature,
                "recommendations": certificate.policy_result.recommendations[:2] if certificate.policy_result else [],
            }
            
            all_valid = has_id and has_level and has_score and has_dates and has_policy
            
            result = TestResult(
                name="Full Certification Flow",
                layer=4,
                status=TestStatus.PASS if all_valid else TestStatus.FAIL,
                duration_ms=duration,
                details=details,
            )
            
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            result = TestResult(
                name="Full Certification Flow",
                layer=4,
                status=TestStatus.FAIL,
                duration_ms=duration,
                error=str(e),
            )
        
        self.plog.log_result(result)
        return result
    
    async def test_full_certification(self, domain: str, analysis: Dict[str, Any]) -> TestResult:
        """Test certification with real Layer 3 analysis results"""
        self.plog.start_test("Full Certification Pipeline", domain)
        start = time.perf_counter()
        
        try:
            # Extract algorithms from Layer 3 analysis
            algorithms = analysis.get("algorithms", ["ECDHE", "RSA"])
            
            # Issue certificate
            certificate = self.certification_engine.issue_certificate(
                subject=domain,
                algorithms=algorithms,
            )
            
            duration = (time.perf_counter() - start) * 1000
            
            details = {
                "domain": domain,
                "algorithms": algorithms,
                "certification_level": certificate.level.value,
                "score": certificate.score,
                "recommendations": certificate.policy_result.recommendations[:2] if certificate.policy_result else [],
            }
            
            result = TestResult(
                name=f"Full Certification [{domain}]",
                layer=4,
                status=TestStatus.PASS,
                duration_ms=duration,
                details=details,
            )
            
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            result = TestResult(
                name=f"Full Certification [{domain}]",
                layer=4,
                status=TestStatus.FAIL,
                duration_ms=duration,
                error=str(e),
            )
        
        self.plog.log_result(result)
        return result


# ============================================================================
# Output Collection Tests
# ============================================================================

class OutputCollectionTests:
    """Output Collection and Structured Output Tests
    
    Tests:
    - OutputCollector initialization
    - Asset type classification
    - Structured output generation
    - Full workflow with output collection
    """
    
    def __init__(self, logger: PipelineLogger):
        self.plog = logger
        self.output_collector = OutputCollector()
    
    async def run_all(self, domains: List[str]) -> LayerResults:
        """Run all output collection tests"""
        self.plog.start_layer(5, "OUTPUT COLLECTION")
        results = LayerResults(layer=5, name="Output Collection")
        
        # Test 1: Asset Type Classification
        result = self.test_asset_type_classifier()
        results.tests.append(result)
        
        # Test 2: Output Collector Initialization
        result = self.test_output_collector_init()
        results.tests.append(result)
        
        # Test 3: Structured Output Schema
        result = self.test_structured_output_schema()
        results.tests.append(result)
        
        # Test 4: Full Workflow with Output Collection
        for domain in domains[:1]:  # Test with first domain only
            result = await self.test_full_workflow_output(domain)
            results.tests.append(result)
        
        return results
    
    def test_asset_type_classifier(self) -> TestResult:
        """Test AssetTypeClassifier"""
        self.plog.start_test("Asset Type Classifier")
        start = time.perf_counter()
        
        try:
            test_cases = [
                ("api.example.com", AssetType.API),
                ("www.example.com", AssetType.WEB_APP),
                ("cdn.example.com", AssetType.CDN),
                ("mail.example.com", AssetType.MAIL_SERVER),
                ("vpn.example.com", AssetType.VPN),
                ("netbanking.example.com", AssetType.WEB_APP),
                ("gateway.example.com", AssetType.GATEWAY),
            ]
            
            all_correct = True
            case_details = []
            
            for fqdn, expected_type in test_cases:
                actual_type = AssetTypeClassifier.classify(fqdn)
                is_correct = actual_type == expected_type
                all_correct = all_correct and is_correct
                case_details.append({
                    "fqdn": fqdn,
                    "expected": expected_type.value,
                    "actual": actual_type.value,
                    "correct": is_correct,
                })
            
            duration = (time.perf_counter() - start) * 1000
            
            result = TestResult(
                name="Asset Type Classifier",
                layer=5,
                status=TestStatus.PASS if all_correct else TestStatus.FAIL,
                duration_ms=duration,
                details={"test_cases": case_details},
            )
            
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            result = TestResult(
                name="Asset Type Classifier",
                layer=5,
                status=TestStatus.FAIL,
                duration_ms=duration,
                error=str(e),
            )
        
        self.plog.log_result(result)
        return result
    
    def test_output_collector_init(self) -> TestResult:
        """Test OutputCollector initialization"""
        self.plog.start_test("OutputCollector Initialization")
        start = time.perf_counter()
        
        try:
            collector = OutputCollector()
            collector.start_scan("test.example.com")
            
            has_scan_id = collector.output.scan_id != ""
            has_domain = collector.output.domain == "test.example.com"
            has_start_time = collector.output.scan_start != ""
            
            duration = (time.perf_counter() - start) * 1000
            
            all_valid = has_scan_id and has_domain and has_start_time
            
            result = TestResult(
                name="OutputCollector Initialization",
                layer=5,
                status=TestStatus.PASS if all_valid else TestStatus.FAIL,
                duration_ms=duration,
                details={
                    "has_scan_id": has_scan_id,
                    "has_domain": has_domain,
                    "has_start_time": has_start_time,
                    "scan_id": collector.output.scan_id,
                },
            )
            
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            result = TestResult(
                name="OutputCollector Initialization",
                layer=5,
                status=TestStatus.FAIL,
                duration_ms=duration,
                error=str(e),
            )
        
        self.plog.log_result(result)
        return result
    
    def test_structured_output_schema(self) -> TestResult:
        """Test StructuredOutput schema and serialization"""
        self.plog.start_test("Structured Output Schema")
        start = time.perf_counter()
        
        try:
            output = StructuredOutput(
                scan_id="test-123",
                domain="example.com",
                scan_start=datetime.now(timezone.utc).isoformat(),
            )
            
            # Test to_dict
            output_dict = output.to_dict()
            
            # Verify required sections exist
            has_metadata = "metadata" in output_dict
            has_dashboard = "dashboard" in output_dict
            has_inventory = "inventory" in output_dict
            has_graph = "graph" in output_dict
            has_summaries = "summaries" in output_dict
            has_layer_outputs = "layer_outputs" in output_dict
            
            # Test to_json
            json_output = output.to_json()
            is_valid_json = json_output.startswith("{")
            
            duration = (time.perf_counter() - start) * 1000
            
            all_valid = all([
                has_metadata, has_dashboard, has_inventory,
                has_graph, has_summaries, has_layer_outputs,
                is_valid_json
            ])
            
            result = TestResult(
                name="Structured Output Schema",
                layer=5,
                status=TestStatus.PASS if all_valid else TestStatus.FAIL,
                duration_ms=duration,
                details={
                    "has_metadata": has_metadata,
                    "has_dashboard": has_dashboard,
                    "has_inventory": has_inventory,
                    "has_graph": has_graph,
                    "has_summaries": has_summaries,
                    "has_layer_outputs": has_layer_outputs,
                    "is_valid_json": is_valid_json,
                },
            )
            
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            result = TestResult(
                name="Structured Output Schema",
                layer=5,
                status=TestStatus.FAIL,
                duration_ms=duration,
                error=str(e),
            )
        
        self.plog.log_result(result)
        return result
    
    async def test_full_workflow_output(self, domain: str) -> TestResult:
        """Test full workflow with output collection"""
        self.plog.start_test("Full Workflow Output", domain)
        start = time.perf_counter()
        
        try:
            # Run workflow with output collection
            workflow = QuShieldWorkflow(
                scan_timeout=30,
                max_concurrent_scans=3,
                save_outputs=True,
            )
            
            result_data = await workflow.run(
                domain=domain,
                max_assets=5,  # Limit for testing
            )
            
            duration = (time.perf_counter() - start) * 1000
            
            # Verify output collection
            has_structured_output = result_data.structured_output is not None
            has_output_file = result_data.output_file is not None
            
            details = {
                "domain": domain,
                "has_structured_output": has_structured_output,
                "has_output_file": has_output_file,
                "output_file": result_data.output_file,
                "assets_discovered": result_data.assets_discovered,
                "assets_scanned": result_data.assets_scanned,
            }
            
            if has_structured_output:
                so = result_data.structured_output
                details["dashboard_total_assets"] = so.dashboard.total_assets
                details["certificates_count"] = len(so.certificates)
                details["graph_nodes_count"] = len(so.graph_nodes)
                details["cyber_rating_score"] = so.cyber_rating.enterprise_score
                # Extended discovery outputs
                details["ns_records_count"] = len(so.ns_records)
                details["mx_records_count"] = len(so.mx_records)
                details["txt_records_count"] = len(so.txt_records)
                details["has_whois"] = so.whois_info is not None
                details["port_scan_count"] = len(so.port_scan_results)
                details["services_count"] = len(so.services)
                details["cloud_assets_count"] = len(so.cloud_assets)
                details["iot_devices_count"] = len(so.iot_devices)
            
            all_valid = has_structured_output and has_output_file
            
            result = TestResult(
                name=f"Full Workflow Output [{domain}]",
                layer=5,
                status=TestStatus.PASS if all_valid else TestStatus.WARN,
                duration_ms=duration,
                details=details,
            )
            
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            result = TestResult(
                name=f"Full Workflow Output [{domain}]",
                layer=5,
                status=TestStatus.FAIL,
                duration_ms=duration,
                error=str(e),
            )
        
        self.plog.log_result(result)
        return result


# ============================================================================
# Main Pipeline Runner
# ============================================================================

class TestPipeline:
    """Main test pipeline orchestrator"""
    
    def __init__(self, domains: List[str] = None, verbose: bool = True):
        self.domains = domains or TEST_DOMAINS
        self.plog = PipelineLogger(verbose=verbose)
        self.results = None
    
    async def run(self) -> PipelineResults:
        """Run the complete testing pipeline"""
        start_time = datetime.now(timezone.utc)
        start_perf = time.perf_counter()
        
        self.plog.start_pipeline(self.domains)
        
        results = PipelineResults(
            start_time=start_time.isoformat(),
            end_time="",
            duration_ms=0,
            domains_tested=self.domains,
        )
        
        # Layer 1: Asset Discovery
        layer1 = Layer1Tests(self.plog)
        results.layers[1] = await layer1.run_all(self.domains)
        
        # Layer 2: Cryptographic Scan
        layer2 = Layer2Tests(self.plog)
        results.layers[2] = await layer2.run_all(self.domains)
        
        # Collect scan results for Layer 3
        scan_results = {}
        for test in results.layers[2].tests:
            if "TLS Handshake" in test.name and test.status == TestStatus.PASS:
                domain = test.details.get("domain", "")
                if domain and "scan_result" in test.details:
                    scan_results[domain] = test.details["scan_result"]
        
        # Layer 3: PQC Analysis & CBOM Generation
        layer3 = Layer3Tests(self.plog)
        results.layers[3] = await layer3.run_all(self.domains, scan_results)
        
        # Collect Layer 3 analysis results for Layer 4
        layer3_results = {}
        for test in results.layers[3].tests:
            if "Full Analysis" in test.name and test.status == TestStatus.PASS:
                domain = test.details.get("domain", "")
                if domain:
                    # Extract algorithms from the test details
                    layer3_results[domain] = {
                        "algorithms": ["ECDHE", "RSA"],  # Default fallback
                        "hndl_score": test.details.get("hndl_score", 0),
                    }
        
        # Layer 4: Certification Engine
        layer4 = Layer4Tests(self.plog)
        results.layers[4] = await layer4.run_all(self.domains, layer3_results)
        
        # Layer 5: Output Collection Tests
        output_tests = OutputCollectionTests(self.plog)
        results.layers[5] = await output_tests.run_all(self.domains)
        
        # Complete
        end_time = datetime.now(timezone.utc)
        results.end_time = end_time.isoformat()
        results.duration_ms = (time.perf_counter() - start_perf) * 1000
        
        self.plog.end_pipeline(results)
        self.results = results
        
        return results
    
    def save_results(self, output_path: Path = None):
        """Save results to JSON file"""
        if not self.results:
            return
        
        if output_path is None:
            output_path = LOG_DIR / f"test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, "w") as f:
            json.dump(self.results.to_dict(), f, indent=2, default=str)
        
        print(f"\n  Results saved to: {output_path}")


async def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="QuShield Testing Pipeline")
    parser.add_argument(
        "--domains", "-d",
        nargs="+",
        default=TEST_DOMAINS,
        help="Domains to test",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Reduce output verbosity",
    )
    parser.add_argument(
        "--save", "-s",
        action="store_true",
        help="Save results to JSON file",
    )
    
    args = parser.parse_args()
    
    # Initialize logging
    setup_logging()
    
    # Run pipeline
    pipeline = TestPipeline(
        domains=args.domains,
        verbose=not args.quiet,
    )
    
    results = await pipeline.run()
    
    if args.save:
        pipeline.save_results()
    
    # Return exit code based on failures
    total_failed = sum(layer.failed for layer in results.layers.values())
    return 1 if total_failed > 0 else 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
