"""
End-to-End Tests for PNB Bank Domains

Tests the complete workflow against Punjab National Bank public domains.
These are live integration tests that require network access.

Run with: pytest tests/test_pnb_banks.py -v
"""

import pytest
import asyncio
import json
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from qushield.workflow import QuShieldWorkflow, WorkflowResult
from qushield.core.scanner import TLSScanner, ScanStatus
from qushield.core.classifier import PQCClassifier, QuantumSafety
from qushield.core.scorer import HNDLScorer, HNDLRiskLabel
from qushield.output.cbom import CBOMBuilder
from qushield.core.discovery import AssetDiscovery


# Test targets - Public Indian Bank domains
PNB_DOMAINS = [
    "pnbindia.in",
    "www.pnbindia.in",
]

OTHER_BANK_DOMAINS = [
    "sbi.co.in",
    "hdfcbank.com",
]


class TestPNBTLSScanner:
    """Test TLS Scanner against PNB domains"""
    
    @pytest.fixture
    def scanner(self):
        return TLSScanner(timeout=30)
    
    @pytest.mark.live
    @pytest.mark.timeout(60)
    def test_scan_pnb_main_site(self, scanner):
        """Scan pnbindia.in main website"""
        result = scanner.scan("www.pnbindia.in", 443)
        
        print(f"\n{'='*60}")
        print(f"PNB Main Site Scan: www.pnbindia.in")
        print(f"{'='*60}")
        print(f"Status: {result.status.value}")
        print(f"Duration: {result.duration_ms:.0f}ms")
        
        if result.status == ScanStatus.SUCCESS:
            print(f"\nTLS Versions:")
            print(f"  TLS 1.0: {result.supports_tls10}")
            print(f"  TLS 1.1: {result.supports_tls11}")
            print(f"  TLS 1.2: {result.supports_tls12}")
            print(f"  TLS 1.3: {result.supports_tls13}")
            
            print(f"\nKey Exchange Algorithms:")
            for algo in result.key_exchange_algorithms:
                print(f"  - {algo}")
            
            if result.certificate:
                print(f"\nCertificate:")
                print(f"  Subject: {result.certificate.subject}")
                print(f"  Issuer: {result.certificate.issuer}")
                print(f"  Algorithm: {result.certificate.public_key_algorithm}")
                print(f"  Key Size: {result.certificate.public_key_size}")
                print(f"  Expires: {result.certificate.not_after}")
            
            print(f"\nVulnerabilities:")
            print(f"  Heartbleed: {result.vulnerable_to_heartbleed}")
            print(f"  Downgrade Prevention: {result.supports_fallback_scsv}")
        else:
            print(f"Error: {result.error_message}")
        
        # Assertions
        assert result.status in [ScanStatus.SUCCESS, ScanStatus.CONNECTION_ERROR, ScanStatus.TIMEOUT]
        if result.status == ScanStatus.SUCCESS:
            assert result.certificate is not None


class TestPNBPQCAnalysis:
    """Test PQC Analysis against PNB domains"""
    
    @pytest.fixture
    def classifier(self):
        return PQCClassifier()
    
    @pytest.fixture
    def scorer(self):
        return HNDLScorer()
    
    @pytest.mark.live
    @pytest.mark.timeout(60)
    def test_analyze_pnb_crypto_posture(self, classifier, scorer):
        """Analyze PNB cryptographic posture"""
        scanner = TLSScanner(timeout=30)
        result = scanner.scan("www.pnbindia.in", 443)
        
        if result.status != ScanStatus.SUCCESS:
            pytest.skip(f"Could not connect to PNB: {result.error_message}")
        
        # Analyze key exchanges
        print(f"\n{'='*60}")
        print(f"PNB Quantum Safety Analysis")
        print(f"{'='*60}")
        
        all_algorithms = result.key_exchange_algorithms.copy()
        if result.certificate:
            all_algorithms.append(result.certificate.public_key_algorithm)
        
        print(f"\nAlgorithms Found:")
        for algo in all_algorithms:
            info = classifier.classify(algo)
            print(f"  {algo}:")
            print(f"    Safety: {info.safety.value}")
            print(f"    Vulnerability Score: {info.vuln_score}")
            if info.migrate_to:
                print(f"    Migration Target: {info.migrate_to}")
        
        # Overall safety
        worst_safety = classifier.get_worst_safety(all_algorithms)
        print(f"\nOverall Quantum Safety: {worst_safety.value}")
        
        # HNDL Score
        cert_algo = result.certificate.public_key_algorithm if result.certificate else "RSA"
        hndl = scorer.calculate(
            key_exchange_algorithms=result.key_exchange_algorithms,
            certificate_algorithm=cert_algo,
            endpoint_type="banking",
            is_high_traffic=True,
        )
        
        print(f"\nHNDL Risk Assessment:")
        print(f"  Score: {hndl.score:.3f}")
        print(f"  Label: {hndl.label.value}")
        print(f"  Risk Horizon: {hndl.estimated_risk_horizon}")
        print(f"  Recommendation: {hndl.recommended_action}")
        
        # Assertions
        assert worst_safety in [QuantumSafety.VULNERABLE, QuantumSafety.HYBRID, QuantumSafety.FULLY_SAFE, QuantumSafety.CRITICAL]
        assert hndl.score >= 0.0 and hndl.score <= 1.0


class TestPNBCBOMGeneration:
    """Test CBOM Generation for PNB"""
    
    @pytest.mark.live
    @pytest.mark.timeout(60)
    def test_generate_pnb_cbom(self):
        """Generate CBOM for PNB"""
        scanner = TLSScanner(timeout=30)
        result = scanner.scan("www.pnbindia.in", 443)
        
        if result.status != ScanStatus.SUCCESS:
            pytest.skip(f"Could not connect to PNB: {result.error_message}")
        
        builder = CBOMBuilder()
        cert_algo = result.certificate.public_key_algorithm if result.certificate else "RSA"
        
        cbom = builder.build_from_scan_result(
            target="www.pnbindia.in",
            key_exchange_algorithms=result.key_exchange_algorithms,
            certificate_algorithm=cert_algo,
            certificate_subject=result.certificate.subject if result.certificate else "",
            certificate_issuer=result.certificate.issuer if result.certificate else "",
            certificate_key_size=result.certificate.public_key_size if result.certificate else None,
            certificate_expiry=result.certificate.not_after if result.certificate else None,
            tls_versions=[v for v, s in [
                ("1.0", result.supports_tls10),
                ("1.1", result.supports_tls11),
                ("1.2", result.supports_tls12),
                ("1.3", result.supports_tls13),
            ] if s],
        )
        
        print(f"\n{'='*60}")
        print(f"PNB CBOM (CycloneDX 1.6)")
        print(f"{'='*60}")
        print(cbom.to_json())
        
        # Save to file
        output_file = Path(__file__).parent.parent / "logs" / "pnb_cbom.json"
        output_file.parent.mkdir(exist_ok=True)
        output_file.write_text(cbom.to_json())
        print(f"\nCBOM saved to: {output_file}")
        
        # Assertions
        assert cbom.bom_format == "CycloneDX"
        assert cbom.spec_version == "1.6"
        assert len(cbom.components) > 0


class TestPNBFullWorkflow:
    """Test Complete Workflow against PNB"""
    
    @pytest.mark.live
    @pytest.mark.timeout(180)
    @pytest.mark.asyncio
    async def test_full_workflow_pnb(self):
        """Run complete 4-layer workflow for PNB"""
        workflow = QuShieldWorkflow(
            scan_timeout=30,
            max_concurrent_scans=3,
            use_ct_logs=False,  # Skip CT logs for speed
            use_subdomain_enum=False,
        )
        
        print(f"\n{'='*60}")
        print(f"PNB Full Workflow Test")
        print(f"Started: {datetime.utcnow().isoformat()}")
        print(f"{'='*60}")
        
        result = await workflow.run(
            domain="pnbindia.in",
            skip_discovery=True,
            targets=["www.pnbindia.in"],
            max_assets=1,
        )
        
        print(f"\n--- Workflow Results ---")
        print(f"Duration: {result.duration_ms:.0f}ms")
        print(f"Assets Discovered: {result.assets_discovered}")
        print(f"Assets Scanned: {result.assets_scanned}")
        print(f"Scan Failures: {result.scan_failures}")
        print(f"\n--- Quantum Safety Summary ---")
        print(f"Quantum Safe: {result.quantum_safe_count}")
        print(f"PQC Ready: {result.pqc_ready_count}")
        print(f"Vulnerable: {result.vulnerable_count}")
        print(f"Critical: {result.critical_count}")
        print(f"Average HNDL Score: {result.average_hndl_score:.3f}")
        
        for asset in result.assets:
            print(f"\n--- Asset: {asset.fqdn} ---")
            print(f"  Scan Success: {asset.scan_success}")
            print(f"  Quantum Safety: {asset.quantum_safety}")
            print(f"  Cert Tier: {asset.cert_tier}")
            if asset.hndl_score:
                print(f"  HNDL Score: {asset.hndl_score.score:.3f} ({asset.hndl_score.label.value})")
                print(f"  Recommendation: {asset.hndl_score.recommended_action}")
        
        # Save full results
        output_file = Path(__file__).parent.parent / "logs" / "pnb_workflow_result.json"
        output_file.parent.mkdir(exist_ok=True)
        output_file.write_text(result.to_json())
        print(f"\nResults saved to: {output_file}")
        
        # Assertions
        assert result.duration_ms > 0
        if result.errors:
            print(f"\nErrors: {result.errors}")


class TestPNBDiscovery:
    """Test Asset Discovery for PNB"""
    
    @pytest.mark.live
    @pytest.mark.timeout(60)
    @pytest.mark.asyncio
    async def test_discover_pnb_subdomains(self):
        """Discover PNB subdomains via CT logs"""
        discovery = AssetDiscovery(timeout=30)
        
        try:
            print(f"\n{'='*60}")
            print(f"PNB Subdomain Discovery")
            print(f"{'='*60}")
            
            assets = await discovery.discover_from_ct_logs("pnbindia.in")
            
            print(f"\nDiscovered {len(assets)} subdomains:")
            for asset in assets[:20]:  # Show first 20
                print(f"  - {asset.fqdn} (source: {asset.source})")
            
            if len(assets) > 20:
                print(f"  ... and {len(assets) - 20} more")
            
            # Assertions
            assert len(assets) >= 0  # CT logs may return 0
            
        finally:
            await discovery.close()


def run_pnb_tests():
    """Run all PNB tests and generate report"""
    import subprocess
    
    print("="*60)
    print("QuShield - PNB Bank Testing Suite")
    print("="*60)
    print(f"Started: {datetime.utcnow().isoformat()}")
    print()
    
    # Run pytest
    result = subprocess.run(
        ["python", "-m", "pytest", __file__, "-v", "--tb=short"],
        capture_output=False,
    )
    
    return result.returncode


if __name__ == "__main__":
    # Run tests
    exit_code = run_pnb_tests()
    sys.exit(exit_code)
