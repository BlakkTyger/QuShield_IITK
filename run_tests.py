#!/usr/bin/env python3
"""
QuShield Test Runner

Runs all tests and generates a comprehensive report.

Usage:
    python run_tests.py              # Run all unit tests
    python run_tests.py --live       # Include live network tests
    python run_tests.py --pnb        # Run PNB bank tests only
    python run_tests.py --quick      # Quick sanity check
"""

import sys
import os
import time
import json
import argparse
from pathlib import Path
from datetime import datetime

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))


def print_banner():
    """Print test banner"""
    print("""
╔═══════════════════════════════════════════════════════════╗
║         QuShield - Backend Testing Suite                  ║
║         Quantum Safe Crypto Scanner Tests                 ║
╚═══════════════════════════════════════════════════════════╝
""")


def run_unit_tests():
    """Run unit tests (no network required)"""
    print("\n" + "="*60)
    print("UNIT TESTS")
    print("="*60)
    
    results = {}
    
    # Test PQC Classifier
    print("\n[1/4] Testing PQC Classifier...")
    try:
        from qushield.core.classifier import PQCClassifier, QuantumSafety
        classifier = PQCClassifier()
        
        # Test NIST algorithms
        assert classifier.classify("ML-KEM-768").safety == QuantumSafety.FULLY_SAFE
        assert classifier.classify("ML-DSA-65").safety == QuantumSafety.FULLY_SAFE
        assert classifier.classify("RSA-2048").safety == QuantumSafety.VULNERABLE
        assert classifier.classify("RC4").safety == QuantumSafety.CRITICAL
        
        # Test utility methods
        assert classifier.is_quantum_safe("ML-KEM-768") == True
        assert classifier.is_quantum_safe("RSA") == False
        assert classifier.get_max_vuln_score(["AES-256", "RSA"]) == 1.0
        
        results["pqc_classifier"] = {"status": "PASS", "tests": 6}
        print("  ✓ PQC Classifier: PASS (6 tests)")
    except Exception as e:
        results["pqc_classifier"] = {"status": "FAIL", "error": str(e)}
        print(f"  ✗ PQC Classifier: FAIL - {e}")
    
    # Test HNDL Scorer
    print("\n[2/4] Testing HNDL Scorer...")
    try:
        from qushield.core.scorer import HNDLScorer, HNDLRiskLabel
        scorer = HNDLScorer()
        
        # Test score calculation
        result = scorer.calculate(
            key_exchange_algorithms=["ECDHE"],
            certificate_algorithm="RSA-2048",
            endpoint_type="banking",
        )
        assert 0.0 <= result.score <= 1.0
        assert result.label in HNDLRiskLabel
        assert result.recommended_action is not None
        
        # Test safe algorithms
        safe_result = scorer.calculate(
            key_exchange_algorithms=["ML-KEM-768"],
            certificate_algorithm="ML-DSA-65",
        )
        assert safe_result.score < 0.1
        
        results["hndl_scorer"] = {"status": "PASS", "tests": 4}
        print("  ✓ HNDL Scorer: PASS (4 tests)")
    except Exception as e:
        results["hndl_scorer"] = {"status": "FAIL", "error": str(e)}
        print(f"  ✗ HNDL Scorer: FAIL - {e}")
    
    # Test CBOM Builder
    print("\n[3/4] Testing CBOM Builder...")
    try:
        from qushield.output.cbom import CBOMBuilder
        builder = CBOMBuilder()
        
        # Test CBOM generation
        builder.add_algorithm("RSA-2048", context="test")
        cbom = builder.build(target_name="test.com")
        
        assert cbom.bom_format == "CycloneDX"
        assert cbom.spec_version == "1.6"
        assert len(cbom.components) > 0
        
        # Test JSON output
        json_str = cbom.to_json()
        parsed = json.loads(json_str)
        assert "bomFormat" in parsed
        
        results["cbom_builder"] = {"status": "PASS", "tests": 4}
        print("  ✓ CBOM Builder: PASS (4 tests)")
    except Exception as e:
        results["cbom_builder"] = {"status": "FAIL", "error": str(e)}
        print(f"  ✗ CBOM Builder: FAIL - {e}")
    
    # Test PQC Signer
    print("\n[4/4] Testing PQC Signer...")
    try:
        from qushield.core.signer import PQCSigner, CertTier, BadgeGenerator
        signer = PQCSigner()
        
        # Test certificate issuance
        cert = signer.issue_certificate(
            subject="test.com:443",
            tier=CertTier.VULNERABLE,
            algorithms_verified=["RSA-2048", "ECDHE"],
        )
        
        assert cert.cert_id is not None
        assert cert.tier == CertTier.VULNERABLE
        assert cert.issued_at is not None
        
        # Test badge generation
        badge_gen = BadgeGenerator()
        html = badge_gen.generate_badge_html(cert)
        assert "QuShield" in html
        
        results["pqc_signer"] = {"status": "PASS", "tests": 4}
        print("  ✓ PQC Signer: PASS (4 tests)")
    except Exception as e:
        results["pqc_signer"] = {"status": "FAIL", "error": str(e)}
        print(f"  ✗ PQC Signer: FAIL - {e}")
    
    return results


def run_scanner_test(target: str = "www.google.com"):
    """Test TLS scanner against a target"""
    print("\n" + "="*60)
    print(f"TLS SCANNER TEST: {target}")
    print("="*60)
    
    try:
        from qushield.core.scanner import TLSScanner, ScanStatus
        scanner = TLSScanner(timeout=30)
        
        print(f"\nScanning {target}:443...")
        result = scanner.scan(target, 443)
        
        print(f"\nStatus: {result.status.value}")
        print(f"Duration: {result.duration_ms:.0f}ms")
        
        if result.status == ScanStatus.SUCCESS:
            print(f"\nTLS Versions Supported:")
            print(f"  TLS 1.0: {result.supports_tls10}")
            print(f"  TLS 1.1: {result.supports_tls11}")
            print(f"  TLS 1.2: {result.supports_tls12}")
            print(f"  TLS 1.3: {result.supports_tls13}")
            
            print(f"\nKey Exchange Algorithms:")
            for algo in result.key_exchange_algorithms:
                print(f"  - {algo}")
            
            if result.certificate:
                print(f"\nCertificate:")
                print(f"  Subject: {result.certificate.subject[:60]}...")
                print(f"  Algorithm: {result.certificate.public_key_algorithm}")
                print(f"  Key Size: {result.certificate.public_key_size}")
            
            return {"status": "PASS", "target": target, "data": result.to_dict()}
        else:
            print(f"\nError: {result.error_message}")
            return {"status": "FAIL", "target": target, "error": result.error_message}
            
    except Exception as e:
        print(f"\nException: {e}")
        return {"status": "ERROR", "target": target, "error": str(e)}


def run_pnb_test():
    """Run tests against PNB Bank domains"""
    print("\n" + "="*60)
    print("PNB BANK DOMAIN TESTS")
    print("="*60)
    
    results = {}
    targets = ["www.pnbindia.in", "pnbindia.in"]
    
    for target in targets:
        print(f"\n--- Testing: {target} ---")
        result = run_scanner_test(target)
        results[target] = result
        
        if result["status"] == "PASS":
            # Run PQC analysis
            try:
                from qushield.core.classifier import PQCClassifier
                from qushield.core.scorer import HNDLScorer
                
                classifier = PQCClassifier()
                scorer = HNDLScorer()
                
                data = result["data"]
                algorithms = data.get("key_exchange_algorithms", [])
                cert_algo = data.get("certificate", {}).get("public_key_algorithm", "RSA")
                
                if cert_algo:
                    algorithms.append(cert_algo)
                
                if algorithms:
                    worst_safety = classifier.get_worst_safety(algorithms)
                    hndl = scorer.calculate(
                        key_exchange_algorithms=data.get("key_exchange_algorithms", []),
                        certificate_algorithm=cert_algo,
                        endpoint_type="banking",
                    )
                    
                    print(f"\n  Quantum Safety: {worst_safety.value}")
                    print(f"  HNDL Score: {hndl.score:.3f} ({hndl.label.value})")
                    print(f"  Recommendation: {hndl.recommended_action}")
                    
                    results[target]["quantum_safety"] = worst_safety.value
                    results[target]["hndl_score"] = hndl.score
                    results[target]["hndl_label"] = hndl.label.value
                    
            except Exception as e:
                print(f"  Analysis error: {e}")
    
    return results


def run_quick_sanity_check():
    """Quick sanity check - no network required"""
    print("\n" + "="*60)
    print("QUICK SANITY CHECK")
    print("="*60)
    
    errors = []
    
    # Check imports
    print("\nChecking imports...")
    try:
        from qushield import (
            PQCClassifier, QuantumSafety,
            HNDLScorer, HNDLRiskLabel,
            CBOMBuilder, CBOM,
            TLSScanner, ScanStatus,
            PQCSigner, CertTier,
            QuShieldWorkflow,
        )
        print("  ✓ All services import successfully")
    except ImportError as e:
        errors.append(f"Import error: {e}")
        print(f"  ✗ Import error: {e}")
    
    # Check basic functionality
    print("\nChecking basic functionality...")
    try:
        classifier = PQCClassifier()
        info = classifier.classify("RSA-2048")
        assert info.safety == QuantumSafety.VULNERABLE
        print("  ✓ PQC Classifier works")
    except Exception as e:
        errors.append(f"Classifier error: {e}")
        print(f"  ✗ Classifier error: {e}")
    
    try:
        scorer = HNDLScorer()
        result = scorer.calculate(["ECDHE"], "RSA-2048")
        assert result.score > 0
        print("  ✓ HNDL Scorer works")
    except Exception as e:
        errors.append(f"Scorer error: {e}")
        print(f"  ✗ Scorer error: {e}")
    
    try:
        builder = CBOMBuilder()
        builder.add_algorithm("RSA-2048")
        cbom = builder.build()
        assert cbom.bom_format == "CycloneDX"
        print("  ✓ CBOM Builder works")
    except Exception as e:
        errors.append(f"CBOM error: {e}")
        print(f"  ✗ CBOM error: {e}")
    
    if errors:
        print(f"\n❌ Sanity check FAILED with {len(errors)} errors")
        return False
    else:
        print("\n✅ Sanity check PASSED")
        return True


def generate_report(results: dict, output_file: str = None):
    """Generate test report"""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "results": results,
        "summary": {
            "total": len(results),
            "passed": sum(1 for r in results.values() if r.get("status") == "PASS"),
            "failed": sum(1 for r in results.values() if r.get("status") == "FAIL"),
        }
    }
    
    if output_file:
        Path(output_file).parent.mkdir(exist_ok=True)
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nReport saved to: {output_file}")
    
    return report


def main():
    parser = argparse.ArgumentParser(description="QuShield Test Runner")
    parser.add_argument("--live", action="store_true", help="Include live network tests")
    parser.add_argument("--pnb", action="store_true", help="Run PNB bank tests only")
    parser.add_argument("--quick", action="store_true", help="Quick sanity check only")
    parser.add_argument("--target", type=str, help="Specific target to scan")
    args = parser.parse_args()
    
    print_banner()
    print(f"Started: {datetime.utcnow().isoformat()}")
    
    start_time = time.time()
    all_results = {}
    
    if args.quick:
        success = run_quick_sanity_check()
        sys.exit(0 if success else 1)
    
    if args.pnb:
        all_results["pnb"] = run_pnb_test()
    elif args.target:
        all_results["scanner"] = run_scanner_test(args.target)
    else:
        # Run unit tests
        all_results["unit_tests"] = run_unit_tests()
        
        if args.live:
            # Run live scanner test
            all_results["scanner"] = run_scanner_test("www.google.com")
    
    # Generate report
    duration = time.time() - start_time
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    report = generate_report(all_results, "logs/test_report.json")
    
    print(f"\nTotal Duration: {duration:.1f}s")
    print(f"Tests Run: {report['summary']['total']}")
    print(f"Passed: {report['summary']['passed']}")
    print(f"Failed: {report['summary']['failed']}")
    
    if report['summary']['failed'] > 0:
        print("\n❌ Some tests FAILED")
        sys.exit(1)
    else:
        print("\n✅ All tests PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
