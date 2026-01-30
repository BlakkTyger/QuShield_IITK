#!/usr/bin/env python3
"""
QuShield Quick Scan

Simplified scanner for quick PQC assessments of single targets.

Usage:
    python scripts/quick_scan.py example.com
    python scripts/quick_scan.py example.com:8443
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from qushield.core.scanner import TLSScanner, ScanStatus
from qushield.core.classifier import PQCClassifier, QuantumSafety
from qushield.core.scorer import HNDLScorer


def print_result(target: str, port: int, scan_result, classification, hndl_score):
    """Print formatted scan result."""
    print(f"\n{'=' * 50}")
    print(f"  Quick Scan: {target}:{port}")
    print(f"{'=' * 50}")
    
    if scan_result.status != ScanStatus.SUCCESS:
        print(f"\n❌ Scan Failed: {scan_result.error_message}")
        return
    
    # TLS Info
    print(f"\n🔒 TLS Configuration:")
    print(f"   Versions: {', '.join(scan_result.supported_tls_versions) or 'None detected'}")
    print(f"   Key Exchange: {', '.join(scan_result.key_exchange_algorithms) or 'Unknown'}")
    
    if scan_result.certificate:
        cert = scan_result.certificate
        print(f"\n📜 Certificate:")
        print(f"   Subject: {cert.subject[:60]}...")
        print(f"   Algorithm: {cert.public_key_algorithm} ({cert.public_key_size} bits)")
        print(f"   Expires: {cert.not_after}")
        if cert.is_expired:
            print(f"   ⚠️  EXPIRED!")
    
    # Quantum Safety
    safety_icons = {
        QuantumSafety.FULLY_SAFE: "✅",
        QuantumSafety.HYBRID: "🔄",
        QuantumSafety.VULNERABLE: "⚠️",
        QuantumSafety.CRITICAL: "🚨",
    }
    icon = safety_icons.get(classification, "❓")
    print(f"\n🔐 Quantum Safety: {icon} {classification.value}")
    
    # HNDL Score
    print(f"\n📊 HNDL Risk Assessment:")
    print(f"   Score: {hndl_score.score:.3f} ({hndl_score.label.value})")
    print(f"   Risk Horizon: {hndl_score.estimated_risk_horizon}")
    print(f"   Recommendation: {hndl_score.recommended_action}")
    
    print(f"\n{'=' * 50}\n")


async def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Usage: python quick_scan.py <target> [port]")
        print("Example: python quick_scan.py example.com 443")
        print("         python quick_scan.py example.com:8443")
        sys.exit(0 if "--help" in sys.argv or "-h" in sys.argv else 1)
    
    # Parse target
    target = sys.argv[1]
    port = 443
    
    if ":" in target:
        target, port_str = target.rsplit(":", 1)
        port = int(port_str)
    elif len(sys.argv) > 2:
        port = int(sys.argv[2])
    
    print(f"\n🔍 Scanning {target}:{port}...")
    
    # Initialize services
    scanner = TLSScanner(timeout=30)
    classifier = PQCClassifier()
    scorer = HNDLScorer()
    
    # Run scan
    scan_result = scanner.scan(target, port)
    
    if scan_result.status == ScanStatus.SUCCESS:
        # Classify
        all_algos = scan_result.key_exchange_algorithms + [
            scan_result.certificate.public_key_algorithm if scan_result.certificate else ""
        ]
        classification = classifier.get_worst_safety(all_algos)
        
        # Score
        hndl_score = scorer.calculate(
            key_exchange_algorithms=scan_result.key_exchange_algorithms,
            certificate_algorithm=scan_result.certificate.public_key_algorithm if scan_result.certificate else "",
        )
    else:
        classification = QuantumSafety.VULNERABLE
        hndl_score = None
    
    print_result(target, port, scan_result, classification, hndl_score)
    
    # Exit code based on safety
    if classification == QuantumSafety.CRITICAL:
        sys.exit(2)
    elif classification == QuantumSafety.VULNERABLE:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())
