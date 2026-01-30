#!/usr/bin/env python3
"""
QuShield CLI Scanner

Command-line interface for running PQC readiness scans.

Usage:
    python scripts/scan.py example.com
    python scripts/scan.py example.com --max-assets 50 --output-dir results/
    python scripts/scan.py example.com --json --quiet
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from qushield.workflow import QuShieldWorkflow
from qushield.utils.logging import setup_logging


def parse_args():
    parser = argparse.ArgumentParser(
        description="QuShield - Quantum-Safe Cryptography Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s example.com
    %(prog)s example.com --max-assets 100
    %(prog)s example.com --output-dir ./results --json
    %(prog)s example.com --targets api.example.com,www.example.com
        """
    )
    
    # Required arguments
    parser.add_argument(
        "domain",
        help="Target domain to scan (e.g., example.com)"
    )
    
    # Optional arguments
    parser.add_argument(
        "--max-assets", "-m",
        type=int,
        default=100,
        help="Maximum number of assets to scan (default: 100)"
    )
    
    parser.add_argument(
        "--output-dir", "-o",
        type=str,
        default="outputs",
        help="Directory for output files (default: outputs)"
    )
    
    parser.add_argument(
        "--log-dir",
        type=str,
        default="logs",
        help="Directory for log files (default: logs)"
    )
    
    parser.add_argument(
        "--targets", "-t",
        type=str,
        help="Comma-separated list of specific targets to scan"
    )
    
    parser.add_argument(
        "--skip-discovery",
        action="store_true",
        help="Skip discovery and use provided targets only"
    )
    
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Scan timeout in seconds (default: 30)"
    )
    
    parser.add_argument(
        "--concurrent", "-c",
        type=int,
        default=5,
        help="Maximum concurrent scans (default: 5)"
    )
    
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )
    
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Minimal console output"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Don't save output files"
    )
    
    return parser.parse_args()


def print_summary(result):
    """Print a formatted summary of the scan results."""
    
    print("\n" + "=" * 60)
    print(f"  QuShield Scan Results: {result.domain}")
    print("=" * 60)
    
    print(f"\n📊 Summary:")
    print(f"   Assets Discovered: {result.assets_discovered}")
    print(f"   Assets Scanned:    {result.assets_scanned}")
    print(f"   Scan Failures:     {result.scan_failures}")
    print(f"   Duration:          {result.duration_ms:.0f}ms")
    
    print(f"\n🔐 Quantum Safety:")
    print(f"   ✅ Quantum-Safe:   {result.quantum_safe_count}")
    print(f"   🔄 Hybrid/PQC:     {result.pqc_ready_count}")
    print(f"   ⚠️  Vulnerable:     {result.vulnerable_count}")
    print(f"   🚨 Critical:       {result.critical_count}")
    
    print(f"\n📜 Certification:")
    print(f"   🏆 Certs Issued:   {result.certificates_issued}")
    
    print(f"\n📈 HNDL Risk Score: {result.average_hndl_score:.3f}")
    
    if result.output_file:
        print(f"\n📁 Output saved to: {result.output_file}")
    
    if result.errors:
        print(f"\n⚠️  Errors: {len(result.errors)}")
        for err in result.errors[:5]:
            print(f"   - {err}")
    
    print("\n" + "=" * 60)


async def main():
    args = parse_args()
    
    # Configure logging
    import logging
    log_level = logging.DEBUG if args.verbose else (logging.WARNING if args.quiet else logging.INFO)
    setup_logging(
        level=log_level,
        console=not args.json,
        file=not args.no_save,
        json_file=not args.no_save,
    )
    
    # Parse targets if provided
    targets = None
    if args.targets:
        targets = [t.strip() for t in args.targets.split(",")]
    
    # Ensure output directory exists
    Path(args.output_dir).mkdir(parents=True, exist_ok=True)
    
    # Run workflow
    try:
        workflow = QuShieldWorkflow(
            scan_timeout=args.timeout,
            max_concurrent_scans=args.concurrent,
            save_outputs=not args.no_save,
        )
        
        result = await workflow.run(
            domain=args.domain,
            max_assets=args.max_assets,
            skip_discovery=args.skip_discovery,
            targets=targets,
        )
        
        if args.json:
            print(result.to_json())
        else:
            print_summary(result)
        
        # Exit with error code if critical issues found
        if result.critical_count > 0:
            sys.exit(2)
        elif result.vulnerable_count > 0:
            sys.exit(1)
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
