"""
QuShield Workflow Orchestrator

Orchestrates the complete 4-layer scanning workflow:
- Layer 1: Asset Discovery
- Layer 2: TLS Scanning
- Layer 3: PQC Analysis & CBOM Generation
- Layer 4: PQC Certification

This module provides the unified entry point for the complete scanning pipeline.
"""

import asyncio
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from qushield.utils.logging import (
    get_logger,
    timed_async,
    log_with_data,
)
from qushield.core.discovery import AssetDiscovery, DiscoveredAsset
from qushield.core.scanner import TLSScanner, TLSScanResult, ScanStatus
from qushield.core.classifier import PQCClassifier, QuantumSafety
from qushield.core.scorer import HNDLScorer, HNDLScore, HNDLRiskLabel
from qushield.output.cbom import CBOMBuilder, CBOM
from qushield.output.collector import OutputCollector, StructuredOutput

logger = get_logger("workflow")
discovery_logger = get_logger("discovery")
scanner_logger = get_logger("scanner")
analysis_logger = get_logger("analysis")
certify_logger = get_logger("certify")

import logging


@dataclass
class AssetAnalysis:
    """Complete analysis for a single asset"""
    # Layer 1: Discovery
    fqdn: str
    port: int = 443
    discovery_source: str = ""
    
    # Layer 2: Scan
    scan_result: Optional[TLSScanResult] = None
    scan_success: bool = False
    
    # Layer 3: Analysis
    quantum_safety: str = "UNKNOWN"
    is_quantum_safe: bool = False
    hndl_score: Optional[HNDLScore] = None
    key_exchange_algorithms: List[str] = field(default_factory=list)
    certificate_algorithm: str = ""
    
    # Layer 4: Certification
    cert_tier: str = "UNKNOWN"
    cert_issued: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "fqdn": self.fqdn,
            "port": self.port,
            "discovery_source": self.discovery_source,
            "scan_success": self.scan_success,
            "quantum_safety": self.quantum_safety,
            "is_quantum_safe": self.is_quantum_safe,
            "hndl_score": self.hndl_score.score if self.hndl_score else None,
            "hndl_label": self.hndl_score.label.value if self.hndl_score else None,
            "recommended_action": self.hndl_score.recommended_action if self.hndl_score else None,
            "key_exchange_algorithms": self.key_exchange_algorithms,
            "certificate_algorithm": self.certificate_algorithm,
            "cert_tier": self.cert_tier,
        }


@dataclass
class WorkflowResult:
    """Complete workflow result for a domain"""
    domain: str
    start_time: str
    end_time: str
    duration_ms: float
    
    # Layer 1 results
    assets_discovered: int = 0
    discovery_sources: List[str] = field(default_factory=list)
    
    # Layer 2 results
    assets_scanned: int = 0
    scan_failures: int = 0
    
    # Layer 3 results (safety counts)
    quantum_safe_count: int = 0
    hybrid_count: int = 0
    pqc_ready_count: int = 0  # Alias for hybrid_count
    vulnerable_count: int = 0
    critical_count: int = 0
    average_hndl_score: float = 0.0
    
    # Layer 4 results (certification tiers)
    platinum_count: int = 0   # FULLY_QUANTUM_SAFE
    gold_count: int = 0       # PQC_READY
    silver_count: int = 0     # VULNERABLE
    bronze_count: int = 0     # CRITICAL
    certificates_issued: int = 0
    
    # Detailed results
    assets: List[AssetAnalysis] = field(default_factory=list)
    cbom: Optional[CBOM] = None
    
    # Structured output (comprehensive)
    structured_output: Optional[StructuredOutput] = None
    output_file: Optional[str] = None
    
    # Errors
    errors: List[str] = field(default_factory=list)
    
    @property
    def summary(self):
        """Allow scripts to access summary statistics directly via .summary attribute"""
        return self
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": self.duration_ms,
            "summary": {
                "assets_discovered": self.assets_discovered,
                "assets_scanned": self.assets_scanned,
                "scan_failures": self.scan_failures,
                "duration_ms": self.duration_ms,
                "quantum_safe_count": self.quantum_safe_count,
                "hybrid_count": self.hybrid_count,
                "vulnerable_count": self.vulnerable_count,
                "critical_count": self.critical_count,
                "platinum_count": self.platinum_count,
                "gold_count": self.gold_count,
                "silver_count": self.silver_count,
                "bronze_count": self.bronze_count,
                "average_hndl_score": round(self.average_hndl_score, 3),
            },
            "assets": [a.to_dict() for a in self.assets],
            "errors": self.errors,
        }
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# Callback type hints
from typing import Callable, Awaitable

OnDiscoveryCallback = Callable[[List['DiscoveredAsset']], Awaitable[None]]
OnAssetScannedCallback = Callable[['AssetAnalysis'], Awaitable[None]]
OnProgressCallback = Callable[[str, int, int], Awaitable[None]]  # stage, current, total


class QuShieldWorkflow:
    """
    Main workflow orchestrator for QuShield.
    
    Coordinates all 4 layers of the scanning pipeline.
    Supports real-time callbacks for streaming results.
    """
    
    def __init__(
        self,
        scan_timeout: int = 30,
        max_concurrent_scans: int = 20,  # Increased for better throughput
        use_ct_logs: bool = True,
        use_subdomain_enum: bool = True,
        save_outputs: bool = True,
        on_discovery: Optional[OnDiscoveryCallback] = None,
        on_asset_scanned: Optional[OnAssetScannedCallback] = None,
        on_progress: Optional[OnProgressCallback] = None,
    ):
        self.scan_timeout = scan_timeout
        self.max_concurrent_scans = max_concurrent_scans
        self.use_ct_logs = use_ct_logs
        self.use_subdomain_enum = use_subdomain_enum
        self.save_outputs = save_outputs
        
        # Callbacks for real-time streaming
        self.on_discovery = on_discovery
        self.on_asset_scanned = on_asset_scanned
        self.on_progress = on_progress
        
        # Initialize services
        self.discovery = AssetDiscovery(timeout=scan_timeout)
        self.scanner = TLSScanner(timeout=scan_timeout)
        self.classifier = PQCClassifier()
        self.hndl_scorer = HNDLScorer()
        self.cbom_builder = CBOMBuilder()
        self.output_collector = OutputCollector()
    
    async def run(
        self,
        domain: str,
        max_assets: int = 50,
        skip_discovery: bool = False,
        targets: Optional[List[str]] = None,
    ) -> WorkflowResult:
        """
        Run complete workflow for a domain.
        
        Args:
            domain: Base domain to scan
            max_assets: Maximum number of assets to scan
            skip_discovery: Skip Layer 1 and use provided targets
            targets: Specific targets to scan (if skip_discovery=True)
            
        Returns:
            WorkflowResult with complete analysis
        """
        import time
        start = time.perf_counter()
        start_time = datetime.utcnow().isoformat()
        
        logger.info(f"Starting QuShield workflow for {domain}", extra={
            "data": {
                "max_assets": max_assets,
                "skip_discovery": skip_discovery,
            }
        })
        
        result = WorkflowResult(
            domain=domain,
            start_time=start_time,
            end_time="",
            duration_ms=0,
        )
        
        # Start structured output collection
        self.output_collector.start_scan(domain)
        
        try:
            # ================================================================
            # LAYER 1: Asset Discovery
            # ================================================================
            if skip_discovery and targets:
                assets = [
                    DiscoveredAsset(fqdn=t, source="manual")
                    for t in targets
                ]
            else:
                assets = await self._layer1_discovery(domain)
            
            # Notify discovery callback
            if self.on_discovery:
                try:
                    await self.on_discovery(assets)
                except Exception as e:
                    logger.warning(f"Discovery callback failed: {e}")
            
            result.assets_discovered = len(assets)
            result.discovery_sources = list(set(a.source for a in assets))
            
            # Collect Layer 1 outputs for ALL discovered assets
            await self.output_collector.collect_layer1(assets)
            
            # Extended Discovery: WHOIS, NS/MX/TXT, ports, ASN/GeoIP, services, cloud/IoT
            # Run on limited subset for performance (port scanning is slow)
            #assets_for_extended = assets[:max_assets]
            assets_for_extended = assets[:]
            await self.output_collector.collect_extended_discovery(assets_for_extended)
            
            # ================================================================
            # LAYER 2: TLS Scanning (limit to max_assets for performance)
            # ================================================================
            #assets_to_scan = assets[:max_assets]
            assets_to_scan = assets[:]
            scanned_assets = await self._layer2_scanning(assets_to_scan)
            
            result.assets_scanned = sum(1 for a in scanned_assets if a.scan_success)
            result.scan_failures = sum(1 for a in scanned_assets if not a.scan_success)
            
            # Collect Layer 2 outputs
            scan_results = [(a.fqdn, a.scan_result) for a in scanned_assets]
            self.output_collector.collect_layer2(scan_results)
            
            # ================================================================
            # LAYER 3: PQC Analysis & CBOM Generation
            # ================================================================
            analyzed_assets = self._layer3_analysis(scanned_assets)
            
            # Calculate statistics
            for asset in analyzed_assets:
                if asset.quantum_safety == QuantumSafety.FULLY_SAFE.value:
                    result.quantum_safe_count += 1
                elif asset.quantum_safety == QuantumSafety.HYBRID.value:
                    result.hybrid_count += 1
                    result.pqc_ready_count += 1  # For legacy compatibility
                elif asset.quantum_safety == QuantumSafety.VULNERABLE.value:
                    result.vulnerable_count += 1
                elif asset.quantum_safety == QuantumSafety.CRITICAL.value:
                    result.critical_count += 1
                
                # Tier mapping
                if asset.cert_tier == "FULLY_QUANTUM_SAFE":
                    result.platinum_count += 1
                elif asset.cert_tier == "PQC_READY":
                    result.gold_count += 1
                elif asset.cert_tier == "VULNERABLE":
                    result.silver_count += 1
                elif asset.cert_tier == "CRITICAL":
                    result.bronze_count += 1
            
            # Calculate average HNDL score
            hndl_scores = [a.hndl_score.score for a in analyzed_assets if a.hndl_score]
            if hndl_scores:
                result.average_hndl_score = sum(hndl_scores) / len(hndl_scores)
            
            # Generate CBOM
            result.cbom = self._generate_cbom(domain, analyzed_assets)
            
            # Collect Layer 3 outputs
            self.output_collector.collect_layer3(analyzed_assets, result.cbom)
            
            # ================================================================
            # LAYER 4: PQC Certification
            # ================================================================
            certified_assets = self._layer4_certification(analyzed_assets)
            result.certificates_issued = sum(1 for a in certified_assets if a.cert_issued)
            
            result.assets = certified_assets
            
            # Collect Layer 4 outputs
            self.output_collector.collect_layer4(certified_assets)
            
        except Exception as e:
            logger.error(f"Workflow failed: {e}", exc_info=True)
            result.errors.append(str(e))
        
        finally:
            # Cleanup
            await self.discovery.close()
        
        # Finalize output collection
        self.output_collector.end_scan()
        
        # Save structured outputs
        if self.save_outputs:
            output_path = self.output_collector.save()
            result.output_file = str(output_path)
        
        result.structured_output = self.output_collector.get_output()
        
        # Finalize result
        end_time = time.perf_counter()
        result.end_time = datetime.utcnow().isoformat()
        result.duration_ms = (end_time - start) * 1000
        
        logger.info(f"Workflow completed for {domain}", extra={
            "data": {
                "duration_ms": result.duration_ms,
                "assets_scanned": result.assets_scanned,
                "quantum_safe": result.quantum_safe_count,
                "vulnerable": result.vulnerable_count,
                "output_file": result.output_file,
            }
        })
        
        return result
    
    @timed_async(layer=1)
    async def _layer1_discovery(self, domain: str) -> List[DiscoveredAsset]:
        """Layer 1: Discover assets via CT logs and subdomain enumeration"""
        discovery_logger.info(f"Starting asset discovery for {domain}", extra={"layer": 1})
        
        assets = await self.discovery.discover_all(
            domain,
            use_ct_logs=self.use_ct_logs,
            use_subdomain_enum=self.use_subdomain_enum,
            verify_dns=False,  # Don't verify DNS to speed up
        )
        
        discovery_logger.info(f"Discovered {len(assets)} assets", extra={
            "layer": 1,
            "data": {"count": len(assets), "sources": list(set(a.source for a in assets))}
        })
        
        return assets
    
    @timed_async(layer=2)
    async def _layer2_scanning(self, assets: List[DiscoveredAsset]) -> List[AssetAnalysis]:
        """Layer 2: Scan all assets for TLS configuration with real-time callbacks"""
        scanner_logger.info(f"Starting TLS scan for {len(assets)} assets", extra={"layer": 2})
        
        results = []
        scanned_count = [0]  # Use list to allow modification in nested function
        total = len(assets)
        
        # Use semaphore to limit concurrent scans
        semaphore = asyncio.Semaphore(self.max_concurrent_scans)
        
        async def scan_with_semaphore(asset: DiscoveredAsset) -> AssetAnalysis:
            async with semaphore:
                analysis = await self._scan_single_asset(asset)
                
                # Run Layer 3 analysis immediately for this asset
                self._analyze_single_asset(analysis)
                
                # Run Layer 4 certification immediately
                self._certify_single_asset(analysis)
                
                # Notify callback with fully analyzed asset
                scanned_count[0] += 1
                if self.on_asset_scanned:
                    try:
                        await self.on_asset_scanned(analysis)
                    except Exception as e:
                        scanner_logger.warning(f"Asset scanned callback failed: {e}")
                
                # Progress callback
                if self.on_progress:
                    try:
                        await self.on_progress("scanning", scanned_count[0], total)
                    except Exception as e:
                        pass
                
                return analysis
        
        # Run scans concurrently
        tasks = [scan_with_semaphore(asset) for asset in assets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                scanner_logger.error(f"Scan exception for {assets[i].fqdn}: {result}")
                failed_analysis = AssetAnalysis(
                    fqdn=assets[i].fqdn,
                    port=assets[i].port,
                    discovery_source=assets[i].source,
                    scan_success=False,
                    cert_tier="NOT_SCANNED",
                )
                valid_results.append(failed_analysis)
                # Still notify callback for failed scans
                if self.on_asset_scanned:
                    try:
                        await self.on_asset_scanned(failed_analysis)
                    except Exception as e:
                        pass
            else:
                valid_results.append(result)
        
        success_count = sum(1 for r in valid_results if r.scan_success)
        scanner_logger.info(f"Completed scanning: {success_count}/{len(assets)} successful", extra={"layer": 2})
        
        return valid_results
    
    def _analyze_single_asset(self, asset: AssetAnalysis):
        """Layer 3: Analyze a single asset for PQC posture"""
        if not asset.scan_success:
            return
        
        # Get all algorithms
        all_algorithms = asset.key_exchange_algorithms.copy()
        if asset.certificate_algorithm:
            all_algorithms.append(asset.certificate_algorithm)
        
        if not all_algorithms:
            return
        
        # Classify quantum safety
        effective_safety = self.classifier.get_effective_safety(all_algorithms)
        asset.quantum_safety = effective_safety.value
        asset.is_quantum_safe = effective_safety == QuantumSafety.FULLY_SAFE
        
        # Calculate HNDL score
        asset.hndl_score = self.hndl_scorer.calculate(
            key_exchange_algorithms=asset.key_exchange_algorithms,
            certificate_algorithm=asset.certificate_algorithm or "RSA",
            endpoint_type="banking",
        )
    
    def _certify_single_asset(self, asset: AssetAnalysis):
        """Layer 4: Determine certification tier for a single asset"""
        if not asset.scan_success:
            asset.cert_tier = "NOT_SCANNED"
            return
        
        if asset.quantum_safety == QuantumSafety.FULLY_SAFE.value:
            asset.cert_tier = "FULLY_QUANTUM_SAFE"
            asset.cert_issued = True
        elif asset.quantum_safety == QuantumSafety.HYBRID.value:
            asset.cert_tier = "PQC_READY"
            asset.cert_issued = True
        elif asset.quantum_safety == QuantumSafety.VULNERABLE.value:
            asset.cert_tier = "VULNERABLE"
            asset.cert_issued = False
        else:
            asset.cert_tier = "CRITICAL"
            asset.cert_issued = False
    
    async def _scan_single_asset(self, asset: DiscoveredAsset) -> AssetAnalysis:
        """Scan a single asset"""
        analysis = AssetAnalysis(
            fqdn=asset.fqdn,
            port=asset.port,
            discovery_source=asset.source,
        )
        
        # 1. Fast pre-scan TCP ping (avoiding 10+ second nmap timeouts on dead ports)
        # Skip this ping if httpx already verified the host is alive recently.
        if asset.source != "httpx":
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(asset.fqdn, asset.port),
                    timeout=5.0
                )
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                scanner_logger.warning(f"Pre-scan TCP ping failed for {asset.fqdn}:{asset.port} ({type(e).__name__})")
                error_msg = str(e) or type(e).__name__
                scan_result = TLSScanResult(
                    target=asset.fqdn, port=asset.port, status=ScanStatus.CONNECTION_ERROR,
                    scan_time=datetime.utcnow().isoformat(), duration_ms=5000,
                    error_message=f"Pre-scan TCP connection failed: {error_msg}"
                )
                analysis.scan_result = scan_result
                analysis.scan_success = False
                return analysis
        
        # 2. Run deep scan in thread pool (Scanner is synchronous)
        loop = asyncio.get_event_loop()
        scan_result = await loop.run_in_executor(
            None,
            lambda: self.scanner.scan(asset.fqdn, asset.port)
        )
        
        analysis.scan_result = scan_result
        analysis.scan_success = scan_result.status == ScanStatus.SUCCESS
        
        if analysis.scan_success:
            analysis.key_exchange_algorithms = scan_result.key_exchange_algorithms
            if scan_result.certificate:
                analysis.certificate_algorithm = scan_result.certificate.public_key_algorithm
        
        return analysis
    
    def _layer3_analysis(self, assets: List[AssetAnalysis]) -> List[AssetAnalysis]:
        """Layer 3: Analyze PQC posture and calculate HNDL scores"""
        analysis_logger.info(f"Starting PQC analysis for {len(assets)} assets", extra={"layer": 3})
        
        for asset in assets:
            if not asset.scan_success:
                continue
            
            # Get all algorithms
            all_algorithms = asset.key_exchange_algorithms.copy()
            if asset.certificate_algorithm:
                all_algorithms.append(asset.certificate_algorithm)
            
            if not all_algorithms:
                continue
            
            # Classify quantum safety
            effective_safety = self.classifier.get_effective_safety(all_algorithms)
            asset.quantum_safety = effective_safety.value
            asset.is_quantum_safe = effective_safety == QuantumSafety.FULLY_SAFE
            
            # Calculate HNDL score
            asset.hndl_score = self.hndl_scorer.calculate(
                key_exchange_algorithms=asset.key_exchange_algorithms,
                certificate_algorithm=asset.certificate_algorithm or "RSA",
                endpoint_type="banking",  # Assume banking for high sensitivity
            )
            
            analysis_logger.debug(f"Analyzed {asset.fqdn}: {asset.quantum_safety}, HNDL={asset.hndl_score.score}", extra={
                "layer": 3,
                "target": asset.fqdn,
            })
        
        analysis_logger.info("PQC analysis completed", extra={"layer": 3})
        return assets
    
    def _generate_cbom(self, domain: str, assets: List[AssetAnalysis]) -> CBOM:
        """Generate CBOM from all analyzed assets"""
        self.cbom_builder.reset()
        
        for asset in assets:
            if not asset.scan_success:
                continue
            
            # Add key exchange algorithms
            for algo in asset.key_exchange_algorithms:
                self.cbom_builder.add_algorithm(algo, context=f"TLS key exchange ({asset.fqdn})")
            
            # Add certificate
            if asset.certificate_algorithm and asset.scan_result and asset.scan_result.certificate:
                cert = asset.scan_result.certificate
                self.cbom_builder.add_certificate(
                    subject=cert.subject,
                    issuer=cert.issuer,
                    algorithm=asset.certificate_algorithm,
                    key_size=cert.public_key_size,
                    not_after=cert.not_after,
                )
        
        return self.cbom_builder.build(target_name=domain)
    
    def _layer4_certification(self, assets: List[AssetAnalysis]) -> List[AssetAnalysis]:
        """Layer 4: Determine certification tier for each asset"""
        certify_logger.info(f"Starting certification evaluation for {len(assets)} assets", extra={"layer": 4})
        
        for asset in assets:
            if not asset.scan_success:
                asset.cert_tier = "NOT_SCANNED"
                continue
            
            # Determine tier based on quantum safety
            if asset.quantum_safety == QuantumSafety.FULLY_SAFE.value:
                asset.cert_tier = "FULLY_QUANTUM_SAFE"
                asset.cert_issued = True
            elif asset.quantum_safety == QuantumSafety.HYBRID.value:
                asset.cert_tier = "PQC_READY"
                asset.cert_issued = True
            elif asset.quantum_safety == QuantumSafety.VULNERABLE.value:
                asset.cert_tier = "VULNERABLE"
                asset.cert_issued = False
            else:
                asset.cert_tier = "CRITICAL"
                asset.cert_issued = False
        
        issued_count = sum(1 for a in assets if a.cert_issued)
        certify_logger.info(f"Certification completed: {issued_count} certificates issued", extra={"layer": 4})
        
        return assets


async def run_workflow(
    domain: str,
    max_assets: int = 50,
    skip_discovery: bool = False,
    targets: Optional[List[str]] = None,
) -> WorkflowResult:
    """Convenience function to run the complete workflow"""
    workflow = QuShieldWorkflow()
    return await workflow.run(
        domain=domain,
        max_assets=max_assets,
        skip_discovery=skip_discovery,
        targets=targets,
    )


def run_workflow_sync(
    domain: str,
    max_assets: int = 50,
    skip_discovery: bool = False,
    targets: Optional[List[str]] = None,
) -> WorkflowResult:
    """Synchronous wrapper for running workflow"""
    return asyncio.run(run_workflow(domain, max_assets, skip_discovery, targets))
