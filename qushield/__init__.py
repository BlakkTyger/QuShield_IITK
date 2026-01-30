"""
QuShield - Quantum-Safe Cryptography Scanner

A comprehensive tool for assessing Post-Quantum Cryptography (PQC) readiness
of digital assets, providing TLS scanning, HNDL risk scoring, and CBOM generation.

Architecture:
    Layer 1: Asset Discovery - CT logs, DNS enumeration, subdomain discovery
    Layer 2: TLS Scanning - Protocol analysis, cipher suite detection
    Layer 3: PQC Analysis - Quantum safety classification, HNDL scoring, CBOM
    Layer 4: Certification - PQC readiness certification

Usage:
    from qushield import QuShieldWorkflow
    
    workflow = QuShieldWorkflow()
    result = await workflow.run("example.com")
"""

__version__ = "1.0.0"
__author__ = "QuShield Team"
__license__ = "MIT"

# Lazy imports to avoid circular dependencies
_LAZY_IMPORTS = {
    # Workflow
    "QuShieldWorkflow": ("qushield.workflow", "QuShieldWorkflow"),
    "WorkflowResult": ("qushield.workflow", "WorkflowResult"),
    "AssetAnalysis": ("qushield.workflow", "AssetAnalysis"),
    "run_workflow": ("qushield.workflow", "run_workflow"),
    "run_workflow_sync": ("qushield.workflow", "run_workflow_sync"),
    # Discovery
    "AssetDiscovery": ("qushield.core.discovery", "AssetDiscovery"),
    "DiscoveredAsset": ("qushield.core.discovery", "DiscoveredAsset"),
    "discover_subdomains": ("qushield.core.discovery", "discover_subdomains"),
    "discover_from_ct": ("qushield.core.discovery", "discover_from_ct"),
    # Scanner
    "TLSScanner": ("qushield.core.scanner", "TLSScanner"),
    "TLSScanResult": ("qushield.core.scanner", "TLSScanResult"),
    "ScanStatus": ("qushield.core.scanner", "ScanStatus"),
    "CertificateInfo": ("qushield.core.scanner", "CertificateInfo"),
    "scan_target": ("qushield.core.scanner", "scan_target"),
    # Classifier
    "PQCClassifier": ("qushield.core.classifier", "PQCClassifier"),
    "QuantumSafety": ("qushield.core.classifier", "QuantumSafety"),
    "AlgorithmInfo": ("qushield.core.classifier", "AlgorithmInfo"),
    "classify_algorithm": ("qushield.core.classifier", "classify_algorithm"),
    "is_quantum_safe": ("qushield.core.classifier", "is_quantum_safe"),
    # Scorer
    "HNDLScorer": ("qushield.core.scorer", "HNDLScorer"),
    "HNDLScore": ("qushield.core.scorer", "HNDLScore"),
    "HNDLRiskLabel": ("qushield.core.scorer", "HNDLRiskLabel"),
    "calculate_hndl_score": ("qushield.core.scorer", "calculate_hndl_score"),
    # Certifier
    "CertificationEngine": ("qushield.core.certifier", "CertificationEngine"),
    "CertificationLevel": ("qushield.core.certifier", "CertificationLevel"),
    "PolicyEvaluator": ("qushield.core.certifier", "PolicyEvaluator"),
    "PQCCertificate": ("qushield.core.certifier", "PQCCertificate"),
    "PolicyResult": ("qushield.core.certifier", "PolicyResult"),
    # Signer
    "PQCSigner": ("qushield.core.signer", "PQCSigner"),
    "CertTier": ("qushield.core.signer", "CertTier"),
    "BadgeGenerator": ("qushield.core.signer", "BadgeGenerator"),
    # CBOM
    "CBOMBuilder": ("qushield.output.cbom", "CBOMBuilder"),
    "CBOM": ("qushield.output.cbom", "CBOM"),
    "CryptoComponent": ("qushield.output.cbom", "CryptoComponent"),
    # Output
    "OutputCollector": ("qushield.output.collector", "OutputCollector"),
    "StructuredOutput": ("qushield.output.collector", "StructuredOutput"),
    "DashboardSummary": ("qushield.output.collector", "DashboardSummary"),
    # Extended Discovery
    "ExtendedDiscoveryService": ("qushield.services.extended", "ExtendedDiscoveryService"),
    # Logging
    "setup_logging": ("qushield.utils.logging", "setup_logging"),
    "get_logger": ("qushield.utils.logging", "get_logger"),
}

def __getattr__(name):
    if name in _LAZY_IMPORTS:
        module_path, attr_name = _LAZY_IMPORTS[name]
        import importlib
        module = importlib.import_module(module_path)
        return getattr(module, attr_name)
    raise AttributeError(f"module 'qushield' has no attribute '{name}'")

__all__ = [
    "QuShieldWorkflow",
    "AssetDiscovery", 
    "TLSScanner",
    "PQCClassifier",
    "QuantumSafety",
    "HNDLScorer",
    "HNDLRiskLabel",
    "CertificationEngine",
    "CBOMBuilder",
    "__version__",
]
