"""
QuShield Core - Business Logic Components

This module contains the core scanning and analysis engines:
- AssetDiscovery: Discovers assets via CT logs and DNS enumeration
- TLSScanner: Performs TLS/SSL security scanning
- PQCClassifier: Classifies quantum safety of cryptographic configurations
- HNDLScorer: Calculates Harvest Now, Decrypt Later risk scores
- CertificationEngine: Issues PQC readiness certifications
- PQCSigner: ML-DSA signing for PQC certificates
"""

from qushield.core.discovery import AssetDiscovery, DiscoveredAsset, discover_subdomains, discover_from_ct
from qushield.core.scanner import TLSScanner, TLSScanResult, ScanStatus, CertificateInfo, scan_target, get_scanner
from qushield.core.classifier import (
    PQCClassifier, QuantumSafety, AlgorithmInfo,
    classify_algorithm, is_quantum_safe,
    PQC_ALGORITHMS, HYBRID_ALGORITHMS, VULNERABLE_ALGORITHMS, CRITICAL_LEGACY, SYMMETRIC_ALGORITHMS,
)
from qushield.core.scorer import HNDLScorer, HNDLScore, HNDLRiskLabel, calculate_hndl_score
from qushield.core.certifier import (
    CertificationEngine, CertificationLevel, PolicyEvaluator, LabelSigner,
    PQCCertificate, PolicyResult, evaluate_policy, issue_certificate, get_certification_level,
)
from qushield.core.signer import PQCSigner, CertTier, BadgeGenerator, generate_badge

__all__ = [
    # Discovery
    "AssetDiscovery",
    "DiscoveredAsset",
    "discover_subdomains",
    "discover_from_ct",
    # Scanner
    "TLSScanner",
    "TLSScanResult",
    "ScanStatus",
    "CertificateInfo",
    "scan_target",
    "get_scanner",
    # Classifier
    "PQCClassifier",
    "QuantumSafety",
    "AlgorithmInfo",
    "classify_algorithm",
    "is_quantum_safe",
    "PQC_ALGORITHMS",
    "HYBRID_ALGORITHMS",
    "VULNERABLE_ALGORITHMS",
    "CRITICAL_LEGACY",
    "SYMMETRIC_ALGORITHMS",
    # Scorer
    "HNDLScorer",
    "HNDLScore",
    "HNDLRiskLabel",
    "calculate_hndl_score",
    # Certifier
    "CertificationEngine",
    "CertificationLevel",
    "PolicyEvaluator",
    "LabelSigner",
    "PQCCertificate",
    "PolicyResult",
    "evaluate_policy",
    "issue_certificate",
    "get_certification_level",
    # Signer
    "PQCSigner",
    "CertTier",
    "BadgeGenerator",
    "generate_badge",
]
