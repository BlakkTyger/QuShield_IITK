"""
Certification Engine - Layer 4

Provides PQC-based certification and labeling for scanned assets.

Submodules:
1. PolicyEvaluator - Three-tier quantum safety policy evaluation
2. LabelSigner - ML-DSA signing for PQC certificates using oqs-python

References:
- NIST FIPS 204: ML-DSA (Dilithium)
- JSON-LD Canonical Form
- oqs-python: https://github.com/open-quantum-safe/liboqs-python
"""

import json
import base64
import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum

from qushield.utils.logging import get_logger, timed
from qushield.core.classifier import PQCClassifier, QuantumSafety, AlgorithmInfo

logger = get_logger("certification")


# ============================================================================
# Policy Evaluation
# ============================================================================

class CertificationLevel(str, Enum):
    """Certification level based on quantum safety"""
    FULLY_SAFE = "FULLY_QUANTUM_SAFE"    # All operations use PQC
    PQC_READY = "PQC_READY"               # Some PQC present
    VULNERABLE = "QUANTUM_VULNERABLE"     # No PQC, classical only


@dataclass
class PolicyResult:
    """Result of policy evaluation"""
    level: CertificationLevel
    score: float                          # 0.0 - 1.0
    pqc_algorithms: List[str]             # PQC algorithms found
    hybrid_algorithms: List[str]          # Hybrid algorithms found
    vulnerable_algorithms: List[str]      # Vulnerable algorithms found
    critical_algorithms: List[str]        # Critical/deprecated algorithms
    recommendations: List[str]            # Policy recommendations
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level.value,
            "score": self.score,
            "pqc_algorithms": self.pqc_algorithms,
            "hybrid_algorithms": self.hybrid_algorithms,
            "vulnerable_algorithms": self.vulnerable_algorithms,
            "critical_algorithms": self.critical_algorithms,
            "recommendations": self.recommendations,
            "details": self.details,
        }


class PolicyEvaluator:
    """
    Evaluates quantum safety policy for a set of algorithms.
    
    Three-tier logic:
    - FULLY_SAFE: All operations use PQC algorithms
    - PQC_READY: At least one PQC algorithm present
    - VULNERABLE: No PQC algorithms present
    """
    
    def __init__(self):
        self.classifier = PQCClassifier()
        logger.debug("PolicyEvaluator initialized", extra={"layer": 4})
    
    @timed(logger=logger, layer=4)
    def evaluate(
        self,
        algorithms: List[str],
        include_recommendations: bool = True,
    ) -> PolicyResult:
        """
        Evaluate policy for a list of algorithms.
        
        Args:
            algorithms: List of algorithm names/identifiers
            include_recommendations: Whether to generate recommendations
            
        Returns:
            PolicyResult with certification level and details
        """
        logger.info("Evaluating policy", extra={
            "layer": 4,
            "data": {"algorithm_count": len(algorithms)}
        })
        
        # Classify all algorithms
        pqc_algos = []
        hybrid_algos = []
        vulnerable_algos = []
        critical_algos = []
        
        for algo in algorithms:
            info = self.classifier.classify(algo)
            
            if info.safety == QuantumSafety.FULLY_SAFE:
                pqc_algos.append(algo)
            elif info.safety == QuantumSafety.HYBRID:
                hybrid_algos.append(algo)
            elif info.safety == QuantumSafety.CRITICAL:
                critical_algos.append(algo)
            else:  # VULNERABLE
                vulnerable_algos.append(algo)
        
        # Determine certification level using three-tier logic
        level = self._determine_level(
            pqc_algos, hybrid_algos, vulnerable_algos, critical_algos
        )
        
        # Calculate score
        score = self._calculate_score(
            pqc_algos, hybrid_algos, vulnerable_algos, critical_algos
        )
        
        # Generate recommendations
        recommendations = []
        if include_recommendations:
            recommendations = self._generate_recommendations(
                level, pqc_algos, hybrid_algos, vulnerable_algos, critical_algos
            )
        
        result = PolicyResult(
            level=level,
            score=score,
            pqc_algorithms=pqc_algos,
            hybrid_algorithms=hybrid_algos,
            vulnerable_algorithms=vulnerable_algos,
            critical_algorithms=critical_algos,
            recommendations=recommendations,
            details={
                "total_algorithms": len(algorithms),
                "pqc_count": len(pqc_algos),
                "hybrid_count": len(hybrid_algos),
                "vulnerable_count": len(vulnerable_algos),
                "critical_count": len(critical_algos),
            }
        )
        
        logger.info(f"Policy evaluation complete: {level.value}", extra={
            "layer": 4,
            "data": {
                "level": level.value,
                "score": score,
                "pqc_count": len(pqc_algos),
            }
        })
        
        return result
    
    def _determine_level(
        self,
        pqc: List[str],
        hybrid: List[str],
        vulnerable: List[str],
        critical: List[str],
    ) -> CertificationLevel:
        """
        Determine certification level using three-tier logic:
        - FULLY_SAFE: All ops PQC (no vulnerable, no critical)
        - PQC_READY: Any PQC present
        - VULNERABLE: None PQC
        """
        has_pqc = len(pqc) > 0 or len(hybrid) > 0
        has_vulnerable = len(vulnerable) > 0 or len(critical) > 0
        
        if has_pqc and not has_vulnerable:
            # All algorithms are PQC or hybrid, none vulnerable
            return CertificationLevel.FULLY_SAFE
        elif has_pqc:
            # Some PQC present, but also some vulnerable
            return CertificationLevel.PQC_READY
        else:
            # No PQC algorithms at all
            return CertificationLevel.VULNERABLE
    
    def _calculate_score(
        self,
        pqc: List[str],
        hybrid: List[str],
        vulnerable: List[str],
        critical: List[str],
    ) -> float:
        """Calculate quantum readiness score (0.0 - 1.0)"""
        total = len(pqc) + len(hybrid) + len(vulnerable) + len(critical)
        if total == 0:
            return 0.0
        
        # Weights: PQC=1.0, Hybrid=0.7, Vulnerable=0.0, Critical=-0.2
        score = (
            len(pqc) * 1.0 +
            len(hybrid) * 0.7 +
            len(vulnerable) * 0.0 +
            len(critical) * -0.2
        ) / total
        
        return max(0.0, min(1.0, score))
    
    def _generate_recommendations(
        self,
        level: CertificationLevel,
        pqc: List[str],
        hybrid: List[str],
        vulnerable: List[str],
        critical: List[str],
    ) -> List[str]:
        """Generate policy recommendations"""
        recommendations = []
        
        if critical:
            recommendations.append(
                f"CRITICAL: Immediately remove deprecated algorithms: {', '.join(critical[:3])}"
            )
        
        if vulnerable:
            recommendations.append(
                f"HIGH: Migrate vulnerable algorithms to PQC: {', '.join(vulnerable[:3])}"
            )
        
        if level == CertificationLevel.VULNERABLE:
            recommendations.append(
                "Deploy hybrid key exchange (X25519+ML-KEM-768) as first step"
            )
            recommendations.append(
                "Plan certificate migration to ML-DSA within 12 months"
            )
        elif level == CertificationLevel.PQC_READY:
            recommendations.append(
                "Continue migration to achieve FULLY_QUANTUM_SAFE status"
            )
            if vulnerable:
                recommendations.append(
                    f"Remaining vulnerable algorithms: {len(vulnerable)}"
                )
        else:  # FULLY_SAFE
            recommendations.append(
                "Maintain PQC posture and monitor for algorithm updates"
            )
        
        return recommendations


# ============================================================================
# PQC Certificate and Label Signing
# ============================================================================

@dataclass
class PQCCertificate:
    """PQC Certificate issued by QuShield"""
    certificate_id: str
    subject: str                          # Asset FQDN
    level: CertificationLevel             # Certification level
    score: float                          # Quantum readiness score
    issued_at: str                        # ISO timestamp
    expires_at: str                       # ISO timestamp
    issuer: str = "QuShield PQC Authority"
    algorithm: str = "ML-DSA-87"          # Signing algorithm
    public_key: Optional[str] = None      # Base64 public key
    signature: Optional[str] = None       # Base64 signature
    payload_hash: Optional[str] = None    # SHA3-256 hash of payload
    policy_result: Optional[PolicyResult] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "certificate_id": self.certificate_id,
            "subject": self.subject,
            "level": self.level.value,
            "score": self.score,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "issuer": self.issuer,
            "algorithm": self.algorithm,
            "public_key": self.public_key,
            "signature": self.signature,
            "payload_hash": self.payload_hash,
            "policy_result": self.policy_result.to_dict() if self.policy_result else None,
        }
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class LabelSigner:
    """
    Signs PQC certificates using ML-DSA (FIPS 204) via oqs-python.
    
    Process:
    1. Create JSON-LD canonical payload
    2. Hash payload with SHA3-256
    3. Sign hash with ML-DSA-87
    4. Base64 encode signature
    """
    
    SUPPORTED_ALGORITHMS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
    DEFAULT_ALGORITHM = "ML-DSA-87"
    VALIDITY_DAYS = 365
    
    def __init__(self, algorithm: str = None):
        self.algorithm = algorithm or self.DEFAULT_ALGORITHM
        self._oqs_available = self._check_oqs()
        self._keypair: Optional[Tuple[bytes, bytes]] = None
        self._sig_instance = None
        
        if self._oqs_available:
            self._initialize_signer()
        
        logger.debug(f"LabelSigner initialized (algorithm={self.algorithm})", extra={
            "layer": 4,
            "data": {"oqs_available": self._oqs_available}
        })
    
    def _check_oqs(self) -> bool:
        """Check if oqs-python is available"""
        try:
            import oqs
            return True
        except ImportError:
            logger.warning("oqs-python not installed. ML-DSA signing disabled.", extra={
                "layer": 4
            })
            return False
    
    def _initialize_signer(self):
        """Initialize ML-DSA signer and generate keypair"""
        try:
            import oqs
            
            # Map algorithm name to OQS name
            oqs_name = self.algorithm.replace("-", "")  # ML-DSA-87 -> MLDSA87
            
            # Create signature instance
            self._sig_instance = oqs.Signature(oqs_name)
            
            # Generate keypair
            public_key = self._sig_instance.generate_keypair()
            secret_key = self._sig_instance.export_secret_key()
            self._keypair = (public_key, secret_key)
            
            logger.info(f"ML-DSA keypair generated", extra={
                "layer": 4,
                "data": {
                    "algorithm": self.algorithm,
                    "public_key_size": len(public_key),
                }
            })
            
        except Exception as e:
            logger.error(f"Failed to initialize ML-DSA signer: {e}", extra={
                "layer": 4
            })
            self._oqs_available = False
    
    def get_public_key(self) -> Optional[str]:
        """Get base64-encoded public key"""
        if self._keypair:
            return base64.b64encode(self._keypair[0]).decode('ascii')
        return None
    
    def _create_canonical_payload(self, certificate: PQCCertificate) -> str:
        """
        Create JSON-LD canonical form of the certificate payload.
        
        The payload includes all certificate fields except signature.
        """
        payload = {
            "@context": "https://w3id.org/security/v2",
            "@type": "PQCCertificate",
            "id": f"urn:uuid:{certificate.certificate_id}",
            "subject": certificate.subject,
            "level": certificate.level.value,
            "score": certificate.score,
            "issuedAt": certificate.issued_at,
            "expiresAt": certificate.expires_at,
            "issuer": certificate.issuer,
            "algorithm": certificate.algorithm,
        }
        
        if certificate.policy_result:
            payload["policyResult"] = {
                "pqcAlgorithms": certificate.policy_result.pqc_algorithms,
                "hybridAlgorithms": certificate.policy_result.hybrid_algorithms,
                "vulnerableAlgorithms": certificate.policy_result.vulnerable_algorithms,
            }
        
        # Canonical JSON: sorted keys, no whitespace
        return json.dumps(payload, sort_keys=True, separators=(',', ':'))
    
    def _hash_payload(self, payload: str) -> bytes:
        """Hash payload with SHA3-256"""
        return hashlib.sha3_256(payload.encode('utf-8')).digest()
    
    @timed(logger=logger, layer=4)
    def sign(self, certificate: PQCCertificate) -> PQCCertificate:
        """
        Sign a PQC certificate using ML-DSA.
        
        Args:
            certificate: Certificate to sign
            
        Returns:
            Certificate with signature, public_key, and payload_hash filled
        """
        logger.info(f"Signing certificate for {certificate.subject}", extra={
            "layer": 4,
            "data": {"level": certificate.level.value}
        })
        
        # Create canonical payload
        canonical_payload = self._create_canonical_payload(certificate)
        
        # Hash payload
        payload_hash = self._hash_payload(canonical_payload)
        certificate.payload_hash = base64.b64encode(payload_hash).decode('ascii')
        
        # Set public key
        certificate.public_key = self.get_public_key()
        
        if self._oqs_available and self._sig_instance:
            try:
                # Sign the hash
                signature = self._sig_instance.sign(payload_hash)
                certificate.signature = base64.b64encode(signature).decode('ascii')
                
                logger.info(f"Certificate signed successfully", extra={
                    "layer": 4,
                    "data": {
                        "signature_size": len(signature),
                        "hash": certificate.payload_hash[:16] + "...",
                    }
                })
                
            except Exception as e:
                logger.error(f"Signing failed: {e}", extra={"layer": 4})
                certificate.signature = None
        else:
            # Fallback: create placeholder signature for testing
            certificate.signature = self._create_placeholder_signature(payload_hash)
            logger.warning("Using placeholder signature (oqs not available)", extra={
                "layer": 4
            })
        
        return certificate
    
    def _create_placeholder_signature(self, payload_hash: bytes) -> str:
        """Create a placeholder signature when oqs is not available"""
        # Use SHA3-256 of hash as placeholder (NOT cryptographically secure)
        placeholder = hashlib.sha3_256(
            b"PLACEHOLDER:" + payload_hash
        ).digest()
        return base64.b64encode(placeholder).decode('ascii')
    
    @timed(logger=logger, layer=4)
    def verify(
        self,
        message: bytes,
        signature: bytes,
        public_key: bytes,
    ) -> bool:
        """
        Verify a signature using ML-DSA.
        
        Args:
            message: Original message (hash)
            signature: Signature bytes
            public_key: Public key bytes
            
        Returns:
            True if signature is valid
        """
        if not self._oqs_available:
            logger.warning("Verification skipped (oqs not available)", extra={
                "layer": 4
            })
            return False
        
        try:
            import oqs
            
            oqs_name = self.algorithm.replace("-", "")
            verifier = oqs.Signature(oqs_name)
            
            is_valid = verifier.verify(message, signature, public_key)
            
            logger.info(f"Signature verification: {'VALID' if is_valid else 'INVALID'}", extra={
                "layer": 4
            })
            
            return is_valid
            
        except Exception as e:
            logger.error(f"Verification failed: {e}", extra={"layer": 4})
            return False


# ============================================================================
# Certification Engine (Main Interface)
# ============================================================================

class CertificationEngine:
    """
    Main interface for Layer 4 certification.
    
    Combines PolicyEvaluator and LabelSigner to issue PQC certificates.
    """
    
    def __init__(self, signing_algorithm: str = None):
        self.policy_evaluator = PolicyEvaluator()
        self.label_signer = LabelSigner(algorithm=signing_algorithm)
        logger.info("CertificationEngine initialized", extra={"layer": 4})
    
    @timed(logger=logger, layer=4)
    def issue_certificate(
        self,
        subject: str,
        algorithms: List[str],
        validity_days: int = 365,
    ) -> PQCCertificate:
        """
        Evaluate policy and issue a signed PQC certificate.
        
        Args:
            subject: Asset FQDN or identifier
            algorithms: List of algorithms used by the asset
            validity_days: Certificate validity period
            
        Returns:
            Signed PQCCertificate
        """
        logger.info(f"Issuing certificate for {subject}", extra={
            "layer": 4,
            "target": subject,
            "data": {"algorithm_count": len(algorithms)}
        })
        
        # Evaluate policy
        policy_result = self.policy_evaluator.evaluate(algorithms)
        
        # Create certificate
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=validity_days)
        
        certificate = PQCCertificate(
            certificate_id=str(uuid.uuid4()),
            subject=subject,
            level=policy_result.level,
            score=policy_result.score,
            issued_at=now.isoformat(),
            expires_at=expires.isoformat(),
            algorithm=self.label_signer.algorithm,
            policy_result=policy_result,
        )
        
        # Sign certificate
        signed_certificate = self.label_signer.sign(certificate)
        
        logger.info(f"Certificate issued: {signed_certificate.level.value}", extra={
            "layer": 4,
            "target": subject,
            "data": {
                "certificate_id": signed_certificate.certificate_id,
                "level": signed_certificate.level.value,
                "score": signed_certificate.score,
            }
        })
        
        return signed_certificate
    
    def verify_certificate(self, certificate: PQCCertificate) -> bool:
        """
        Verify a certificate's signature.
        
        Args:
            certificate: Certificate to verify
            
        Returns:
            True if signature is valid
        """
        if not certificate.signature or not certificate.public_key:
            logger.warning("Certificate missing signature or public key", extra={
                "layer": 4
            })
            return False
        
        try:
            # Decode components
            signature = base64.b64decode(certificate.signature)
            public_key = base64.b64decode(certificate.public_key)
            payload_hash = base64.b64decode(certificate.payload_hash)
            
            return self.label_signer.verify(payload_hash, signature, public_key)
            
        except Exception as e:
            logger.error(f"Certificate verification failed: {e}", extra={
                "layer": 4
            })
            return False


# ============================================================================
# Convenience Functions
# ============================================================================

def evaluate_policy(algorithms: List[str]) -> PolicyResult:
    """Quick function to evaluate policy for algorithms"""
    evaluator = PolicyEvaluator()
    return evaluator.evaluate(algorithms)


def issue_certificate(subject: str, algorithms: List[str]) -> PQCCertificate:
    """Quick function to issue a certificate"""
    engine = CertificationEngine()
    return engine.issue_certificate(subject, algorithms)


def get_certification_level(algorithms: List[str]) -> CertificationLevel:
    """Quick function to get certification level"""
    result = evaluate_policy(algorithms)
    return result.level
