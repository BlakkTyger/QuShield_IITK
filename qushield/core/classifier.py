"""
PQC Algorithm Classifier

Classifies cryptographic algorithms based on quantum safety levels
according to NIST FIPS 203/204/205 standards.

References:
- NIST FIPS 203: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
- NIST FIPS 204: ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
- NIST FIPS 205: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
- IETF draft-ietf-pquip-pqc-engineers: PQC migration guidance
"""

from enum import Enum
from dataclasses import dataclass
from typing import Optional, List, Dict
import re

from qushield.utils.logging import get_logger, timed

logger = get_logger("pqc_classifier")


class QuantumSafety(str, Enum):
    """Quantum safety classification levels"""
    FULLY_SAFE = "FULLY_QUANTUM_SAFE"       # NIST PQC standardized
    HYBRID = "PQC_READY"                     # Hybrid classical + PQC
    VULNERABLE = "QUANTUM_VULNERABLE"        # Broken by Shor's algorithm
    CRITICAL = "CRITICAL_LEGACY"             # Broken even classically


@dataclass
class AlgorithmInfo:
    """Information about a cryptographic algorithm"""
    name: str
    safety: QuantumSafety
    nist_fips: Optional[str]      # FIPS standard reference
    primitive: str                 # 'kem', 'sig', 'cipher', 'hash'
    key_size_bits: Optional[int]
    migrate_to: Optional[str]      # Recommended migration target
    vuln_score: float              # 0.0 (safe) to 1.0 (critical)
    notes: str = ""


# ============================================================================
# NIST Standardized Post-Quantum Algorithms (FULLY SAFE)
# ============================================================================

PQC_ALGORITHMS: Dict[str, AlgorithmInfo] = {
    # FIPS 203 - ML-KEM (Key Encapsulation Mechanism)
    "ML-KEM-512": AlgorithmInfo(
        "ML-KEM-512", QuantumSafety.FULLY_SAFE, "FIPS-203", "kem",
        key_size_bits=1632, migrate_to=None, vuln_score=0.0,
        notes="128-bit security, smallest parameter set"
    ),
    "ML-KEM-768": AlgorithmInfo(
        "ML-KEM-768", QuantumSafety.FULLY_SAFE, "FIPS-203", "kem",
        key_size_bits=2400, migrate_to=None, vuln_score=0.0,
        notes="192-bit security, recommended for general use"
    ),
    "ML-KEM-1024": AlgorithmInfo(
        "ML-KEM-1024", QuantumSafety.FULLY_SAFE, "FIPS-203", "kem",
        key_size_bits=3168, migrate_to=None, vuln_score=0.0,
        notes="256-bit security, highest security level"
    ),
    
    # FIPS 204 - ML-DSA (Digital Signatures)
    "ML-DSA-44": AlgorithmInfo(
        "ML-DSA-44", QuantumSafety.FULLY_SAFE, "FIPS-204", "sig",
        key_size_bits=1312, migrate_to=None, vuln_score=0.0,
        notes="Category 2 security"
    ),
    "ML-DSA-65": AlgorithmInfo(
        "ML-DSA-65", QuantumSafety.FULLY_SAFE, "FIPS-204", "sig",
        key_size_bits=1952, migrate_to=None, vuln_score=0.0,
        notes="Category 3 security, recommended"
    ),
    "ML-DSA-87": AlgorithmInfo(
        "ML-DSA-87", QuantumSafety.FULLY_SAFE, "FIPS-204", "sig",
        key_size_bits=2592, migrate_to=None, vuln_score=0.0,
        notes="Category 5 security, highest level"
    ),
    
    # FIPS 205 - SLH-DSA (Hash-based Signatures)
    "SLH-DSA-128s": AlgorithmInfo(
        "SLH-DSA-128s", QuantumSafety.FULLY_SAFE, "FIPS-205", "sig",
        key_size_bits=64, migrate_to=None, vuln_score=0.0,
        notes="Small signatures, slower signing"
    ),
    "SLH-DSA-128f": AlgorithmInfo(
        "SLH-DSA-128f", QuantumSafety.FULLY_SAFE, "FIPS-205", "sig",
        key_size_bits=64, migrate_to=None, vuln_score=0.0,
        notes="Fast signing, larger signatures"
    ),
    "SLH-DSA-192s": AlgorithmInfo(
        "SLH-DSA-192s", QuantumSafety.FULLY_SAFE, "FIPS-205", "sig",
        key_size_bits=96, migrate_to=None, vuln_score=0.0
    ),
    "SLH-DSA-192f": AlgorithmInfo(
        "SLH-DSA-192f", QuantumSafety.FULLY_SAFE, "FIPS-205", "sig",
        key_size_bits=96, migrate_to=None, vuln_score=0.0
    ),
    "SLH-DSA-256s": AlgorithmInfo(
        "SLH-DSA-256s", QuantumSafety.FULLY_SAFE, "FIPS-205", "sig",
        key_size_bits=128, migrate_to=None, vuln_score=0.0
    ),
    "SLH-DSA-256f": AlgorithmInfo(
        "SLH-DSA-256f", QuantumSafety.FULLY_SAFE, "FIPS-205", "sig",
        key_size_bits=128, migrate_to=None, vuln_score=0.0
    ),
}

# ============================================================================
# Hybrid Algorithms (Transitional - PQC Ready)
# ============================================================================

HYBRID_ALGORITHMS: Dict[str, AlgorithmInfo] = {
    "X25519MLKEM768": AlgorithmInfo(
        "X25519+ML-KEM-768", QuantumSafety.HYBRID, None, "kem",
        key_size_bits=None, migrate_to="ML-KEM-768", vuln_score=0.1,
        notes="Chrome/Firefox hybrid, draft-ietf-tls-hybrid-design"
    ),
    "SecP256r1MLKEM768": AlgorithmInfo(
        "P-256+ML-KEM-768", QuantumSafety.HYBRID, None, "kem",
        key_size_bits=None, migrate_to="ML-KEM-768", vuln_score=0.1
    ),
    "X25519Kyber768Draft00": AlgorithmInfo(
        "X25519+Kyber768", QuantumSafety.HYBRID, None, "kem",
        key_size_bits=None, migrate_to="ML-KEM-768", vuln_score=0.15,
        notes="Pre-standardization hybrid"
    ),
    "ECDSA+ML-DSA": AlgorithmInfo(
        "ECDSA+ML-DSA", QuantumSafety.HYBRID, None, "sig",
        key_size_bits=None, migrate_to="ML-DSA-65", vuln_score=0.1
    ),
}

# ============================================================================
# Quantum-Vulnerable Algorithms (Broken by Shor's Algorithm)
# ============================================================================

VULNERABLE_ALGORITHMS: Dict[str, AlgorithmInfo] = {
    # RSA - broken by Shor's algorithm
    "RSA": AlgorithmInfo(
        "RSA", QuantumSafety.VULNERABLE, None, "sig",
        key_size_bits=None, migrate_to="ML-DSA", vuln_score=1.0,
        notes="Vulnerable to Shor's algorithm, all key sizes"
    ),
    "RSA-2048": AlgorithmInfo(
        "RSA-2048", QuantumSafety.VULNERABLE, None, "sig",
        key_size_bits=2048, migrate_to="ML-DSA-65", vuln_score=1.0
    ),
    "RSA-4096": AlgorithmInfo(
        "RSA-4096", QuantumSafety.VULNERABLE, None, "sig",
        key_size_bits=4096, migrate_to="ML-DSA-87", vuln_score=1.0
    ),
    
    # Elliptic Curve - broken by Shor's algorithm
    "ECDSA": AlgorithmInfo(
        "ECDSA", QuantumSafety.VULNERABLE, None, "sig",
        key_size_bits=None, migrate_to="ML-DSA", vuln_score=1.0,
        notes="All curves vulnerable to Shor's"
    ),
    "ECDH": AlgorithmInfo(
        "ECDH", QuantumSafety.VULNERABLE, None, "kem",
        key_size_bits=None, migrate_to="ML-KEM", vuln_score=1.0
    ),
    "ECDHE": AlgorithmInfo(
        "ECDHE", QuantumSafety.VULNERABLE, None, "kem",
        key_size_bits=None, migrate_to="ML-KEM", vuln_score=1.0
    ),
    "X25519": AlgorithmInfo(
        "X25519", QuantumSafety.VULNERABLE, None, "kem",
        key_size_bits=256, migrate_to="ML-KEM-768", vuln_score=0.95,
        notes="Faster than NIST curves, still quantum vulnerable"
    ),
    "Ed25519": AlgorithmInfo(
        "Ed25519", QuantumSafety.VULNERABLE, None, "sig",
        key_size_bits=256, migrate_to="ML-DSA-65", vuln_score=0.95
    ),
    
    # Diffie-Hellman
    "DH": AlgorithmInfo(
        "DH", QuantumSafety.VULNERABLE, None, "kem",
        key_size_bits=None, migrate_to="ML-KEM", vuln_score=1.0
    ),
    "DHE": AlgorithmInfo(
        "DHE", QuantumSafety.VULNERABLE, None, "kem",
        key_size_bits=None, migrate_to="ML-KEM", vuln_score=1.0
    ),
    "DSA": AlgorithmInfo(
        "DSA", QuantumSafety.VULNERABLE, None, "sig",
        key_size_bits=None, migrate_to="ML-DSA", vuln_score=1.0
    ),
}

# ============================================================================
# Critical Legacy (Broken Even Classically)
# ============================================================================

CRITICAL_LEGACY: Dict[str, AlgorithmInfo] = {
    "RC4": AlgorithmInfo(
        "RC4", QuantumSafety.CRITICAL, None, "cipher",
        key_size_bits=None, migrate_to="AES-256-GCM", vuln_score=1.0,
        notes="Broken, must not use"
    ),
    "DES": AlgorithmInfo(
        "DES", QuantumSafety.CRITICAL, None, "cipher",
        key_size_bits=56, migrate_to="AES-256", vuln_score=1.0
    ),
    "3DES": AlgorithmInfo(
        "3DES", QuantumSafety.CRITICAL, None, "cipher",
        key_size_bits=168, migrate_to="AES-256", vuln_score=0.9
    ),
    "MD5": AlgorithmInfo(
        "MD5", QuantumSafety.CRITICAL, None, "hash",
        key_size_bits=128, migrate_to="SHA-384", vuln_score=1.0
    ),
    "SHA1": AlgorithmInfo(
        "SHA1", QuantumSafety.CRITICAL, None, "hash",
        key_size_bits=160, migrate_to="SHA-256", vuln_score=0.8
    ),
    "NULL": AlgorithmInfo(
        "NULL", QuantumSafety.CRITICAL, None, "cipher",
        key_size_bits=0, migrate_to="AES-256-GCM", vuln_score=1.0
    ),
    "EXPORT": AlgorithmInfo(
        "EXPORT", QuantumSafety.CRITICAL, None, "cipher",
        key_size_bits=40, migrate_to="AES-256-GCM", vuln_score=1.0
    ),
}

# ============================================================================
# Symmetric Algorithms (Quantum considerations via Grover's)
# ============================================================================

SYMMETRIC_ALGORITHMS: Dict[str, AlgorithmInfo] = {
    "AES-128": AlgorithmInfo(
        "AES-128", QuantumSafety.VULNERABLE, None, "cipher",
        key_size_bits=128, migrate_to="AES-256", vuln_score=0.3,
        notes="Grover's reduces to 64-bit security"
    ),
    "AES-192": AlgorithmInfo(
        "AES-192", QuantumSafety.FULLY_SAFE, None, "cipher",
        key_size_bits=192, migrate_to=None, vuln_score=0.1,
        notes="96-bit post-quantum security"
    ),
    "AES-256": AlgorithmInfo(
        "AES-256", QuantumSafety.FULLY_SAFE, None, "cipher",
        key_size_bits=256, migrate_to=None, vuln_score=0.0,
        notes="128-bit post-quantum security"
    ),
    "CHACHA20": AlgorithmInfo(
        "ChaCha20", QuantumSafety.FULLY_SAFE, None, "cipher",
        key_size_bits=256, migrate_to=None, vuln_score=0.0
    ),
}


class PQCClassifier:
    """Classifier for determining quantum safety of cryptographic algorithms"""
    
    # Fuzzy match patterns for cipher suite names
    FUZZY_PATTERNS = [
        # PQC patterns
        (r"ML[-_]?KEM[-_]?1024|KYBER[-_]?1024", "ML-KEM-1024"),
        (r"ML[-_]?KEM[-_]?768|KYBER[-_]?768", "ML-KEM-768"),
        (r"ML[-_]?KEM[-_]?512|KYBER[-_]?512", "ML-KEM-512"),
        (r"ML[-_]?DSA[-_]?87|DILITHIUM[-_]?5", "ML-DSA-87"),
        (r"ML[-_]?DSA[-_]?65|DILITHIUM[-_]?3", "ML-DSA-65"),
        (r"ML[-_]?DSA[-_]?44|DILITHIUM[-_]?2", "ML-DSA-44"),
        (r"SLH[-_]?DSA|SPHINCS", "SLH-DSA-128s"),
        # Hybrid patterns
        (r"X25519[-_]?ML[-_]?KEM|X25519KYBER|X25519MLKEM", "X25519MLKEM768"),
        (r"ECDH.*ML[-_]?KEM|P256.*KYBER", "SecP256r1MLKEM768"),
        # Vulnerable key exchange
        (r"ECDHE[-_]?P[-_]?384|ECDHE[-_]?SECP384", "ECDHE"),
        (r"ECDHE[-_]?P[-_]?256|ECDHE[-_]?SECP256|ECDHE[-_]?PRIME256", "ECDHE"),
        (r"X25519", "X25519"),
        (r"ECDHE|ECDH", "ECDHE"),
        (r"DHE[-_]?\d+|DHE[-_]?RSA", "DHE"),
        # RSA patterns
        (r"RSA[-_]?PSS", "RSA"),
        (r"RSA[-_]?OAEP", "RSA"),
        (r"RSA[-_]?4096", "RSA-4096"),
        (r"RSA[-_]?2048", "RSA-2048"),
        (r"RSA[-_]?1024", "RSA"),
        (r"RSA", "RSA"),
        # ECDSA patterns
        (r"ECDSA[-_]?P[-_]?384|ECDSA[-_]?SECP384", "ECDSA"),
        (r"ECDSA[-_]?P[-_]?256|ECDSA[-_]?SECP256", "ECDSA"),
        (r"ECDSA", "ECDSA"),
        (r"ED25519|EDDSA", "Ed25519"),
        # Symmetric
        (r"AES[-_]?256[-_]?GCM|AES256GCM", "AES-256"),
        (r"AES[-_]?128[-_]?GCM|AES128GCM", "AES-128"),
        (r"AES[-_]?256", "AES-256"),
        (r"AES[-_]?128", "AES-128"),
        (r"CHACHA20[-_]?POLY1305|CHACHA20", "CHACHA20"),
        # Critical legacy
        (r"RC4", "RC4"),
        (r"3DES|TRIPLE[-_]?DES|DES[-_]?EDE", "3DES"),
        (r"DES(?![-_]?EDE)", "DES"),
        (r"MD5", "MD5"),
        (r"SHA[-_]?1(?![\d])", "SHA1"),
        (r"NULL|ANON|EXPORT", "NULL"),
    ]
    
    def __init__(self):
        # Combine all algorithm dictionaries into registry
        self._algorithm_registry = {
            **PQC_ALGORITHMS,
            **HYBRID_ALGORITHMS,
            **VULNERABLE_ALGORITHMS,
            **CRITICAL_LEGACY,
            **SYMMETRIC_ALGORITHMS,
        }
        # Compile regex patterns for performance
        self._compiled_patterns = [
            (re.compile(pattern, re.IGNORECASE), algo_key)
            for pattern, algo_key in self.FUZZY_PATTERNS
        ]
        
        logger.debug(f"PQCClassifier initialized with {len(self._algorithm_registry)} algorithms")
    
    @timed(logger=logger, layer=3)
    def classify(self, algorithm: str) -> AlgorithmInfo:
        """
        Classify an algorithm's quantum safety level.
        
        Args:
            algorithm: Algorithm name (e.g., "RSA", "ECDHE-P256", "ML-KEM-768")
            
        Returns:
            AlgorithmInfo with safety classification
        """
        if not algorithm:
            return self._unknown_algorithm("")
        
        # Normalize: uppercase, remove common separators
        algo_norm = algorithm.upper().replace("-", "").replace("_", "").replace(" ", "")
        
        # Direct match first
        for key, info in self._algorithm_registry.items():
            key_norm = key.upper().replace("-", "").replace("_", "")
            if key_norm == algo_norm:
                logger.debug(f"Direct match: {algorithm} -> {key}", extra={"layer": 3})
                return info
        
        # Partial match (e.g., "ECDHE-P256" contains "ECDHE")
        for key, info in self._algorithm_registry.items():
            key_norm = key.upper().replace("-", "").replace("_", "")
            if key_norm in algo_norm or algo_norm in key_norm:
                logger.debug(f"Partial match: {algorithm} -> {key}", extra={"layer": 3})
                return info
        
        # Fuzzy match using compiled regex patterns
        for pattern, algo_key in self._compiled_patterns:
            if pattern.search(algorithm):
                if algo_key in self._algorithm_registry:
                    logger.debug(f"Fuzzy match: {algorithm} -> {algo_key}", extra={"layer": 3})
                    return self._algorithm_registry[algo_key]
        
        # Unknown - assume vulnerable
        logger.warning(f"Unknown algorithm: {algorithm}, assuming vulnerable", extra={"layer": 3})
        return self._unknown_algorithm(algorithm)
    
    def _unknown_algorithm(self, algorithm: str) -> AlgorithmInfo:
        """Return info for unknown algorithm"""
        return AlgorithmInfo(
            algorithm or "Unknown", QuantumSafety.VULNERABLE, None, "unknown",
            key_size_bits=None, migrate_to="ML-KEM/ML-DSA", vuln_score=0.5,
            notes="Unknown algorithm, assumed vulnerable"
        )
    
    def classify_multiple(self, algorithms: List[str]) -> List[AlgorithmInfo]:
        """Classify multiple algorithms"""
        return [self.classify(algo) for algo in algorithms]
    
    def get_effective_safety(self, algorithms: List[str]) -> QuantumSafety:
        """
        Get the effective quantum safety level from a list of supported algorithms.
        
        If a server supports a PQC or Hybrid algorithm but retains classical algorithms
        for backward compatibility, it should be categorized as HYBRID (transitional), 
        not strictly VULNERABLE, as this is the standard industry migration path.
        """
        if not algorithms:
            return QuantumSafety.VULNERABLE
            
        safeties = [self.classify(algo).safety for algo in algorithms]
        
        if QuantumSafety.CRITICAL in safeties:
            return QuantumSafety.CRITICAL
            
        has_pqc = QuantumSafety.FULLY_SAFE in safeties or QuantumSafety.HYBRID in safeties
        has_vulnerable = QuantumSafety.VULNERABLE in safeties
        
        if has_pqc and has_vulnerable:
            return QuantumSafety.HYBRID  # Transitional deployment
        elif has_pqc:
            # If it has EXACTLY fully safe algorithms, it's Fully Safe. 
            # If it relies exclusively on hybrid KEMs/Sigs, it remains Hybrid.
            return QuantumSafety.FULLY_SAFE if QuantumSafety.FULLY_SAFE in safeties and QuantumSafety.HYBRID not in safeties else QuantumSafety.HYBRID
            
        return QuantumSafety.VULNERABLE
    
    def get_max_vuln_score(self, algorithms: List[str]) -> float:
        """Get the maximum vulnerability score from a list of algorithms"""
        if not algorithms:
            return 0.0
        scores = [self.classify(algo).vuln_score for algo in algorithms]
        return max(scores)
    
    def get_remediation(self, algorithm: str) -> Optional[str]:
        """Get the recommended migration target for an algorithm"""
        info = self.classify(algorithm)
        return info.migrate_to
    
    def is_quantum_safe(self, algorithm: str) -> bool:
        """Check if an algorithm is fully quantum safe"""
        info = self.classify(algorithm)
        return info.safety == QuantumSafety.FULLY_SAFE


# Singleton instance
classifier = PQCClassifier()


def classify_algorithm(algorithm: str) -> AlgorithmInfo:
    """Convenience function to classify an algorithm"""
    return classifier.classify(algorithm)


def is_quantum_safe(algorithm: str) -> bool:
    """Convenience function to check quantum safety"""
    return classifier.is_quantum_safe(algorithm)
