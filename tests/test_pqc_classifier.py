"""
Tests for PQC Algorithm Classifier (Layer 3)

Tests classification of algorithms against NIST FIPS 203/204/205 standards.
"""

import pytest
import sys
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from qushield.core.classifier import (
    PQCClassifier,
    QuantumSafety,
    AlgorithmInfo,
    classify_algorithm,
    is_quantum_safe,
)


class TestPQCClassifier:
    """Test suite for PQC Algorithm Classifier"""
    
    @pytest.fixture
    def classifier(self):
        return PQCClassifier()
    
    # ================================================================
    # NIST FIPS 203 - ML-KEM Tests
    # ================================================================
    
    def test_ml_kem_512_is_fully_safe(self, classifier):
        """ML-KEM-512 should be fully quantum safe"""
        info = classifier.classify("ML-KEM-512")
        assert info.safety == QuantumSafety.FULLY_SAFE
        assert info.nist_fips == "FIPS-203"
        assert info.primitive == "kem"
        assert info.vuln_score == 0.0
    
    def test_ml_kem_768_is_fully_safe(self, classifier):
        """ML-KEM-768 should be fully quantum safe"""
        info = classifier.classify("ML-KEM-768")
        assert info.safety == QuantumSafety.FULLY_SAFE
        assert info.nist_fips == "FIPS-203"
        assert info.vuln_score == 0.0
    
    def test_ml_kem_1024_is_fully_safe(self, classifier):
        """ML-KEM-1024 should be fully quantum safe"""
        info = classifier.classify("ML-KEM-1024")
        assert info.safety == QuantumSafety.FULLY_SAFE
        assert info.nist_fips == "FIPS-203"
        assert info.vuln_score == 0.0
    
    # ================================================================
    # NIST FIPS 204 - ML-DSA Tests
    # ================================================================
    
    def test_ml_dsa_44_is_fully_safe(self, classifier):
        """ML-DSA-44 should be fully quantum safe"""
        info = classifier.classify("ML-DSA-44")
        assert info.safety == QuantumSafety.FULLY_SAFE
        assert info.nist_fips == "FIPS-204"
        assert info.primitive == "sig"
    
    def test_ml_dsa_65_is_fully_safe(self, classifier):
        """ML-DSA-65 should be fully quantum safe"""
        info = classifier.classify("ML-DSA-65")
        assert info.safety == QuantumSafety.FULLY_SAFE
        assert info.nist_fips == "FIPS-204"
    
    def test_ml_dsa_87_is_fully_safe(self, classifier):
        """ML-DSA-87 should be fully quantum safe"""
        info = classifier.classify("ML-DSA-87")
        assert info.safety == QuantumSafety.FULLY_SAFE
        assert info.nist_fips == "FIPS-204"
    
    # ================================================================
    # NIST FIPS 205 - SLH-DSA Tests
    # ================================================================
    
    def test_slh_dsa_128s_is_fully_safe(self, classifier):
        """SLH-DSA-128s should be fully quantum safe"""
        info = classifier.classify("SLH-DSA-128s")
        assert info.safety == QuantumSafety.FULLY_SAFE
        assert info.nist_fips == "FIPS-205"
    
    # ================================================================
    # Hybrid Algorithm Tests
    # ================================================================
    
    def test_x25519_mlkem768_is_hybrid(self, classifier):
        """X25519+ML-KEM-768 hybrid should be PQC Ready"""
        info = classifier.classify("X25519MLKEM768")
        assert info.safety == QuantumSafety.HYBRID
        assert info.vuln_score < 0.5
    
    # ================================================================
    # Vulnerable Algorithm Tests
    # ================================================================
    
    def test_rsa_is_vulnerable(self, classifier):
        """RSA should be quantum vulnerable"""
        info = classifier.classify("RSA")
        assert info.safety == QuantumSafety.VULNERABLE
        assert info.vuln_score == 1.0
        assert info.migrate_to is not None
    
    def test_rsa_2048_is_vulnerable(self, classifier):
        """RSA-2048 should be quantum vulnerable"""
        info = classifier.classify("RSA-2048")
        assert info.safety == QuantumSafety.VULNERABLE
        assert info.migrate_to == "ML-DSA-65"
    
    def test_ecdsa_is_vulnerable(self, classifier):
        """ECDSA should be quantum vulnerable"""
        info = classifier.classify("ECDSA")
        assert info.safety == QuantumSafety.VULNERABLE
        assert info.vuln_score == 1.0
    
    def test_ecdhe_is_vulnerable(self, classifier):
        """ECDHE should be quantum vulnerable"""
        info = classifier.classify("ECDHE")
        assert info.safety == QuantumSafety.VULNERABLE
    
    def test_x25519_is_vulnerable(self, classifier):
        """X25519 (standalone) should be quantum vulnerable"""
        info = classifier.classify("X25519")
        assert info.safety == QuantumSafety.VULNERABLE
        assert info.migrate_to == "ML-KEM-768"
    
    # ================================================================
    # Critical Legacy Tests
    # ================================================================
    
    def test_rc4_is_critical(self, classifier):
        """RC4 should be critical (broken classically)"""
        info = classifier.classify("RC4")
        assert info.safety == QuantumSafety.CRITICAL
        assert info.vuln_score == 1.0
    
    def test_des_is_critical(self, classifier):
        """DES should be critical"""
        info = classifier.classify("DES")
        assert info.safety == QuantumSafety.CRITICAL
    
    def test_md5_is_critical(self, classifier):
        """MD5 should be critical"""
        info = classifier.classify("MD5")
        assert info.safety == QuantumSafety.CRITICAL
    
    def test_sha1_is_critical(self, classifier):
        """SHA1 should be critical"""
        info = classifier.classify("SHA1")
        assert info.safety == QuantumSafety.CRITICAL
    
    # ================================================================
    # Symmetric Algorithm Tests
    # ================================================================
    
    def test_aes_256_is_safe(self, classifier):
        """AES-256 should be fully safe (128-bit post-quantum)"""
        info = classifier.classify("AES-256")
        assert info.safety == QuantumSafety.FULLY_SAFE
        assert info.vuln_score == 0.0
    
    def test_aes_128_is_vulnerable(self, classifier):
        """AES-128 should be vulnerable (64-bit post-quantum)"""
        info = classifier.classify("AES-128")
        assert info.safety == QuantumSafety.VULNERABLE
        assert info.vuln_score > 0
        assert info.migrate_to == "AES-256"
    
    # ================================================================
    # Utility Method Tests
    # ================================================================
    
    def test_get_worst_safety(self, classifier):
        """get_worst_safety should return worst safety level"""
        algorithms = ["AES-256", "RSA-2048", "ML-KEM-768"]
        worst = classifier.get_worst_safety(algorithms)
        assert worst == QuantumSafety.VULNERABLE  # RSA is worst
    
    def test_get_worst_safety_with_critical(self, classifier):
        """get_worst_safety with critical should return critical"""
        algorithms = ["RSA-2048", "RC4", "ML-KEM-768"]
        worst = classifier.get_worst_safety(algorithms)
        assert worst == QuantumSafety.CRITICAL
    
    def test_get_max_vuln_score(self, classifier):
        """get_max_vuln_score should return maximum score"""
        algorithms = ["AES-256", "RSA-2048"]
        max_score = classifier.get_max_vuln_score(algorithms)
        assert max_score == 1.0  # RSA has 1.0
    
    def test_is_quantum_safe_true(self, classifier):
        """is_quantum_safe should return True for safe algorithms"""
        assert classifier.is_quantum_safe("ML-KEM-768") == True
        assert classifier.is_quantum_safe("AES-256") == True
    
    def test_is_quantum_safe_false(self, classifier):
        """is_quantum_safe should return False for unsafe algorithms"""
        assert classifier.is_quantum_safe("RSA-2048") == False
        assert classifier.is_quantum_safe("ECDHE") == False
    
    # ================================================================
    # Convenience Function Tests
    # ================================================================
    
    def test_classify_algorithm_function(self):
        """classify_algorithm convenience function should work"""
        info = classify_algorithm("RSA-2048")
        assert info.safety == QuantumSafety.VULNERABLE
    
    def test_is_quantum_safe_function(self):
        """is_quantum_safe convenience function should work"""
        assert is_quantum_safe("ML-KEM-768") == True
        assert is_quantum_safe("RSA") == False
    
    # ================================================================
    # Edge Case Tests
    # ================================================================
    
    def test_unknown_algorithm_fallback(self, classifier):
        """Unknown algorithms should default to vulnerable"""
        info = classifier.classify("UNKNOWN_ALGO_XYZ")
        assert info.safety == QuantumSafety.VULNERABLE
        assert info.vuln_score == 0.5
    
    def test_case_insensitive(self, classifier):
        """Classification should be case-insensitive"""
        info1 = classifier.classify("rsa-2048")
        info2 = classifier.classify("RSA-2048")
        assert info1.safety == info2.safety
    
    def test_normalize_separators(self, classifier):
        """Classification should handle various separators"""
        info1 = classifier.classify("ML-KEM-768")
        info2 = classifier.classify("ML_KEM_768")
        info3 = classifier.classify("MLKEM768")
        assert info1.safety == QuantumSafety.FULLY_SAFE
        # All should match ML-KEM


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
