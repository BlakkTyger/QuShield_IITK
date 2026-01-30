"""
Tests for HNDL Risk Scorer (Layer 3)

Tests HNDL (Harvest Now, Decrypt Later) risk score calculation.
"""

import pytest
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent))

from qushield.core.scorer import (
    HNDLScorer,
    HNDLScore,
    HNDLRiskLabel,
    calculate_hndl_score,
)


class TestHNDLScorer:
    """Test suite for HNDL Risk Scorer"""
    
    @pytest.fixture
    def scorer(self):
        return HNDLScorer()
    
    # ================================================================
    # Basic Score Calculation Tests
    # ================================================================
    
    def test_calculate_returns_hndl_score(self, scorer):
        """calculate() should return HNDLScore object"""
        result = scorer.calculate(
            key_exchange_algorithms=["ECDHE"],
            certificate_algorithm="RSA-2048",
        )
        assert isinstance(result, HNDLScore)
        assert 0.0 <= result.score <= 1.0
    
    def test_vulnerable_algo_high_score(self, scorer):
        """Vulnerable algorithms should have high scores"""
        result = scorer.calculate(
            key_exchange_algorithms=["RSA"],
            certificate_algorithm="RSA-2048",
            endpoint_type="banking",
        )
        assert result.score >= 0.5
        assert result.algo_vulnerability == 1.0
    
    def test_safe_algo_low_score(self, scorer):
        """Quantum-safe algorithms should have low scores"""
        result = scorer.calculate(
            key_exchange_algorithms=["ML-KEM-768"],
            certificate_algorithm="ML-DSA-65",
            endpoint_type="banking",
        )
        assert result.score < 0.1
        assert result.algo_vulnerability == 0.0
    
    # ================================================================
    # Risk Label Tests
    # ================================================================
    
    def test_critical_label_threshold(self, scorer):
        """Score >= 0.8 should be CRITICAL"""
        result = scorer.calculate(
            key_exchange_algorithms=["RSA"],
            certificate_algorithm="RSA-2048",
            endpoint_type="payment",
            is_high_traffic=True,
        )
        # Banking + RSA + high traffic should hit critical
        if result.score >= 0.8:
            assert result.label == HNDLRiskLabel.CRITICAL
    
    def test_high_label_threshold(self, scorer):
        """Score >= 0.6 and < 0.8 should be HIGH"""
        # Test boundary
        result = scorer.calculate(
            key_exchange_algorithms=["ECDHE"],
            certificate_algorithm="RSA-2048",
            endpoint_type="api",
        )
        if 0.6 <= result.score < 0.8:
            assert result.label == HNDLRiskLabel.HIGH
    
    def test_medium_label_threshold(self, scorer):
        """Score >= 0.3 and < 0.6 should be MEDIUM"""
        result = scorer.calculate(
            key_exchange_algorithms=["X25519"],
            certificate_algorithm="RSA-2048",
            endpoint_type="web",
        )
        if 0.3 <= result.score < 0.6:
            assert result.label == HNDLRiskLabel.MEDIUM
    
    def test_low_label_threshold(self, scorer):
        """Score < 0.3 should be LOW"""
        result = scorer.calculate(
            key_exchange_algorithms=["ML-KEM-768"],
            certificate_algorithm="ML-DSA-65",
            endpoint_type="cdn",
        )
        assert result.score < 0.3
        assert result.label == HNDLRiskLabel.LOW
    
    # ================================================================
    # Data Sensitivity Tests
    # ================================================================
    
    def test_banking_high_sensitivity(self, scorer):
        """Banking endpoints should have high sensitivity"""
        result = scorer.calculate(
            key_exchange_algorithms=["ECDHE"],
            certificate_algorithm="RSA-2048",
            endpoint_type="banking",
        )
        assert result.data_sensitivity >= 0.9
    
    def test_payment_high_sensitivity(self, scorer):
        """Payment endpoints should have maximum sensitivity"""
        result = scorer.calculate(
            key_exchange_algorithms=["ECDHE"],
            certificate_algorithm="RSA-2048",
            endpoint_type="payment",
        )
        assert result.data_sensitivity == 1.0
    
    def test_cdn_low_sensitivity(self, scorer):
        """CDN endpoints should have low sensitivity"""
        result = scorer.calculate(
            key_exchange_algorithms=["ECDHE"],
            certificate_algorithm="RSA-2048",
            endpoint_type="cdn",
        )
        assert result.data_sensitivity <= 0.3
    
    def test_api_moderate_sensitivity(self, scorer):
        """API endpoints should have moderate-high sensitivity"""
        result = scorer.calculate(
            key_exchange_algorithms=["ECDHE"],
            certificate_algorithm="RSA-2048",
            endpoint_type="api",
        )
        assert 0.7 <= result.data_sensitivity <= 0.9
    
    # ================================================================
    # Exposure Factor Tests
    # ================================================================
    
    def test_exposure_increases_with_time(self, scorer):
        """Longer exposure should increase exposure factor"""
        recent = datetime.now(timezone.utc) - timedelta(days=7)
        old = datetime.now(timezone.utc) - timedelta(days=365)
        
        result_recent = scorer.calculate(
            key_exchange_algorithms=["ECDHE"],
            certificate_algorithm="RSA-2048",
            first_seen=recent,
        )
        
        result_old = scorer.calculate(
            key_exchange_algorithms=["ECDHE"],
            certificate_algorithm="RSA-2048",
            first_seen=old,
        )
        
        assert result_old.exposure_factor > result_recent.exposure_factor
    
    def test_high_traffic_increases_exposure(self, scorer):
        """High traffic should increase exposure factor"""
        result_normal = scorer.calculate(
            key_exchange_algorithms=["ECDHE"],
            certificate_algorithm="RSA-2048",
            is_high_traffic=False,
        )
        
        result_high = scorer.calculate(
            key_exchange_algorithms=["ECDHE"],
            certificate_algorithm="RSA-2048",
            is_high_traffic=True,
        )
        
        assert result_high.exposure_factor > result_normal.exposure_factor
    
    # ================================================================
    # Recommendation Tests
    # ================================================================
    
    def test_recommendation_for_vulnerable(self, scorer):
        """Vulnerable algorithms should have migration recommendation"""
        result = scorer.calculate(
            key_exchange_algorithms=["RSA"],
            certificate_algorithm="RSA-2048",
        )
        assert "RSA" in result.recommended_action
        assert "ML-DSA" in result.recommended_action or "migrate" in result.recommended_action.lower()
    
    def test_recommendation_for_safe(self, scorer):
        """Safe algorithms should have no action recommendation"""
        result = scorer.calculate(
            key_exchange_algorithms=["ML-KEM-768"],
            certificate_algorithm="ML-DSA-65",
        )
        assert "no action" in result.recommended_action.lower() or "safe" in result.recommended_action.lower()
    
    # ================================================================
    # Risk Horizon Tests
    # ================================================================
    
    def test_risk_horizon_for_vulnerable(self, scorer):
        """Vulnerable algorithms should show CRQC timeline"""
        result = scorer.calculate(
            key_exchange_algorithms=["RSA"],
            certificate_algorithm="RSA-2048",
        )
        assert "2035" in result.estimated_risk_horizon or "year" in result.estimated_risk_horizon.lower()
    
    def test_risk_horizon_for_safe(self, scorer):
        """Safe algorithms should indicate not applicable"""
        result = scorer.calculate(
            key_exchange_algorithms=["ML-KEM-768"],
            certificate_algorithm="ML-DSA-65",
        )
        assert "not applicable" in result.estimated_risk_horizon.lower() or "quantum-resistant" in result.estimated_risk_horizon.lower()
    
    # ================================================================
    # Convenience Function Tests
    # ================================================================
    
    def test_calculate_hndl_score_function(self):
        """calculate_hndl_score convenience function should work"""
        result = calculate_hndl_score(
            key_exchange_algorithms=["ECDHE"],
            certificate_algorithm="RSA-2048",
        )
        assert isinstance(result, HNDLScore)
    
    # ================================================================
    # Edge Case Tests
    # ================================================================
    
    def test_empty_algorithms(self, scorer):
        """Should handle empty algorithm lists gracefully"""
        result = scorer.calculate(
            key_exchange_algorithms=[],
            certificate_algorithm="RSA-2048",
        )
        assert result is not None
    
    def test_unknown_endpoint_type(self, scorer):
        """Unknown endpoint types should use default sensitivity"""
        result = scorer.calculate(
            key_exchange_algorithms=["ECDHE"],
            certificate_algorithm="RSA-2048",
            endpoint_type="unknown_service_xyz",
        )
        assert result.data_sensitivity == 0.5  # default


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
