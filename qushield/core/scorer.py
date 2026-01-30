"""
HNDL Risk Scorer

Calculates "Harvest Now, Decrypt Later" (HNDL) risk scores for assets
based on cryptographic posture and business context.

Formula: HNDL_Score = Data_Sensitivity × Algorithm_Vulnerability × Exposure_Factor

References:
- IETF draft-ietf-pquip-pqc-engineers Section 4.2 (Threat Models)
- NSA CNSA 2.0 Timeline Requirements
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, List
from enum import Enum

from qushield.core.classifier import PQCClassifier, QuantumSafety
from qushield.utils.logging import get_logger, timed

logger = get_logger("hndl_scorer")


class HNDLRiskLabel(str, Enum):
    """Risk label categories"""
    CRITICAL = "CRITICAL"   # Score >= 0.8
    HIGH = "HIGH"           # Score >= 0.6
    MEDIUM = "MEDIUM"       # Score >= 0.3
    LOW = "LOW"             # Score < 0.3


@dataclass
class HNDLScore:
    """HNDL risk assessment result"""
    score: float                    # 0.0 to 1.0
    label: HNDLRiskLabel
    data_sensitivity: float
    algo_vulnerability: float
    exposure_factor: float
    algorithms_analyzed: List[str]
    worst_algorithm: str
    recommended_action: str
    estimated_risk_horizon: str     # When CRQC might break this


# Data sensitivity weights by endpoint/service type
DATA_SENSITIVITY_WEIGHTS = {
    # Financial - highest sensitivity
    "payment": 1.0,
    "banking": 1.0,
    "transaction": 1.0,
    "core_banking": 1.0,
    
    # Authentication & Identity
    "authentication": 0.95,
    "auth": 0.95,
    "identity": 0.95,
    "sso": 0.90,
    "oauth": 0.90,
    
    # Personal Data
    "pii": 0.90,
    "customer": 0.85,
    "kyc": 0.90,
    
    # API & Services
    "api": 0.80,
    "rest": 0.75,
    "grpc": 0.75,
    "graphql": 0.75,
    
    # Internal Systems
    "internal": 0.60,
    "admin": 0.70,
    "management": 0.65,
    
    # Web & Static
    "web": 0.50,
    "website": 0.50,
    "portal": 0.60,
    "static": 0.30,
    "cdn": 0.25,
    
    # Default
    "unknown": 0.50,
}

# CRQC timeline estimates (years until algorithm is broken)
CRQC_TIMELINE = {
    QuantumSafety.CRITICAL: "Already broken",
    QuantumSafety.VULNERABLE: "5-15 years (NSA CNSA 2.0: 2035)",
    QuantumSafety.HYBRID: "Post-2040 (if classical component breaks)",
    QuantumSafety.FULLY_SAFE: "Not applicable (quantum-resistant)",
}


class HNDLScorer:
    """
    Harvest Now, Decrypt Later (HNDL) Risk Scorer
    
    Evaluates the risk that encrypted data captured today could be
    decrypted by future quantum computers.
    """
    
    def __init__(self):
        self.classifier = PQCClassifier()
        logger.debug("HNDLScorer initialized", extra={"layer": 3})
    
    @timed(logger=logger, layer=3)
    def calculate(
        self,
        key_exchange_algorithms: List[str],
        certificate_algorithm: str,
        endpoint_type: str = "unknown",
        first_seen: Optional[datetime] = None,
        is_high_traffic: bool = False,
        has_sensitive_data: bool = True,
    ) -> HNDLScore:
        """
        Calculate HNDL risk score for an endpoint.
        
        Args:
            key_exchange_algorithms: List of key exchange algorithms (e.g., ["ECDHE-P256"])
            certificate_algorithm: Certificate signature algorithm (e.g., "RSA-2048")
            endpoint_type: Type of service (e.g., "payment", "api", "web")
            first_seen: When the asset was first discovered
            is_high_traffic: Whether this is a high-traffic endpoint
            has_sensitive_data: Whether endpoint handles sensitive data
            
        Returns:
            HNDLScore with detailed risk assessment
        """
        # Combine all algorithms for analysis
        all_algorithms = key_exchange_algorithms + [certificate_algorithm]
        
        # 1. Calculate algorithm vulnerability (worst case)
        algo_vulnerability = self._calculate_algo_vulnerability(all_algorithms)
        worst_algo = self._get_worst_algorithm(all_algorithms)
        effective_safety = self.classifier.get_effective_safety(all_algorithms)
        
        # Discount vulnerability for hybrid/PQC deployments
        if effective_safety == QuantumSafety.HYBRID:
            algo_vulnerability = min(algo_vulnerability, 0.15)
        elif effective_safety == QuantumSafety.FULLY_SAFE:
            algo_vulnerability = 0.0
        
        # 2. Calculate data sensitivity
        data_sensitivity = self._calculate_data_sensitivity(
            endpoint_type, has_sensitive_data
        )
        
        # 3. Calculate exposure factor
        exposure_factor = self._calculate_exposure_factor(
            first_seen, is_high_traffic
        )
        
        # 4. Final HNDL score
        raw_score = data_sensitivity * algo_vulnerability * exposure_factor
        score = round(min(1.0, raw_score), 3)
        
        # 5. Determine risk label
        label = self._score_to_label(score)
        
        # 6. Get recommended action
        action = self._get_recommendation(worst_algo, score)
        
        # 7. Get risk horizon
        risk_horizon = CRQC_TIMELINE.get(effective_safety, "Unknown")
        
        return HNDLScore(
            score=score,
            label=label,
            data_sensitivity=round(data_sensitivity, 3),
            algo_vulnerability=round(algo_vulnerability, 3),
            exposure_factor=round(exposure_factor, 3),
            algorithms_analyzed=all_algorithms,
            worst_algorithm=worst_algo,
            recommended_action=action,
            estimated_risk_horizon=risk_horizon,
        )
    
    def _calculate_algo_vulnerability(self, algorithms: List[str]) -> float:
        """Get maximum vulnerability score from algorithms"""
        if not algorithms:
            return 0.5  # Unknown
        
        return self.classifier.get_max_vuln_score(algorithms)
    
    def _get_worst_algorithm(self, algorithms: List[str]) -> str:
        """Get the most vulnerable algorithm from the list"""
        if not algorithms:
            return "Unknown"
        
        worst = algorithms[0]
        worst_score = 0.0
        
        for algo in algorithms:
            info = self.classifier.classify(algo)
            if info.vuln_score > worst_score:
                worst_score = info.vuln_score
                worst = algo
        
        return worst
    
    def _calculate_data_sensitivity(
        self, endpoint_type: str, has_sensitive_data: bool
    ) -> float:
        """Calculate data sensitivity factor"""
        # Get base sensitivity from endpoint type
        endpoint_lower = endpoint_type.lower().strip()
        
        # Check for partial matches
        base_sensitivity = 0.5
        for key, weight in DATA_SENSITIVITY_WEIGHTS.items():
            if key in endpoint_lower or endpoint_lower in key:
                base_sensitivity = weight
                break
        
        # Adjust for sensitive data flag
        if not has_sensitive_data:
            base_sensitivity *= 0.7
        
        return min(1.0, base_sensitivity)
    
    def _calculate_exposure_factor(
        self, first_seen: Optional[datetime], is_high_traffic: bool
    ) -> float:
        """
        Calculate exposure factor based on time exposed and traffic.
        
        Longer exposure = more time for adversaries to harvest data
        Higher traffic = more valuable data captured
        """
        # Base exposure: how long has the asset been exposed?
        if first_seen:
            now = datetime.now(timezone.utc)
            if first_seen.tzinfo is None:
                first_seen = first_seen.replace(tzinfo=timezone.utc)
            days_exposed = (now - first_seen).days
        else:
            days_exposed = 30  # Assume 1 month if unknown
        
        # Normalize: 1 year = full exposure
        time_factor = min(1.0, days_exposed / 365)
        
        # Base exposure factor (50% minimum for any internet-facing asset)
        exposure = 0.5 + (0.5 * time_factor)
        
        # High traffic multiplier
        if is_high_traffic:
            exposure = min(1.0, exposure * 1.3)
        
        return exposure
    
    def _score_to_label(self, score: float) -> HNDLRiskLabel:
        """Convert numeric score to risk label"""
        if score >= 0.8:
            return HNDLRiskLabel.CRITICAL
        elif score >= 0.6:
            return HNDLRiskLabel.HIGH
        elif score >= 0.3:
            return HNDLRiskLabel.MEDIUM
        else:
            return HNDLRiskLabel.LOW
    
    def _get_recommendation(self, worst_algo: str, score: float) -> str:
        """Generate recommended action based on risk"""
        info = self.classifier.classify(worst_algo)
        
        if info.safety == QuantumSafety.FULLY_SAFE:
            return "No action needed - fully quantum safe"
        
        if info.safety == QuantumSafety.HYBRID:
            return "Consider migration to pure PQC by 2030 (CNSA 2.0 deadline: 2035)"
        
        if info.safety == QuantumSafety.CRITICAL:
            return f"URGENT: Replace {worst_algo} immediately with {info.migrate_to or 'modern algorithm'}"
        
        # Vulnerable
        if score >= 0.8:
            return f"CRITICAL: Migrate {worst_algo} to {info.migrate_to} within 6 months"
        elif score >= 0.6:
            return f"HIGH: Plan migration of {worst_algo} to {info.migrate_to} within 1 year"
        elif score >= 0.3:
            return f"MEDIUM: Schedule {worst_algo} migration to {info.migrate_to} by 2027"
        else:
            return f"LOW: Add {worst_algo} → {info.migrate_to} to long-term roadmap"


# Singleton instance
scorer = HNDLScorer()


def calculate_hndl_score(
    key_exchange_algorithms: List[str],
    certificate_algorithm: str,
    endpoint_type: str = "unknown",
    first_seen: Optional[datetime] = None,
    is_high_traffic: bool = False,
) -> HNDLScore:
    """Convenience function to calculate HNDL score"""
    return scorer.calculate(
        key_exchange_algorithms=key_exchange_algorithms,
        certificate_algorithm=certificate_algorithm,
        endpoint_type=endpoint_type,
        first_seen=first_seen,
        is_high_traffic=is_high_traffic,
    )
