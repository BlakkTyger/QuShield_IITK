"""
PQC Certificate Signer (Layer 4)

Issues PQC-signed digital certificates using ML-DSA-87 (FIPS 204).
Generates "Fully Quantum Safe" or "PQC Ready" labels.

References:
- NIST FIPS 204: ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
- JSON-LD for certificate structure
"""

import json
import hashlib
import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum
import uuid

from qushield.utils.logging import get_logger

logger = get_logger("certify")


class CertTier(str, Enum):
    """Certificate tier levels"""
    FULLY_QUANTUM_SAFE = "FULLY_QUANTUM_SAFE"
    PQC_READY = "PQC_READY"
    VULNERABLE = "VULNERABLE"
    CRITICAL = "CRITICAL"
    NOT_SCANNED = "NOT_SCANNED"


@dataclass
class PQCCertificate:
    """QuShield PQC Certificate structure (JSON-LD compatible)"""
    # Required fields
    cert_id: str
    subject: str
    tier: CertTier
    algorithms_verified: List[str]
    
    # Timestamps
    issued_at: str = ""
    expires_at: str = ""
    
    # NIST standards referenced
    nist_standards: List[str] = field(default_factory=list)
    
    # HNDL assessment
    hndl_score: Optional[float] = None
    hndl_label: Optional[str] = None
    
    # Proof (signature)
    signature: Optional[str] = None
    signature_algorithm: str = "ML-DSA-87"
    verification_method: str = "did:qushield:ca#key-1"
    
    def __post_init__(self):
        if not self.cert_id:
            self.cert_id = str(uuid.uuid4())
        if not self.issued_at:
            self.issued_at = datetime.now(timezone.utc).isoformat()
        if not self.expires_at:
            expires = datetime.now(timezone.utc) + timedelta(days=90)
            self.expires_at = expires.isoformat()
    
    def to_json_ld(self) -> Dict[str, Any]:
        """Convert to JSON-LD format"""
        return {
            "@context": "https://qushield.io/context/v1",
            "@type": "PQCCertificate",
            "id": f"urn:uuid:{self.cert_id}",
            "subject": self.subject,
            "tier": self.tier.value,
            "algorithmsVerified": self.algorithms_verified,
            "nistStandards": self.nist_standards,
            "issuedAt": self.issued_at,
            "expiresAt": self.expires_at,
            "hndlAssessment": {
                "score": self.hndl_score,
                "label": self.hndl_label,
            } if self.hndl_score is not None else None,
            "proof": {
                "type": self.signature_algorithm,
                "created": self.issued_at,
                "proofPurpose": "assertionMethod",
                "verificationMethod": self.verification_method,
                "signature": self.signature,
            } if self.signature else None,
        }
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_json_ld(), indent=indent)


class PQCSigner:
    """
    PQC Certificate Signer using ML-DSA-87.
    
    Note: Full ML-DSA-87 signing requires liboqs-python.
    This implementation provides a fallback using SHA-384 HMAC
    when liboqs is not available.
    """
    
    def __init__(self, private_key: Optional[bytes] = None):
        """
        Initialize signer.
        
        Args:
            private_key: ML-DSA-87 private key (or HMAC secret for fallback)
        """
        self._private_key = private_key
        self._oqs_available = self._check_oqs()
        
        if self._oqs_available:
            logger.info("liboqs available - using ML-DSA-87 signatures")
        else:
            logger.warning("liboqs not available - using SHA-384 HMAC fallback")
    
    def _check_oqs(self) -> bool:
        """Check if liboqs is available"""
        try:
            import oqs
            return True
        except ImportError:
            return False
    
    def generate_keypair(self) -> tuple:
        """
        Generate ML-DSA-87 keypair.
        
        Returns:
            (public_key, private_key) tuple
        """
        if self._oqs_available:
            import oqs
            signer = oqs.Signature("Dilithium5")  # ML-DSA-87
            public_key = signer.generate_keypair()
            private_key = signer.export_secret_key()
            return (public_key, private_key)
        else:
            # Fallback: generate random HMAC secret
            import secrets
            secret = secrets.token_bytes(64)
            return (secret[:32], secret)  # "public" and "private"
    
    def sign(self, message: bytes) -> bytes:
        """
        Sign a message using ML-DSA-87 (or fallback).
        
        Args:
            message: Message bytes to sign
            
        Returns:
            Signature bytes
        """
        if not self._private_key:
            raise ValueError("No private key configured")
        
        if self._oqs_available:
            import oqs
            signer = oqs.Signature("Dilithium5")
            signer.import_secret_key(self._private_key)
            return signer.sign(message)
        else:
            # Fallback: HMAC-SHA384
            import hmac
            return hmac.new(self._private_key, message, hashlib.sha384).digest()
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify a signature.
        
        Args:
            message: Original message
            signature: Signature to verify
            public_key: Public key for verification
            
        Returns:
            True if valid, False otherwise
        """
        if self._oqs_available:
            import oqs
            verifier = oqs.Signature("Dilithium5")
            return verifier.verify(message, signature, public_key)
        else:
            # Fallback: HMAC verification
            import hmac
            expected = hmac.new(self._private_key, message, hashlib.sha384).digest()
            return hmac.compare_digest(expected, signature)
    
    def issue_certificate(
        self,
        subject: str,
        tier: CertTier,
        algorithms_verified: List[str],
        hndl_score: Optional[float] = None,
        hndl_label: Optional[str] = None,
        validity_days: int = 90,
    ) -> PQCCertificate:
        """
        Issue a PQC certificate for a subject.
        
        Args:
            subject: Certificate subject (e.g., "api.bank.com:443")
            tier: Certificate tier
            algorithms_verified: List of algorithms found
            hndl_score: Optional HNDL risk score
            hndl_label: Optional HNDL risk label
            validity_days: Certificate validity in days
            
        Returns:
            Signed PQCCertificate
        """
        # Determine NIST standards
        nist_standards = []
        for algo in algorithms_verified:
            algo_upper = algo.upper()
            if "MLKEM" in algo_upper or "KEM" in algo_upper:
                if "FIPS-203" not in nist_standards:
                    nist_standards.append("FIPS-203")
            if "MLDSA" in algo_upper or "DSA" in algo_upper and "SLH" not in algo_upper:
                if "FIPS-204" not in nist_standards:
                    nist_standards.append("FIPS-204")
            if "SLH" in algo_upper:
                if "FIPS-205" not in nist_standards:
                    nist_standards.append("FIPS-205")
        
        # Create certificate
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=validity_days)
        
        cert = PQCCertificate(
            cert_id=str(uuid.uuid4()),
            subject=subject,
            tier=tier,
            algorithms_verified=algorithms_verified,
            nist_standards=nist_standards,
            issued_at=now.isoformat(),
            expires_at=expires.isoformat(),
            hndl_score=hndl_score,
            hndl_label=hndl_label,
        )
        
        # Sign the certificate
        if self._private_key:
            cert_json = cert.to_json()
            signature = self.sign(cert_json.encode())
            cert.signature = base64.b64encode(signature).decode()
        
        logger.info(f"Issued {tier.value} certificate for {subject}", extra={
            "layer": 4,
            "target": subject,
            "data": {
                "cert_id": cert.cert_id,
                "tier": tier.value,
                "algorithms": algorithms_verified,
            }
        })
        
        return cert


class BadgeGenerator:
    """Generate HTML badges for PQC certificates"""
    
    BADGE_COLORS = {
        CertTier.FULLY_QUANTUM_SAFE: "#10b981",  # Green
        CertTier.PQC_READY: "#3b82f6",           # Blue
        CertTier.VULNERABLE: "#f59e0b",           # Orange
        CertTier.CRITICAL: "#ef4444",             # Red
        CertTier.NOT_SCANNED: "#6b7280",          # Gray
    }
    
    BADGE_LABELS = {
        CertTier.FULLY_QUANTUM_SAFE: "Fully Quantum Safe",
        CertTier.PQC_READY: "PQC Ready",
        CertTier.VULNERABLE: "Quantum Vulnerable",
        CertTier.CRITICAL: "Critical Risk",
        CertTier.NOT_SCANNED: "Not Scanned",
    }
    
    BADGE_ICONS = {
        CertTier.FULLY_QUANTUM_SAFE: "✓",
        CertTier.PQC_READY: "◐",
        CertTier.VULNERABLE: "⚠",
        CertTier.CRITICAL: "✗",
        CertTier.NOT_SCANNED: "?",
    }
    
    def generate_badge_html(self, cert: PQCCertificate, verify_url: str = "") -> str:
        """
        Generate embeddable HTML badge for a certificate.
        
        Args:
            cert: The PQC certificate
            verify_url: URL for verification (optional)
            
        Returns:
            HTML string for the badge
        """
        color = self.BADGE_COLORS.get(cert.tier, "#6b7280")
        label = self.BADGE_LABELS.get(cert.tier, "Unknown")
        icon = self.BADGE_ICONS.get(cert.tier, "?")
        
        if not verify_url:
            verify_url = f"https://qushield.io/verify/{cert.cert_id}"
        
        return f'''<!DOCTYPE html>
<html>
<head>
    <style>
        .qushield-badge {{
            display: inline-flex;
            align-items: center;
            padding: 8px 16px;
            border-radius: 8px;
            font-family: system-ui, -apple-system, sans-serif;
            font-size: 14px;
            font-weight: 600;
            background: linear-gradient(135deg, {color} 0%, {color}dd 100%);
            color: white;
            text-decoration: none;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .qushield-badge:hover {{
            transform: translateY(-1px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }}
        .qushield-icon {{
            margin-right: 8px;
            font-size: 16px;
        }}
        .qushield-text {{
            display: flex;
            flex-direction: column;
            align-items: flex-start;
        }}
        .qushield-label {{
            font-size: 12px;
            opacity: 0.9;
        }}
        .qushield-status {{
            font-size: 14px;
            font-weight: 700;
        }}
    </style>
</head>
<body>
    <a href="{verify_url}" class="qushield-badge" target="_blank" rel="noopener">
        <span class="qushield-icon">{icon}</span>
        <span class="qushield-text">
            <span class="qushield-label">QuShield Verified</span>
            <span class="qushield-status">{label}</span>
        </span>
    </a>
</body>
</html>'''
    
    def generate_badge_svg(self, cert: PQCCertificate) -> str:
        """Generate SVG badge for embedding"""
        color = self.BADGE_COLORS.get(cert.tier, "#6b7280")
        label = self.BADGE_LABELS.get(cert.tier, "Unknown")
        
        return f'''<svg xmlns="http://www.w3.org/2000/svg" width="180" height="28">
    <linearGradient id="bg" x2="0" y2="100%">
        <stop offset="0" stop-color="#555"/>
        <stop offset=".1" stop-color="#444"/>
    </linearGradient>
    <rect rx="4" width="180" height="28" fill="url(#bg)"/>
    <rect rx="4" x="70" width="110" height="28" fill="{color}"/>
    <text x="8" y="19" fill="#fff" font-family="DejaVu Sans,Verdana,sans-serif" font-size="11">QuShield</text>
    <text x="78" y="19" fill="#fff" font-family="DejaVu Sans,Verdana,sans-serif" font-size="11">{label}</text>
</svg>'''


# Singleton instances
_signer: Optional[PQCSigner] = None
_badge_generator = BadgeGenerator()


def get_signer(private_key: Optional[bytes] = None) -> PQCSigner:
    """Get or create PQC signer instance"""
    global _signer
    if _signer is None:
        _signer = PQCSigner(private_key=private_key)
    return _signer


def issue_certificate(
    subject: str,
    tier: CertTier,
    algorithms: List[str],
    **kwargs
) -> PQCCertificate:
    """Convenience function to issue a certificate"""
    return get_signer().issue_certificate(
        subject=subject,
        tier=tier,
        algorithms_verified=algorithms,
        **kwargs
    )


def generate_badge(cert: PQCCertificate, verify_url: str = "") -> str:
    """Generate HTML badge for a certificate"""
    return _badge_generator.generate_badge_html(cert, verify_url)
