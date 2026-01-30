"""
CBOM (Cryptographic Bill of Materials) Builder

Generates CycloneDX 1.6 compliant CBOM documents with crypto properties
and CERT-In QBOM (Quantum Bill of Materials) extension.

References:
- CycloneDX 1.6 Specification: https://cyclonedx.org/docs/1.6/
- OWASP CycloneDX CBOM Guide: https://cyclonedx.org/capabilities/cbom/
- CERT-In CBOM Guidelines v2.0
- NIST SP 800-208: Recommendation for Stateful Hash-Based Signature Schemes
"""

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from enum import Enum

from qushield.core.classifier import PQCClassifier, QuantumSafety, AlgorithmInfo
from qushield.utils.logging import get_logger, timed

logger = get_logger("cbom_builder")


class CryptoAssetType(str, Enum):
    """Types of cryptographic assets"""
    ALGORITHM = "algorithm"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"
    KEY = "key"
    RELATED_CRYPTO_MATERIAL = "related-crypto-material"


class CryptoPrimitive(str, Enum):
    """Cryptographic primitive types"""
    KEY_ENCAPSULATION = "key-encapsulation"
    KEY_AGREEMENT = "key-agreement"
    SIGNATURE = "signature"
    ENCRYPTION = "encryption"
    HASH = "hash"
    MAC = "mac"
    UNKNOWN = "unknown"


@dataclass
class CryptoProperties:
    """CycloneDX crypto properties extension"""
    asset_type: CryptoAssetType
    algorithm_name: str
    primitive: CryptoPrimitive
    parameter_set_identifier: Optional[str] = None
    oid: Optional[str] = None
    nist_quantum_security_level: Optional[int] = None  # 1-5
    
    # Custom extension for quantum safety
    x_quantum_safe: bool = False
    x_quantum_safety_level: str = "UNKNOWN"
    x_migration_target: Optional[str] = None


@dataclass
class CryptoComponent:
    """A cryptographic component in the CBOM"""
    bom_ref: str
    type: str = "cryptographic-asset"
    name: str = ""
    version: str = ""
    description: str = ""
    crypto_properties: Optional[CryptoProperties] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            "bom-ref": self.bom_ref,
            "type": self.type,
            "name": self.name,
        }
        if self.version:
            result["version"] = self.version
        if self.description:
            result["description"] = self.description
        if self.crypto_properties:
            result["cryptoProperties"] = {
                "assetType": self.crypto_properties.asset_type.value,
                "algorithmProperties": {
                    "primitive": self.crypto_properties.primitive.value,
                }
            }
            if self.crypto_properties.parameter_set_identifier:
                result["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"] = \
                    self.crypto_properties.parameter_set_identifier
            if self.crypto_properties.oid:
                result["cryptoProperties"]["oid"] = self.crypto_properties.oid
            if self.crypto_properties.nist_quantum_security_level:
                result["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] = \
                    self.crypto_properties.nist_quantum_security_level
            
            # Custom quantum safety extensions (x- prefix)
            result["cryptoProperties"]["x-quantumSafe"] = self.crypto_properties.x_quantum_safe
            result["cryptoProperties"]["x-quantumSafetyLevel"] = self.crypto_properties.x_quantum_safety_level
            if self.crypto_properties.x_migration_target:
                result["cryptoProperties"]["x-migrationTarget"] = self.crypto_properties.x_migration_target
        
        return result


@dataclass
class CBOMMetadata:
    """CBOM metadata"""
    timestamp: str = ""
    tools: List[Dict] = field(default_factory=list)
    component: Optional[Dict] = None
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if not self.tools:
            self.tools = [{
                "vendor": "QuShield",
                "name": "QuShield PQC Scanner",
                "version": "1.0.0",
            }]


@dataclass
class CERTInQBOMExtension:
    """CERT-In QBOM (Quantum Bill of Materials) Extension"""
    assessment_date: str = ""
    organization: str = ""
    pqc_readiness_score: float = 0.0  # 0.0 to 1.0
    migration_priority: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    compliance_status: str = "NON_COMPLIANT"  # COMPLIANT, PARTIAL, NON_COMPLIANT
    nist_security_levels: List[int] = field(default_factory=list)
    vulnerable_algorithm_count: int = 0
    pqc_algorithm_count: int = 0
    hybrid_algorithm_count: int = 0
    recommended_actions: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.assessment_date:
            self.assessment_date = datetime.now(timezone.utc).isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessmentDate": self.assessment_date,
            "organization": self.organization,
            "pqcReadinessScore": round(self.pqc_readiness_score, 3),
            "migrationPriority": self.migration_priority,
            "complianceStatus": self.compliance_status,
            "nistSecurityLevels": self.nist_security_levels,
            "statistics": {
                "vulnerableAlgorithms": self.vulnerable_algorithm_count,
                "pqcAlgorithms": self.pqc_algorithm_count,
                "hybridAlgorithms": self.hybrid_algorithm_count,
            },
            "recommendedActions": self.recommended_actions,
        }


@dataclass
class CBOM:
    """CycloneDX 1.6 Cryptographic Bill of Materials with CERT-In QBOM Extension"""
    bom_format: str = "CycloneDX"
    spec_version: str = "1.6"
    serial_number: str = ""
    version: int = 1
    metadata: CBOMMetadata = field(default_factory=CBOMMetadata)
    components: List[CryptoComponent] = field(default_factory=list)
    cert_in_qbom: Optional[CERTInQBOMExtension] = None
    
    def __post_init__(self):
        if not self.serial_number:
            self.serial_number = f"urn:uuid:{uuid.uuid4()}"
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            "bomFormat": self.bom_format,
            "specVersion": self.spec_version,
            "serialNumber": self.serial_number,
            "version": self.version,
            "metadata": {
                "timestamp": self.metadata.timestamp,
                "tools": self.metadata.tools,
            },
            "components": [c.to_dict() for c in self.components],
        }
        
        # Add CERT-In QBOM extension if present
        if self.cert_in_qbom:
            result["extensions"] = {
                "x-cert-in-qbom": self.cert_in_qbom.to_dict()
            }
        
        return result
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class CBOMBuilder:
    """Builder for creating CBOM documents from scan results with CERT-In QBOM extension"""
    
    # NIST security level mapping
    NIST_SECURITY_LEVELS = {
        "ML-KEM-512": 1,
        "ML-KEM-768": 3,
        "ML-KEM-1024": 5,
        "ML-DSA-44": 2,
        "ML-DSA-65": 3,
        "ML-DSA-87": 5,
        "SLH-DSA-128s": 1,
        "SLH-DSA-128f": 1,
        "SLH-DSA-192s": 3,
        "SLH-DSA-192f": 3,
        "SLH-DSA-256s": 5,
        "SLH-DSA-256f": 5,
        "AES-128": 1,
        "AES-192": 3,
        "AES-256": 5,
    }
    
    # OID mappings for common algorithms
    ALGORITHM_OIDS = {
        "RSA": "1.2.840.113549.1.1.1",
        "RSA-SHA256": "1.2.840.113549.1.1.11",
        "RSA-SHA384": "1.2.840.113549.1.1.12",
        "RSA-SHA512": "1.2.840.113549.1.1.13",
        "ECDSA": "1.2.840.10045.2.1",
        "ECDSA-SHA256": "1.2.840.10045.4.3.2",
        "ECDSA-SHA384": "1.2.840.10045.4.3.3",
        "Ed25519": "1.3.101.112",
        "X25519": "1.3.101.110",
        "AES-128": "2.16.840.1.101.3.4.1.1",
        "AES-256": "2.16.840.1.101.3.4.1.41",
        "SHA-256": "2.16.840.1.101.3.4.2.1",
        "SHA-384": "2.16.840.1.101.3.4.2.2",
        "SHA-512": "2.16.840.1.101.3.4.2.3",
        # PQC (draft OIDs)
        "ML-KEM-768": "2.16.840.1.101.3.4.4.2",
        "ML-DSA-65": "2.16.840.1.101.3.4.3.18",
    }
    
    # Primitive mapping
    PRIMITIVE_MAP = {
        "kem": CryptoPrimitive.KEY_ENCAPSULATION,
        "sig": CryptoPrimitive.SIGNATURE,
        "cipher": CryptoPrimitive.ENCRYPTION,
        "hash": CryptoPrimitive.HASH,
    }
    
    def __init__(self):
        self.classifier = PQCClassifier()
        self._components: List[CryptoComponent] = []
        self._seen_algorithms: set = set()
        self._stats = {"vulnerable": 0, "pqc": 0, "hybrid": 0}
        logger.debug("CBOMBuilder initialized", extra={"layer": 3})
    
    def reset(self):
        """Reset builder state"""
        self._components = []
        self._seen_algorithms = set()
        self._stats = {"vulnerable": 0, "pqc": 0, "hybrid": 0}
    
    def add_algorithm(
        self,
        algorithm: str,
        context: str = "",
        occurrence_count: int = 1
    ) -> CryptoComponent:
        """
        Add a cryptographic algorithm to the CBOM.
        
        Args:
            algorithm: Algorithm name (e.g., "RSA-2048", "ECDHE-P256")
            context: Where this was found (e.g., "TLS key exchange")
            occurrence_count: How many times this was observed
        """
        # Skip duplicates
        algo_key = f"{algorithm}:{context}"
        if algo_key in self._seen_algorithms:
            return None
        self._seen_algorithms.add(algo_key)
        
        # Classify the algorithm
        info = self.classifier.classify(algorithm)
        
        # Map primitive
        primitive = self.PRIMITIVE_MAP.get(info.primitive, CryptoPrimitive.UNKNOWN)
        
        # Create crypto properties
        crypto_props = CryptoProperties(
            asset_type=CryptoAssetType.ALGORITHM,
            algorithm_name=info.name,
            primitive=primitive,
            oid=self.ALGORITHM_OIDS.get(algorithm.upper()),
            x_quantum_safe=(info.safety == QuantumSafety.FULLY_SAFE),
            x_quantum_safety_level=info.safety.value,
            x_migration_target=info.migrate_to,
        )
        
        # Set NIST security level for PQC algorithms
        if info.nist_fips:
            if "768" in algorithm or "65" in algorithm:
                crypto_props.nist_quantum_security_level = 3
            elif "1024" in algorithm or "87" in algorithm:
                crypto_props.nist_quantum_security_level = 5
            elif "512" in algorithm or "44" in algorithm:
                crypto_props.nist_quantum_security_level = 1
        
        # Build description
        description = f"Found in {context}" if context else ""
        if info.migrate_to and info.safety != QuantumSafety.FULLY_SAFE:
            description += f". Migration target: {info.migrate_to}"
        
        component = CryptoComponent(
            bom_ref=f"crypto-{uuid.uuid4().hex[:8]}",
            name=algorithm,
            description=description.strip(),
            crypto_properties=crypto_props,
        )
        
        self._components.append(component)
        
        # Track statistics
        if info.safety == QuantumSafety.FULLY_SAFE:
            self._stats["pqc"] += 1
        elif info.safety == QuantumSafety.HYBRID:
            self._stats["hybrid"] += 1
        else:
            self._stats["vulnerable"] += 1
        
        logger.debug(f"Added algorithm: {algorithm} ({info.safety.value})", extra={"layer": 3})
        return component
    
    def add_certificate(
        self,
        subject: str,
        issuer: str,
        algorithm: str,
        key_size: Optional[int] = None,
        not_after: Optional[str] = None,
    ) -> CryptoComponent:
        """Add a certificate to the CBOM"""
        info = self.classifier.classify(algorithm)
        
        crypto_props = CryptoProperties(
            asset_type=CryptoAssetType.CERTIFICATE,
            algorithm_name=algorithm,
            primitive=CryptoPrimitive.SIGNATURE,
            parameter_set_identifier=str(key_size) if key_size else None,
            x_quantum_safe=(info.safety == QuantumSafety.FULLY_SAFE),
            x_quantum_safety_level=info.safety.value,
            x_migration_target=info.migrate_to,
        )
        
        description = f"Subject: {subject}, Issuer: {issuer}"
        if not_after:
            description += f", Expires: {not_after}"
        
        component = CryptoComponent(
            bom_ref=f"cert-{uuid.uuid4().hex[:8]}",
            name=f"Certificate ({subject})",
            description=description,
            crypto_properties=crypto_props,
        )
        
        self._components.append(component)
        return component
    
    def add_protocol(
        self,
        protocol: str,
        version: str,
        cipher_suites: List[str] = None,
    ) -> CryptoComponent:
        """Add a protocol (e.g., TLS) to the CBOM"""
        component = CryptoComponent(
            bom_ref=f"proto-{uuid.uuid4().hex[:8]}",
            type="cryptographic-asset",
            name=f"{protocol} {version}",
            version=version,
            description=f"Cipher suites: {', '.join(cipher_suites or [])}",
            crypto_properties=CryptoProperties(
                asset_type=CryptoAssetType.PROTOCOL,
                algorithm_name=protocol,
                primitive=CryptoPrimitive.UNKNOWN,
                x_quantum_safe=False,  # TLS versions aren't inherently quantum safe
                x_quantum_safety_level="PROTOCOL",
            ),
        )
        
        self._components.append(component)
        return component
    
    def build(
        self,
        target_name: str = "",
        target_version: str = "1.0",
    ) -> CBOM:
        """
        Build the final CBOM document.
        
        Args:
            target_name: Name of the scanned target/application
            target_version: Version of the target
        """
        metadata = CBOMMetadata()
        if target_name:
            metadata.component = {
                "type": "application",
                "name": target_name,
                "version": target_version,
            }
        
        return CBOM(
            metadata=metadata,
            components=self._components.copy(),
        )
    
    @timed(logger=logger, layer=3)
    def build_from_scan_result(
        self,
        target: str,
        key_exchange_algorithms: List[str],
        certificate_algorithm: str,
        certificate_subject: str = "",
        certificate_issuer: str = "",
        certificate_key_size: Optional[int] = None,
        certificate_expiry: Optional[str] = None,
        tls_versions: List[str] = None,
        cipher_suites: List[str] = None,
        organization: str = "",
    ) -> CBOM:
        """
        Build CBOM from a scan result with CERT-In QBOM extension.
        
        Convenience method that adds all components from a single scan.
        """
        logger.info(f"Building CBOM for {target}", extra={
            "layer": 3,
            "target": target,
            "data": {
                "key_exchanges": key_exchange_algorithms,
                "cert_algorithm": certificate_algorithm,
            }
        })
        
        self.reset()
        
        # Add key exchange algorithms
        for algo in key_exchange_algorithms:
            self.add_algorithm(algo, context="TLS key exchange")
        
        # Add certificate
        if certificate_algorithm:
            self.add_certificate(
                subject=certificate_subject or target,
                issuer=certificate_issuer or "Unknown CA",
                algorithm=certificate_algorithm,
                key_size=certificate_key_size,
                not_after=certificate_expiry,
            )
            # Track certificate algorithm stats
            cert_info = self.classifier.classify(certificate_algorithm)
            if cert_info.safety == QuantumSafety.FULLY_SAFE:
                self._stats["pqc"] += 1
            elif cert_info.safety == QuantumSafety.HYBRID:
                self._stats["hybrid"] += 1
            else:
                self._stats["vulnerable"] += 1
        
        # Add TLS protocols
        for version in (tls_versions or []):
            self.add_protocol("TLS", version, cipher_suites)
        
        # Build CERT-In QBOM extension
        cert_in_qbom = self._build_cert_in_extension(
            target=target,
            organization=organization,
            key_exchange_algorithms=key_exchange_algorithms,
            certificate_algorithm=certificate_algorithm,
        )
        
        cbom = self.build(target_name=target)
        cbom.cert_in_qbom = cert_in_qbom
        
        logger.info(f"CBOM generated with {len(self._components)} components", extra={
            "layer": 3,
            "target": target,
            "data": {
                "components": len(self._components),
                "pqc_readiness": cert_in_qbom.pqc_readiness_score,
                "migration_priority": cert_in_qbom.migration_priority,
            }
        })
        
        return cbom
    
    def _build_cert_in_extension(
        self,
        target: str,
        organization: str,
        key_exchange_algorithms: List[str],
        certificate_algorithm: str,
    ) -> CERTInQBOMExtension:
        """Build CERT-In QBOM extension from scan data"""
        
        # Calculate PQC readiness score
        total_algos = self._stats["pqc"] + self._stats["hybrid"] + self._stats["vulnerable"]
        if total_algos > 0:
            pqc_readiness = (self._stats["pqc"] + 0.5 * self._stats["hybrid"]) / total_algos
        else:
            pqc_readiness = 0.0
        
        # Determine migration priority
        if self._stats["vulnerable"] > 0:
            if pqc_readiness < 0.3:
                migration_priority = "CRITICAL"
            elif pqc_readiness < 0.5:
                migration_priority = "HIGH"
            else:
                migration_priority = "MEDIUM"
        else:
            migration_priority = "LOW"
        
        # Determine compliance status
        if pqc_readiness >= 0.9:
            compliance_status = "COMPLIANT"
        elif pqc_readiness >= 0.5:
            compliance_status = "PARTIAL"
        else:
            compliance_status = "NON_COMPLIANT"
        
        # Collect NIST security levels
        nist_levels = set()
        all_algos = key_exchange_algorithms + [certificate_algorithm]
        for algo in all_algos:
            for key, level in self.NIST_SECURITY_LEVELS.items():
                if key.upper() in algo.upper():
                    nist_levels.add(level)
        
        # Generate recommended actions
        recommended_actions = []
        if self._stats["vulnerable"] > 0:
            recommended_actions.append(
                f"Migrate {self._stats['vulnerable']} vulnerable algorithm(s) to PQC"
            )
        if "ECDHE" in str(key_exchange_algorithms).upper():
            recommended_actions.append("Upgrade key exchange to X25519+ML-KEM-768 hybrid")
        if "RSA" in certificate_algorithm.upper():
            recommended_actions.append("Plan certificate migration to ML-DSA")
        if not recommended_actions:
            recommended_actions.append("Continue monitoring PQC ecosystem maturity")
        
        return CERTInQBOMExtension(
            organization=organization or target,
            pqc_readiness_score=pqc_readiness,
            migration_priority=migration_priority,
            compliance_status=compliance_status,
            nist_security_levels=sorted(list(nist_levels)),
            vulnerable_algorithm_count=self._stats["vulnerable"],
            pqc_algorithm_count=self._stats["pqc"],
            hybrid_algorithm_count=self._stats["hybrid"],
            recommended_actions=recommended_actions,
        )


# Convenience function
def generate_cbom(
    target: str,
    key_exchange_algorithms: List[str],
    certificate_algorithm: str,
    **kwargs
) -> str:
    """Generate CBOM JSON from scan data"""
    builder = CBOMBuilder()
    cbom = builder.build_from_scan_result(
        target=target,
        key_exchange_algorithms=key_exchange_algorithms,
        certificate_algorithm=certificate_algorithm,
        **kwargs
    )
    return cbom.to_json()
