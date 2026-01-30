"""
Tests for CBOM Builder (Layer 3)

Tests CycloneDX 1.6 CBOM generation with crypto properties.
"""

import pytest
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from qushield.output.cbom import (
    CBOMBuilder,
    CBOM,
    CryptoComponent,
    CryptoProperties,
    CryptoAssetType,
    CryptoPrimitive,
    generate_cbom,
)


class TestCBOMBuilder:
    """Test suite for CBOM Builder"""
    
    @pytest.fixture
    def builder(self):
        return CBOMBuilder()
    
    # ================================================================
    # CBOM Structure Tests
    # ================================================================
    
    def test_cbom_has_correct_format(self, builder):
        """CBOM should have CycloneDX format"""
        cbom = builder.build(target_name="test.com")
        assert cbom.bom_format == "CycloneDX"
        assert cbom.spec_version == "1.6"
    
    def test_cbom_has_serial_number(self, builder):
        """CBOM should have unique serial number"""
        cbom = builder.build(target_name="test.com")
        assert cbom.serial_number.startswith("urn:uuid:")
    
    def test_cbom_has_metadata(self, builder):
        """CBOM should have metadata with timestamp and tools"""
        cbom = builder.build(target_name="test.com")
        assert cbom.metadata is not None
        assert cbom.metadata.timestamp is not None
        assert len(cbom.metadata.tools) > 0
    
    def test_cbom_to_dict(self, builder):
        """CBOM to_dict should produce valid structure"""
        builder.add_algorithm("RSA-2048", context="test")
        cbom = builder.build(target_name="test.com")
        d = cbom.to_dict()
        
        assert "bomFormat" in d
        assert "specVersion" in d
        assert "serialNumber" in d
        assert "metadata" in d
        assert "components" in d
    
    def test_cbom_to_json(self, builder):
        """CBOM to_json should produce valid JSON"""
        builder.add_algorithm("RSA-2048", context="test")
        cbom = builder.build(target_name="test.com")
        json_str = cbom.to_json()
        
        # Should be valid JSON
        parsed = json.loads(json_str)
        assert parsed["bomFormat"] == "CycloneDX"
    
    # ================================================================
    # Algorithm Component Tests
    # ================================================================
    
    def test_add_algorithm(self, builder):
        """add_algorithm should create algorithm component"""
        component = builder.add_algorithm("RSA-2048", context="TLS")
        assert component is not None
        assert component.name == "RSA-2048"
    
    def test_algorithm_has_crypto_properties(self, builder):
        """Algorithm should have cryptoProperties"""
        component = builder.add_algorithm("RSA-2048")
        assert component.crypto_properties is not None
        assert component.crypto_properties.asset_type == CryptoAssetType.ALGORITHM
    
    def test_algorithm_quantum_safety_extension(self, builder):
        """Algorithm should have x-quantumSafe extension"""
        builder.add_algorithm("RSA-2048")
        cbom = builder.build()
        d = cbom.to_dict()
        
        component = d["components"][0]
        assert "x-quantumSafe" in component["cryptoProperties"]
        assert component["cryptoProperties"]["x-quantumSafe"] == False  # RSA is not safe
    
    def test_safe_algorithm_marked_safe(self, builder):
        """Quantum-safe algorithms should be marked as safe"""
        builder.add_algorithm("ML-KEM-768")
        cbom = builder.build()
        d = cbom.to_dict()
        
        component = d["components"][0]
        assert component["cryptoProperties"]["x-quantumSafe"] == True
    
    def test_migration_target_included(self, builder):
        """Vulnerable algorithms should include migration target"""
        builder.add_algorithm("RSA-2048")
        cbom = builder.build()
        d = cbom.to_dict()
        
        component = d["components"][0]
        assert "x-migrationTarget" in component["cryptoProperties"]
    
    # ================================================================
    # Certificate Component Tests
    # ================================================================
    
    def test_add_certificate(self, builder):
        """add_certificate should create certificate component"""
        component = builder.add_certificate(
            subject="test.com",
            issuer="Test CA",
            algorithm="RSA-2048",
            key_size=2048,
        )
        assert component is not None
        assert "Certificate" in component.name
    
    def test_certificate_has_crypto_properties(self, builder):
        """Certificate should have cryptoProperties"""
        component = builder.add_certificate(
            subject="test.com",
            issuer="Test CA",
            algorithm="RSA-2048",
        )
        assert component.crypto_properties.asset_type == CryptoAssetType.CERTIFICATE
        assert component.crypto_properties.primitive == CryptoPrimitive.SIGNATURE
    
    # ================================================================
    # Protocol Component Tests
    # ================================================================
    
    def test_add_protocol(self, builder):
        """add_protocol should create protocol component"""
        component = builder.add_protocol(
            protocol="TLS",
            version="1.3",
            cipher_suites=["TLS_AES_256_GCM_SHA384"],
        )
        assert component is not None
        assert "TLS" in component.name
    
    # ================================================================
    # Build from Scan Result Tests
    # ================================================================
    
    def test_build_from_scan_result(self, builder):
        """build_from_scan_result should create complete CBOM"""
        cbom = builder.build_from_scan_result(
            target="api.bank.com",
            key_exchange_algorithms=["ECDHE-P256", "X25519"],
            certificate_algorithm="RSA-2048",
            certificate_subject="api.bank.com",
            certificate_issuer="DigiCert",
            certificate_key_size=2048,
            tls_versions=["1.2", "1.3"],
        )
        
        assert len(cbom.components) > 0
        # Should have algorithms + certificate + protocols
    
    def test_build_from_scan_result_resets_state(self, builder):
        """build_from_scan_result should reset builder state"""
        builder.add_algorithm("OLD-ALGO")
        
        cbom = builder.build_from_scan_result(
            target="test.com",
            key_exchange_algorithms=["ECDHE"],
            certificate_algorithm="RSA-2048",
        )
        
        # Should not contain OLD-ALGO
        names = [c.name for c in cbom.components]
        assert "OLD-ALGO" not in names
    
    # ================================================================
    # Deduplication Tests
    # ================================================================
    
    def test_duplicate_algorithms_deduplicated(self, builder):
        """Duplicate algorithms should be deduplicated"""
        builder.add_algorithm("RSA-2048", context="TLS")
        builder.add_algorithm("RSA-2048", context="TLS")  # Same context
        cbom = builder.build()
        
        # Should only have one RSA-2048 for TLS context
        rsa_count = sum(1 for c in cbom.components if c.name == "RSA-2048")
        assert rsa_count == 1
    
    def test_same_algo_different_context_kept(self, builder):
        """Same algorithm in different contexts should be kept"""
        builder.add_algorithm("RSA-2048", context="TLS")
        builder.add_algorithm("RSA-2048", context="Certificate")
        cbom = builder.build()
        
        # Should have two RSA-2048 (different contexts)
        rsa_count = sum(1 for c in cbom.components if c.name == "RSA-2048")
        assert rsa_count == 2
    
    # ================================================================
    # Convenience Function Tests
    # ================================================================
    
    def test_generate_cbom_function(self):
        """generate_cbom convenience function should work"""
        json_str = generate_cbom(
            target="test.com",
            key_exchange_algorithms=["ECDHE"],
            certificate_algorithm="RSA-2048",
        )
        
        # Should be valid JSON
        parsed = json.loads(json_str)
        assert parsed["bomFormat"] == "CycloneDX"
    
    # ================================================================
    # CycloneDX Compliance Tests
    # ================================================================
    
    def test_component_has_bom_ref(self, builder):
        """Components should have bom-ref"""
        builder.add_algorithm("RSA-2048")
        cbom = builder.build()
        d = cbom.to_dict()
        
        assert "bom-ref" in d["components"][0]
    
    def test_primitive_is_valid(self, builder):
        """Primitive should be valid CycloneDX value"""
        builder.add_algorithm("RSA-2048")
        cbom = builder.build()
        d = cbom.to_dict()
        
        primitive = d["components"][0]["cryptoProperties"]["algorithmProperties"]["primitive"]
        valid_primitives = ["key-encapsulation", "key-agreement", "signature", "encryption", "hash", "mac", "unknown"]
        assert primitive in valid_primitives


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
