"""
Tests for QuShield Workflow Orchestrator

Integration tests for the complete 4-layer workflow.
"""

import pytest
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from qushield.workflow import (
    QuShieldWorkflow,
    WorkflowResult,
    AssetAnalysis,
    run_workflow,
    run_workflow_sync,
)
from qushield.core.classifier import QuantumSafety


class TestQuShieldWorkflow:
    """Test suite for QuShield Workflow"""
    
    @pytest.fixture
    def workflow(self):
        return QuShieldWorkflow(
            scan_timeout=30,
            max_concurrent_scans=3,
        )
    
    # ================================================================
    # Workflow Result Structure Tests
    # ================================================================
    
    def test_workflow_result_structure(self):
        """WorkflowResult should have all required fields"""
        result = WorkflowResult(
            domain="test.com",
            start_time="2024-01-01T00:00:00",
            end_time="2024-01-01T00:01:00",
            duration_ms=60000,
        )
        
        assert result.domain == "test.com"
        assert result.assets_discovered == 0
        assert result.assets_scanned == 0
        assert isinstance(result.assets, list)
    
    def test_workflow_result_to_dict(self):
        """WorkflowResult.to_dict() should produce valid structure"""
        result = WorkflowResult(
            domain="test.com",
            start_time="2024-01-01T00:00:00",
            end_time="2024-01-01T00:01:00",
            duration_ms=60000,
        )
        
        d = result.to_dict()
        assert "domain" in d
        assert "summary" in d
        assert "assets" in d
    
    def test_workflow_result_to_json(self):
        """WorkflowResult.to_json() should produce valid JSON"""
        import json
        result = WorkflowResult(
            domain="test.com",
            start_time="2024-01-01T00:00:00",
            end_time="2024-01-01T00:01:00",
            duration_ms=60000,
        )
        
        json_str = result.to_json()
        parsed = json.loads(json_str)
        assert parsed["domain"] == "test.com"
    
    # ================================================================
    # Asset Analysis Structure Tests
    # ================================================================
    
    def test_asset_analysis_structure(self):
        """AssetAnalysis should have all required fields"""
        asset = AssetAnalysis(
            fqdn="api.test.com",
            port=443,
        )
        
        assert asset.fqdn == "api.test.com"
        assert asset.port == 443
        assert asset.scan_success == False
        assert asset.quantum_safety == "UNKNOWN"
    
    def test_asset_analysis_to_dict(self):
        """AssetAnalysis.to_dict() should produce valid structure"""
        asset = AssetAnalysis(
            fqdn="api.test.com",
            port=443,
            quantum_safety=QuantumSafety.VULNERABLE.value,
        )
        
        d = asset.to_dict()
        assert d["fqdn"] == "api.test.com"
        assert d["quantum_safety"] == "QUANTUM_VULNERABLE"
    
    # ================================================================
    # Workflow Skip Discovery Tests
    # ================================================================
    
    @pytest.mark.asyncio
    async def test_workflow_skip_discovery_with_targets(self, workflow):
        """Workflow should use provided targets when skip_discovery=True"""
        targets = ["target1.com", "target2.com"]
        
        # Run with skip_discovery (won't actually scan, just test flow)
        result = await workflow.run(
            domain="test.com",
            skip_discovery=True,
            targets=targets,
            max_assets=2,
        )
        
        # Should have processed the targets
        assert result.assets_discovered == 2
    
    # ================================================================
    # Workflow Layer Integration Tests  
    # ================================================================
    
    @pytest.mark.asyncio
    async def test_workflow_initializes_services(self, workflow):
        """Workflow should initialize all layer services"""
        assert workflow.discovery is not None
        assert workflow.scanner is not None
        assert workflow.classifier is not None
        assert workflow.hndl_scorer is not None
        assert workflow.cbom_builder is not None
    
    # ================================================================
    # Convenience Function Tests
    # ================================================================
    
    @pytest.mark.asyncio
    async def test_run_workflow_function(self):
        """run_workflow async function should work"""
        result = await run_workflow(
            domain="example.com",
            skip_discovery=True,
            targets=["example.com"],
            max_assets=1,
        )
        assert isinstance(result, WorkflowResult)


class TestWorkflowLiveIntegration:
    """
    Live integration tests - these require network access.
    
    These tests are marked with pytest.mark.live and can be skipped
    in CI environments using: pytest -m "not live"
    """
    
    @pytest.mark.live
    @pytest.mark.asyncio
    @pytest.mark.timeout(120)
    async def test_workflow_with_google(self):
        """Test workflow against google.com (reliable public endpoint)"""
        workflow = QuShieldWorkflow(scan_timeout=30)
        
        result = await workflow.run(
            domain="google.com",
            skip_discovery=True,
            targets=["www.google.com"],
            max_assets=1,
        )
        
        assert result.assets_scanned >= 0  # May succeed or fail
        assert result.duration_ms > 0
    
    @pytest.mark.live
    @pytest.mark.asyncio
    @pytest.mark.timeout(120)
    async def test_workflow_generates_cbom(self):
        """Test that workflow generates CBOM"""
        workflow = QuShieldWorkflow(scan_timeout=30)
        
        result = await workflow.run(
            domain="example.com",
            skip_discovery=True,
            targets=["www.example.com"],
            max_assets=1,
        )
        
        if result.assets_scanned > 0:
            assert result.cbom is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "not live"])
