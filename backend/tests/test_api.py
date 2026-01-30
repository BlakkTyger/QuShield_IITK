#!/usr/bin/env python3
"""
QuShield API Test Script

Tests all API endpoints without requiring a frontend.
Run: python -m tests.test_api
"""

import httpx
import time
import json
from typing import Optional

BASE_URL = "http://localhost:8000/api/v1"


class QuShieldAPITester:
    """API testing client."""
    
    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url
        self.client = httpx.Client(timeout=60.0)
        self.token: Optional[str] = None
        self.user_email = f"test_{int(time.time())}@example.com"
        self.user_password = "TestPass123!"
    
    def _headers(self) -> dict:
        """Get headers with auth token."""
        if self.token:
            return {"Authorization": f"Bearer {self.token}"}
        return {}
    
    def _print_response(self, name: str, resp: httpx.Response):
        """Print formatted response."""
        status = "✅" if resp.status_code < 400 else "❌"
        print(f"{status} {name}: {resp.status_code}")
        if resp.status_code >= 400:
            print(f"   Error: {resp.text[:200]}")
    
    # ========== Authentication ==========
    
    def test_register(self) -> bool:
        """Test user registration."""
        resp = self.client.post(
            f"{self.base_url}/auth/register",
            json={
                "email": self.user_email,
                "password": self.user_password,
                "full_name": "Test User"
            }
        )
        self._print_response("POST /auth/register", resp)
        return resp.status_code == 201
    
    def test_login(self) -> bool:
        """Test user login."""
        resp = self.client.post(
            f"{self.base_url}/auth/login",
            data={
                "username": self.user_email,
                "password": self.user_password
            }
        )
        self._print_response("POST /auth/login", resp)
        if resp.status_code == 200:
            self.token = resp.json()["access_token"]
            return True
        return False
    
    def test_get_me(self) -> bool:
        """Test get current user."""
        resp = self.client.get(
            f"{self.base_url}/auth/me",
            headers=self._headers()
        )
        self._print_response("GET /auth/me", resp)
        return resp.status_code == 200
    
    # ========== Scans ==========
    
    def test_trigger_scan(self, domain: str = "example.com") -> Optional[str]:
        """Test triggering a scan."""
        resp = self.client.post(
            f"{self.base_url}/scans/trigger",
            json={"domain": domain, "max_assets": 5},
            headers=self._headers()
        )
        self._print_response("POST /scans/trigger", resp)
        if resp.status_code == 202:
            return resp.json()["id"]
        return None
    
    def test_list_scans(self) -> bool:
        """Test listing scans."""
        resp = self.client.get(
            f"{self.base_url}/scans",
            headers=self._headers()
        )
        self._print_response("GET /scans", resp)
        return resp.status_code == 200
    
    def test_get_scan_status(self, scan_id: str) -> str:
        """Test getting scan status."""
        resp = self.client.get(
            f"{self.base_url}/scans/{scan_id}/status",
            headers=self._headers()
        )
        self._print_response("GET /scans/{id}/status", resp)
        if resp.status_code == 200:
            return resp.json()["status"]
        return "unknown"
    
    def wait_for_scan(self, scan_id: str, timeout: int = 120) -> bool:
        """Wait for scan to complete."""
        print(f"⏳ Waiting for scan {scan_id[:8]}... to complete")
        start = time.time()
        while time.time() - start < timeout:
            status = self.test_get_scan_status(scan_id)
            if status == "completed":
                print(f"✅ Scan completed!")
                return True
            elif status == "failed":
                print(f"❌ Scan failed!")
                return False
            time.sleep(5)
        print(f"⏰ Scan timeout!")
        return False
    
    # ========== Dashboard ==========
    
    def test_dashboard_metrics(self) -> bool:
        """Test dashboard metrics."""
        resp = self.client.get(
            f"{self.base_url}/dashboard/metrics",
            headers=self._headers()
        )
        self._print_response("GET /dashboard/metrics", resp)
        return resp.status_code == 200
    
    def test_risk_distribution(self) -> bool:
        """Test risk distribution."""
        resp = self.client.get(
            f"{self.base_url}/dashboard/risk-distribution",
            headers=self._headers()
        )
        self._print_response("GET /dashboard/risk-distribution", resp)
        return resp.status_code == 200
    
    # ========== Assets ==========
    
    def test_list_assets(self) -> bool:
        """Test listing assets."""
        resp = self.client.get(
            f"{self.base_url}/assets",
            headers=self._headers()
        )
        self._print_response("GET /assets", resp)
        return resp.status_code == 200
    
    # ========== Discovery ==========
    
    def test_discovery_summary(self) -> bool:
        """Test discovery summary."""
        resp = self.client.get(
            f"{self.base_url}/discovery/summary",
            headers=self._headers()
        )
        self._print_response("GET /discovery/summary", resp)
        return resp.status_code == 200
    
    def test_discovery_graph(self) -> bool:
        """Test discovery graph."""
        resp = self.client.get(
            f"{self.base_url}/discovery/graph",
            headers=self._headers()
        )
        self._print_response("GET /discovery/graph", resp)
        return resp.status_code == 200
    
    # ========== CBOM ==========
    
    def test_cbom_metrics(self) -> bool:
        """Test CBOM metrics."""
        resp = self.client.get(
            f"{self.base_url}/cbom/metrics",
            headers=self._headers()
        )
        self._print_response("GET /cbom/metrics", resp)
        return resp.status_code == 200
    
    def test_cbom_export(self) -> bool:
        """Test CBOM export."""
        resp = self.client.get(
            f"{self.base_url}/cbom/export",
            headers=self._headers()
        )
        self._print_response("GET /cbom/export", resp)
        return resp.status_code in [200, 404]  # 404 if no scan
    
    # ========== Posture ==========
    
    def test_posture_summary(self) -> bool:
        """Test posture summary."""
        resp = self.client.get(
            f"{self.base_url}/posture/summary",
            headers=self._headers()
        )
        self._print_response("GET /posture/summary", resp)
        return resp.status_code == 200
    
    def test_posture_recommendations(self) -> bool:
        """Test posture recommendations."""
        resp = self.client.get(
            f"{self.base_url}/posture/recommendations",
            headers=self._headers()
        )
        self._print_response("GET /posture/recommendations", resp)
        return resp.status_code == 200
    
    # ========== Rating ==========
    
    def test_enterprise_rating(self) -> bool:
        """Test enterprise rating."""
        resp = self.client.get(
            f"{self.base_url}/rating/enterprise",
            headers=self._headers()
        )
        self._print_response("GET /rating/enterprise", resp)
        return resp.status_code == 200
    
    def test_asset_ratings(self) -> bool:
        """Test asset ratings."""
        resp = self.client.get(
            f"{self.base_url}/rating/assets",
            headers=self._headers()
        )
        self._print_response("GET /rating/assets", resp)
        return resp.status_code == 200
    
    # ========== Run All Tests ==========
    
    def run_auth_tests(self):
        """Run authentication tests."""
        print("\n" + "=" * 50)
        print("🔐 AUTHENTICATION TESTS")
        print("=" * 50)
        self.test_register()
        self.test_login()
        self.test_get_me()
    
    def run_endpoint_tests(self):
        """Run all endpoint tests."""
        print("\n" + "=" * 50)
        print("📊 ENDPOINT TESTS (without scan)")
        print("=" * 50)
        self.test_list_scans()
        self.test_dashboard_metrics()
        self.test_risk_distribution()
        self.test_list_assets()
        self.test_discovery_summary()
        self.test_discovery_graph()
        self.test_cbom_metrics()
        self.test_posture_summary()
        self.test_posture_recommendations()
        self.test_enterprise_rating()
        self.test_asset_ratings()
    
    def run_full_workflow(self, domain: str = "example.com"):
        """Run full workflow test with actual scan."""
        print("\n" + "=" * 50)
        print(f"🚀 FULL WORKFLOW TEST: {domain}")
        print("=" * 50)
        
        scan_id = self.test_trigger_scan(domain)
        if scan_id:
            if self.wait_for_scan(scan_id):
                print("\n📈 Testing endpoints with scan data...")
                self.test_dashboard_metrics()
                self.test_risk_distribution()
                self.test_list_assets()
                self.test_discovery_summary()
                self.test_discovery_graph()
                self.test_cbom_metrics()
                self.test_cbom_export()
                self.test_posture_summary()
                self.test_posture_recommendations()
                self.test_enterprise_rating()
                self.test_asset_ratings()


def main():
    """Run API tests."""
    print("\n" + "=" * 60)
    print("       QuShield API Test Suite")
    print("=" * 60)
    
    tester = QuShieldAPITester()
    
    # Run tests
    tester.run_auth_tests()
    tester.run_endpoint_tests()
    
    # Optionally run full workflow
    # tester.run_full_workflow("pnbindia.in")
    
    print("\n" + "=" * 60)
    print("       Tests Complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
