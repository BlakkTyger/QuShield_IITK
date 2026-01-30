"""
Asset Discovery Service

Discovers subdomains and assets using robust tools:
1. subfinder (Main robust passive discovery)
2. httpx (Main HTTP verifier tool)
3. Certificate Transparency logs via crt.sh (Fallback)
4. DNS enumeration & Brute-forcing (Fallback)
"""

import asyncio
import re
import os
import sys
import json
import tempfile
import shutil
from dataclasses import dataclass
from datetime import datetime
from typing import List, Set, Optional
import httpx

from qushield.utils.logging import get_logger

logger = get_logger("discovery")


@dataclass
class DiscoveredAsset:
    """A discovered asset/subdomain"""
    fqdn: str
    port: int = 443
    source: str = "ct_logs"
    discovered_at: datetime = None
    
    def __post_init__(self):
        if self.discovered_at is None:
            self.discovered_at = datetime.utcnow()


class AssetDiscovery:
    """
    Asset discovery service using multiple sources.
    
    Primary: subfinder + httpx (robust concurrent API & HTTP toolkit)
    Fallback: Certificate Transparency logs (crt.sh) + common subdomain enum
    """
    
    COMMON_SUBDOMAINS = [
        "www", "api", "app", "mobile", "m",
        "portal", "secure", "login", "auth", "sso",
        "admin", "mail", "email", "webmail",
        "vpn", "remote", "gateway",
        "payments", "pay", "checkout", "transaction",
        "netbanking", "ibanking", "onlinebanking", "ebanking",
        "corporate", "business", "retail",
        "cdn", "static", "assets", "img", "images",
        "dev", "staging", "test", "uat", "qa",
        "api-v1", "api-v2", "api-gateway",
        "ws", "websocket", "socket",
        "docs", "developer", "developers",
    ]
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
        
        # Tool Paths
        go_bin = os.path.expanduser("~/go/bin")
        self._nmap_bin = self._find_tool("nmap", ["/usr/bin/nmap", "/usr/local/bin/nmap", "/bin/nmap"])
        self._subfinder_bin = self._find_tool("subfinder", [os.path.join(go_bin, "subfinder")])
        self._httpx_bin = self._find_tool("httpx", [os.path.join(go_bin, "httpx")])
        
    def _find_tool(self, name: str, check_paths: List[str]) -> str:
        # Prioritize specific check_paths first to avoid python packages (e.g., Python httpx CLI) masking Go security tools
        for p in check_paths:
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p
                
        found = shutil.which(name)
        if found:
            return found
            
        return name
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client for slow fallbacks"""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                headers={"User-Agent": "QuShield/1.0 (PQC Scanner)"}
            )
        return self._client
    
    async def close(self):
        """Close HTTP client"""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            
    # ─────────────────────────────────────────────────────────────────
    # Robust Toolset Pipeline (subfinder + httpx)
    # ─────────────────────────────────────────────────────────────────
    
    async def discover_via_subfinder(self, domain_name: str) -> List[str]:
        """Runs subfinder to organically map out subdomains"""
        logger.info(f"Running subfinder for {domain_name}")
        subdomains = []

        if not os.path.isfile(self._subfinder_bin) and not shutil.which(self._subfinder_bin):
            logger.warning("subfinder not found — skipping robust subdomain enumeration.")
            return [domain_name]

        try:
            process = await asyncio.create_subprocess_exec(
                self._subfinder_bin, "-d", domain_name, "-silent",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60.0)
            
            subdomains = [
                line.strip()
                for line in stdout.decode().splitlines()
                if line.strip()
            ]
            logger.info(f"subfinder found {len(subdomains)} subdomains")
        except asyncio.TimeoutError:
            logger.warning("subfinder timed out.")
            try:
                process.kill()
            except Exception:
                pass
        except Exception as e:
            logger.error(f"subfinder failed: {e}")

        # Always include the root domain itself
        if domain_name not in subdomains:
            subdomains.append(domain_name)

        return subdomains

    async def discover_via_httpx(self, hosts: List[str]) -> List[DiscoveredAsset]:
        """Uses httpx to find live HTTPS/HTTP hosts rapidly"""
        logger.info(f"Probing {len(hosts)} hosts with httpx")
        live_assets = []
        if not hosts:
            return live_assets

        if not os.path.isfile(self._httpx_bin) and not shutil.which(self._httpx_bin):
            logger.warning("httpx not found — skipping high-speed live host filtering.")
            return live_assets

        # Prioritize root domain and important subdomains for earlier pipeline injection
        PRIORITY_PREFIXES = [
            "www", "api", "netbanking", "ibanking", "mobilebanking",
            "portal", "secure", "online", "app", "vpn", "gateway",
            "pay", "payment", "credit", "loan", "digital", "webapps",
            "pnbnet", "apps", "mypnb", "insurance", "creditcard",
        ]
        
        root_domain = [h for h in hosts if h == h.split(".", 1)[1] if "." in h] or [hosts[-1]]
        priority_hosts = [h for h in hosts if any(h.split(".")[0] == p for p in PRIORITY_PREFIXES)]
        other_hosts = [h for h in hosts if h not in priority_hosts and h not in root_domain]
        
        ordered_hosts = list(dict.fromkeys(root_domain + priority_hosts + other_hosts))

        fd, path = tempfile.mkstemp(suffix=".txt")
        try:
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(ordered_hosts))

            httpx_timeout = max(120, len(ordered_hosts) * 2)
            
            process = await asyncio.create_subprocess_exec(
                self._httpx_bin, "-l", path, "-silent", "-json", "-ports", "443,8443,80", "-ip", "-timeout", "4", "-t", "50",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=httpx_timeout)
                
                seen_targets = set()
                for line in stdout.decode().splitlines():
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        if "host" not in data:
                            continue

                        fqdn = data["host"]
                        port = int(data.get("port", 443))
                        
                        target_key = f"{fqdn}:{port}"
                        if target_key not in seen_targets:
                            seen_targets.add(target_key)
                            
                            asset = DiscoveredAsset(
                                fqdn=fqdn,
                                port=port,
                                source="httpx"
                            )
                            live_assets.append(asset)
                    except (json.JSONDecodeError, ValueError):
                        continue
                
                if process.returncode != 0 or not live_assets:
                    logger.warning(f"httpx returned code {process.returncode}. stderr: {stderr.decode().strip()}")
                        
                logger.info(f"httpx verified {len(live_assets)} live service(s)")
            except asyncio.TimeoutError:
                logger.warning("httpx timed out.")
                try:
                    process.kill()
                except Exception:
                    pass
            except Exception as e:
                logger.error(f"httpx failed: {e}")
        finally:
            try:
                os.remove(path)
            except OSError:
                pass

        return live_assets

    # ─────────────────────────────────────────────────────────────────
    # Legacy Discovery Pipeline (crt.sh)
    # ─────────────────────────────────────────────────────────────────
    
    async def discover_from_ct_logs(self, domain: str) -> List[DiscoveredAsset]:
        """Legacy fallback: Discover subdomains from CT logs"""
        client = await self._get_client()
        assets: Set[str] = set()
        
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = await client.get(url, timeout=15.0)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        assets.add(name.strip().lower())
        except (httpx.TimeoutException, Exception) as e:
            logger.warning(f"crt.sh failed ({type(e).__name__}), falling back to CertSpotter")
            
        if len(assets) < 5:
            try:
                url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
                response = await client.get(url, timeout=15.0)
                if response.status_code == 200:
                    data = response.json()
                    for entry in data:
                        for name in entry.get("dns_names", []):
                            assets.add(name.strip().lower())
            except Exception as e:
                logger.warning(f"CertSpotter fallback failed ({type(e).__name__})")
                
        valid_assets: Set[str] = set()
        for name in assets:
            if name.startswith("*."):
                name = name[2:]
            if (name.endswith(f".{domain}") or name == domain) and "*" not in name and self._is_valid_hostname(name):
                valid_assets.add(name)
                
        return [
            DiscoveredAsset(fqdn=fqdn, source="ct_logs")
            for fqdn in sorted(valid_assets)
        ]
    
    async def discover_common_subdomains(self, domain: str, check_dns: bool = True) -> List[DiscoveredAsset]:
        """Legacy fallback: Discover common subdomains"""
        assets = []
        for prefix in self.COMMON_SUBDOMAINS:
            fqdn = f"{prefix}.{domain}"
            if check_dns:
                if await self._check_dns(fqdn):
                    assets.append(DiscoveredAsset(fqdn=fqdn, source="subdomain_enum"))
            else:
                assets.append(DiscoveredAsset(fqdn=fqdn, source="subdomain_enum"))
        return assets
    
    async def _check_dns(self, hostname: str) -> bool:
        """Check if hostname resolves via DNS"""
        try:
            import socket
            loop = asyncio.get_event_loop()
            await loop.getaddrinfo(hostname, 443)
            return True
        except Exception:
            return False
    
    def _is_valid_hostname(self, hostname: str) -> bool:
        """Validate hostname format"""
        if not hostname or len(hostname) > 255:
            return False
        pattern = r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$'
        return bool(re.match(pattern, hostname.lower()))
    
    async def discover_all(
        self,
        domain: str,
        use_ct_logs: bool = True,
        use_subdomain_enum: bool = True,
        verify_dns: bool = False,
    ) -> List[DiscoveredAsset]:
        """
        Run discovery methods combining subfinder, httpx, and fallback mechanisms.
        """
        # 1. Primary High-Performance Path (Go Tools)
        subfinder_avail = os.path.isfile(self._subfinder_bin) or shutil.which(self._subfinder_bin)
        httpx_avail = os.path.isfile(self._httpx_bin) or shutil.which(self._httpx_bin)
        
        if subfinder_avail and httpx_avail:
            logger.info("Hardware tools found! Running high-performance discovery pipeline...")
            subdomains = await self.discover_via_subfinder(domain)
            live_assets = await self.discover_via_httpx(subdomains)
            
            if live_assets:
                # Add base domain if not present
                baseline_seen = any(a.fqdn == domain for a in live_assets)
                if not baseline_seen:
                    live_assets.insert(0, DiscoveredAsset(fqdn=domain, source="base_domain"))
                return live_assets
            else:
                logger.warning("High-performance discovery pipeline yielded empty results, trying static fallback.")

        # 2. Legacy Python Fallback Path (crt.sh)
        tasks = []
        if use_ct_logs:
            tasks.append(self.discover_from_ct_logs(domain))
        if use_subdomain_enum:
            tasks.append(self.discover_common_subdomains(domain, check_dns=verify_dns))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        seen_fqdns: Set[str] = set()
        unique_assets: List[DiscoveredAsset] = []
        
        for result in results:
            if isinstance(result, Exception):
                continue
            for asset in result:
                if asset.fqdn not in seen_fqdns:
                    seen_fqdns.add(asset.fqdn)
                    unique_assets.append(asset)
        
        if domain not in seen_fqdns:
            unique_assets.insert(0, DiscoveredAsset(fqdn=domain, source="base_domain"))
        
        return unique_assets


# Convenience functions
async def discover_subdomains(domain: str) -> List[DiscoveredAsset]:
    """Discover all subdomains for a domain"""
    discovery = AssetDiscovery()
    try:
        return await discovery.discover_all(domain)
    finally:
        await discovery.close()


async def discover_from_ct(domain: str) -> List[DiscoveredAsset]:
    """Discover subdomains from CT logs only"""
    discovery = AssetDiscovery()
    try:
        return await discovery.discover_from_ct_logs(domain)
    finally:
        await discovery.close()
