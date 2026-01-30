import subprocess
import json
import logging
import sys
import os
import tempfile
import shutil
from typing import List

def _find_tool(name: str, check_paths: List[str]) -> str:
    found = shutil.which(name)
    if found:
        return found
    for p in check_paths:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return name

_NMAP_BIN = _find_tool("nmap", ["/usr/bin/nmap", "/usr/local/bin/nmap", "/bin/nmap"])
_GO_BIN = os.path.expanduser("~/go/bin")
_SUBFINDER_BIN = _find_tool("subfinder", [os.path.join(_GO_BIN, "subfinder")])
_HTTPX_BIN = _find_tool("httpx", [os.path.join(_GO_BIN, "httpx")])

from models.asset import Asset
from models.enums import ProtocolEnum, ServiceTypeEnum, ScanStatusEnum

logger = logging.getLogger(__name__)


class DiscoveryService:
    def __init__(self, db_session):
        self.db = db_session

    def discover_subdomains(self, domain_name: str, domain_id: int) -> List[str]:
        """Runs subfinder to discover subdomains. Falls back gracefully."""
        logger.info(f"Running subfinder for {domain_name}")
        subdomains = []

        try:
            result = subprocess.run(
                [_SUBFINDER_BIN, "-d", domain_name, "-silent"],
                capture_output=True, text=True, check=True, timeout=60
            )
            subdomains = [
                line.strip()
                for line in result.stdout.splitlines()
                if line.strip()
            ]
            logger.info(f"subfinder found {len(subdomains)} subdomains")
        except FileNotFoundError:
            logger.warning("subfinder not found — skipping subdomain enumeration.")
        except subprocess.TimeoutExpired:
            logger.warning("subfinder timed out.")
        except Exception as e:
            logger.error(f"subfinder failed: {e}")

        # Always include the root domain itself
        if domain_name not in subdomains:
            subdomains.append(domain_name)

        return subdomains

    def filter_live_hosts(self, hosts: List[str]) -> List[dict]:
        """
        Uses httpx to find live HTTPS/HTTP hosts.
        """
        logger.info(f"Probing {len(hosts)} hosts with httpx")
        live_hosts = []
        if not hosts:
            return live_hosts


        PRIORITY_PREFIXES = [
            "www", "api", "netbanking", "ibanking", "mobilebanking",
            "portal", "secure", "online", "app", "vpn", "gateway",
            "pay", "payment", "credit", "loan", "digital", "webapps",
            "pnbnet", "apps", "mypnb", "insurance", "creditcard",
        ]
        # Root domain first (e.g. pnb.bank.in itself)
        root_domain = [h for h in hosts if h == h.split(".", 1)[1]
                       if "." in h] or [hosts[-1]]  # fallback to last entry
        # Exact priority subdomain matches
        priority_hosts = [
            h for h in hosts
            if any(h.split(".")[0] == p for p in PRIORITY_PREFIXES)
        ]
        other_hosts = [
            h for h in hosts
            if h not in priority_hosts and h not in root_domain
        ]
        # root first → priority → others
        ordered_hosts = list(dict.fromkeys(
            root_domain + priority_hosts + other_hosts
        ))
        logger.info(
            f"Probing {len(ordered_hosts)} hosts: "
            f"{ordered_hosts}"
        )

        fd, path = tempfile.mkstemp(suffix=".txt")
        try:
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(ordered_hosts))

            httpx_timeout = max(120, len(ordered_hosts) * 5)
            seen_targets: dict = {}
            print(f"[*] Probing {len(ordered_hosts)} hosts with httpx. This may take up to {httpx_timeout}s...")

            process = subprocess.Popen(
                [
                    _HTTPX_BIN,
                    "-l", path,
                    "-silent",
                    "-json",
                    "-ports", "443,8443,80",
                    "-ip",
                    "-timeout", "5",
                    "-t", "10",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            
            for line in process.stdout:
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
                        seen_targets[target_key] = data
                        sys.stdout.write(f"  [+] Found live: {target_key}\n")
                        sys.stdout.flush()

                except (json.JSONDecodeError, ValueError):
                    pass

            process.wait()

            live_hosts = list(seen_targets.values())
            logger.info(f"httpx found {len(live_hosts)} live service(s)")

        except FileNotFoundError:
            logger.warning("httpx not found — skipping live host filtering.")
        except subprocess.TimeoutExpired:
            logger.warning("httpx timed out.")
        except Exception as e:
            logger.error(f"httpx failed: {e}")
        finally:
            try:
                os.remove(path)
            except OSError:
                pass

        return live_hosts

    def scan_ports(self, target: str) -> List[dict]:
        """Quick nmap scan for HTTPS and VPN ports on a given IP/hostname."""
        logger.info(f"Running nmap on {target}")
        open_services = []

        try:
            result = subprocess.run(
                [
                    _NMAP_BIN, "-sS", "-sU",
                    "-p", "T:443,8443,U:500,4500",
                    "--open", "-oX", "-", target
                ],
                capture_output=True, text=True,
                check=False, timeout=120
            )
            output = result.stdout

            PORT_MAP = {
                '443':  (ProtocolEnum.tcp, ServiceTypeEnum.HTTPS),
                '8443': (ProtocolEnum.tcp, ServiceTypeEnum.HTTPS),
                '500':  (ProtocolEnum.udp, ServiceTypeEnum.VPN_IPSEC),
                '4500': (ProtocolEnum.udp, ServiceTypeEnum.VPN_IPSEC),
            }

            for portid, (proto, svc_type) in PORT_MAP.items():
                if f'portid="{portid}"' in output and 'state="open"' in output:
                    open_services.append({
                        "port":     int(portid),
                        "protocol": proto,
                        "type":     svc_type,
                    })

        except FileNotFoundError:
            logger.warning("nmap not found — skipping port scan.")
        except subprocess.TimeoutExpired:
            logger.warning(f"nmap timed out for {target}.")
        except Exception as e:
            logger.error(f"nmap scan failed for {target}: {e}")

        return open_services

    # ──────────────────────────────────────────────────────────────────────
    def run_discovery_pipeline(self, domain_name: str, domain_id: int):
        """Full Phase 1 pipeline — subdomain enum → live check → VPN scan."""

        hosts = self.discover_subdomains(domain_name, domain_id)
        logger.info(f"Total hosts to probe: {len(hosts)}")

        live_httpx_results = self.filter_live_hosts(hosts)
        logger.info(f"Live httpx results: {len(live_httpx_results)}")

        seen_targets: set = set()

        for data in live_httpx_results:
            if not isinstance(data, dict):
                continue

            fqdn = data.get("host", domain_name)
            port = int(data.get("port", 443))

            ip = data.get("host_ip") or data.get("ip", "")

            if port == 80:
                logger.info(f"Overriding port 80 → 443 for {fqdn}")
                port = 443

            target_key = f"{fqdn}:{port}"
            if target_key in seen_targets:
                continue

            scheme = data.get("scheme", "https")
            svc_type = ServiceTypeEnum.HTTPS if scheme in ("https", "http") \
                       else ServiceTypeEnum.UNKNOWN

            tech = data.get("tech", [])
            title = data.get("title", "").lower()
            if any(t in str(tech).lower() for t in
                   ["globalprotect", "anyconnect", "big-ip", "fortinet"]):
                svc_type = ServiceTypeEnum.VPN_IPSEC

            asset = Asset(
                domain_id=domain_id,
                fqdn=fqdn,
                ip=ip,
                port=port,
                protocol=ProtocolEnum.tcp,
                service_type=svc_type,
                scan_status=ScanStatusEnum.PENDING,
                discovery_sources={"tool": "httpx", "title": data.get("title", "")}
            )
            self.db.add(asset)
            seen_targets.add(target_key)
            logger.info(f"Asset added: {fqdn}:{port} ({svc_type})")

        unique_ips = set(
            data.get("host_ip") or data.get("ip")
            for data in live_httpx_results
            if isinstance(data, dict) and (data.get("host_ip") or data.get("ip"))
        )

        for ip in unique_ips:
            if not ip:
                continue
            services = self.scan_ports(ip)
            for s in services:
                if s["type"] == ServiceTypeEnum.VPN_IPSEC:
                    target_key = f"{ip}:{s['port']}"
                    if target_key in seen_targets:
                        continue
                    asset = Asset(
                        domain_id=domain_id,
                        fqdn=ip,
                        ip=ip,
                        port=s["port"],
                        protocol=s["protocol"],
                        service_type=s["type"],
                        scan_status=ScanStatusEnum.PENDING,
                        discovery_sources={"tool": "nmap"}
                    )
                    self.db.add(asset)
                    seen_targets.add(target_key)
                    logger.info(f"VPN asset added: {ip}:{s['port']}")

        self.db.commit()
        logger.info(
            f"Phase 1 complete for {domain_name} — "
            f"{len(seen_targets)} asset(s) saved."
        )