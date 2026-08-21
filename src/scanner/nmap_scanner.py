"""
Nmap scanner module for network discovery and service detection.
Provides comprehensive scanning capabilities using python-nmap.
"""

import subprocess
from datetime import datetime
from typing import Any, Dict, List

import nmap

from src.config import Config
from src.utils.logger import logger


class NmapScanner:
    """Handles all Nmap scanning operations."""

    def __init__(self, nmap_path: str | None = None):
        self.nmap_path = nmap_path or Config.NMAP_PATH
        self.scanner = nmap.PortScanner()
        self._verify_nmap()

    def _verify_nmap(self) -> None:
        """Verify Nmap installation."""
        try:
            subprocess.run(
                [self.nmap_path, "--version"],
                capture_output=True,
                check=True,
            )
            logger.info("Nmap verified successfully.")

        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            logger.error(f"Nmap verification failed: {e}")
            raise RuntimeError(
                "Nmap not found. Install Nmap or configure NMAP_PATH."
            )

    # ------------------------------------------------------------
    # Host Discovery
    # ------------------------------------------------------------
    def host_discovery(self, target: str) -> Dict[str, Any]:
        """Discover hosts on the target network."""

        logger.info(f"Discovering hosts on {target}")

        self.scanner.scan(
            hosts=target,
            arguments="-sn -v --host-timeout 30s",
            timeout=Config.SCAN_TIMEOUT,
        )

        hosts: List[Dict[str, Any]] = []

        for ip in self.scanner.all_hosts():

            host = self.scanner[ip]

            addresses = host.get("addresses", {})

            hosts.append(
                {
                    "ip_address": ip,
                    "status": host.state(),
                    "hostname": host.hostname() or "",
                    "mac_address": addresses.get("mac", ""),
                }
            )

        logger.info(f"Found {len(hosts)} hosts")

        return {
            "target": target,
            "timestamp": datetime.utcnow().isoformat(),
            "total_hosts": len(hosts),
            "hosts": hosts,
        }

    # ------------------------------------------------------------
    # Port Scan
    # ------------------------------------------------------------
    def port_scan(
        self,
        target: str,
        ports: str | None = None,
        scan_type: str = "quick",
    ) -> Dict[str, Any]:
        """Perform a port scan."""

        logger.info(f"Scanning {target}")

        if scan_type == "quick":
            ports = "22,23,25,53,80,443,3389,8080,3306,5432,27017"

        elif scan_type == "full":
            ports = "1-65535"

        elif ports is None:
            ports = "1-1000"

        self.scanner.scan(
            hosts=target,
            ports=ports,
            arguments=f"-sV -O -p {ports} --version-intensity 5 --host-timeout 60s",
            timeout=Config.SCAN_TIMEOUT,
        )

        if target not in self.scanner.all_hosts():
            return {
                "target": target,
                "error": "Host not reachable",
            }

        host = self.scanner[target]

        results: Dict[str, Any] = {
            "target": target,
            "timestamp": datetime.utcnow().isoformat(),
            "hostname": host.hostname() or "",
            "status": host.state(),
            "services": [],
            "os_name": "",
            "os_accuracy": 0,
        }

        # ---------------- OS Detection ----------------

        os_matches = host.get("osmatch", [])

        if os_matches:
            best_match = os_matches[0]
            results["os_name"] = best_match.get("name", "")
            results["os_accuracy"] = int(best_match.get("accuracy", 0))

        # ---------------- Services ----------------

        for proto in host.all_protocols():

            protocol = host.get(proto, {})

            for port in sorted(protocol.keys()):

                service = protocol.get(port, {})

                results["services"].append(
                    {
                        "port": port,
                        "protocol": proto,
                        "state": service.get("state", ""),
                        "service_name": service.get("name", ""),
                        "product": service.get("product", ""),
                        "service_version": service.get("version", ""),
                        "banner": service.get("extrainfo", ""),
                    }
                )

        logger.info(
            f"Found {len(results['services'])} services on {target}"
        )

        return results

    # ------------------------------------------------------------
    # Quick Scan
    # ------------------------------------------------------------
    def quick_scan(self, target: str) -> Dict[str, Any]:
        """Perform host discovery followed by port scanning."""

        discovery = self.host_discovery(target)

        results = {
            "target": target,
            "timestamp": datetime.utcnow().isoformat(),
            "hosts": [],
        }

        for host in discovery["hosts"]:

            if host["status"] != "up":
                results["hosts"].append(host)
                continue

            try:
                scan = self.port_scan(host["ip_address"])

                merged = {**host, **scan}

            except Exception as e:

                logger.error(e)

                merged = {
                    **host,
                    "error": str(e),
                }

            results["hosts"].append(merged)

        return results

    # ------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------
    def get_scan_statistics(self) -> Dict[str, int]:
        """Return statistics from the last scan."""

        stats = {
            "total_hosts": 0,
            "up_hosts": 0,
            "total_services": 0,
            "open_ports": 0,
        }

        try:

            hosts = self.scanner.all_hosts()

            stats["total_hosts"] = len(hosts)

            for host_ip in hosts:

                host = self.scanner[host_ip]

                if host.state() == "up":
                    stats["up_hosts"] += 1

                for proto in host.all_protocols():

                    protocol = host.get(proto, {})

                    stats["total_services"] += len(protocol)

                    for service in protocol.values():

                        if service.get("state") == "open":
                            stats["open_ports"] += 1

            return stats

        except Exception as e:

            logger.error(f"Statistics error: {e}")

            return stats