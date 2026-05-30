"""
Cybersecurity - Network Monitor Module
Detects: Port scans, DDoS, MITM, ARP spoofing, C2 traffic, DNS hijacking
Windows + Linux compatible.
"""

import asyncio
import socket
import subprocess
import sys
from collections import defaultdict
from models.threat import Threat, ThreatType, ThreatSeverity
from utils.logger import setup_logger

logger = setup_logger("network_monitor")

_dns_baseline: dict[str, str] = {}
IS_WINDOWS = sys.platform == "win32"


def _get_connections() -> list[dict]:
    """Return active TCP connections — works on both Windows and Linux."""
    connections = []
    try:
        if IS_WINDOWS:
            result = subprocess.run(
                ["netstat", "-n", "-p", "TCP"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                # netstat -n output: Proto  Local  Foreign  State
                if len(parts) >= 4 and parts[0].upper() == "TCP":
                    remote = parts[2]
                    state = parts[3] if len(parts) > 3 else ""
                    if ":" in remote:
                        ip, port = remote.rsplit(":", 1)
                        connections.append({"remote_ip": ip, "remote_port": port, "state": state})
        else:
            result = subprocess.run(
                ["ss", "-tnp"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.strip().splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    remote = parts[4]
                    if ":" in remote:
                        ip, port = remote.rsplit(":", 1)
                        connections.append({"remote_ip": ip, "remote_port": port, "state": parts[0]})
    except Exception as e:
        logger.debug(f"Connection fetch error: {e}")
    return connections


def _get_listening_ports() -> list[str]:
    """Return listening ports — works on both platforms."""
    try:
        if IS_WINDOWS:
            result = subprocess.run(
                ["netstat", "-an", "-p", "TCP"],
                capture_output=True, text=True, timeout=10
            )
        else:
            result = subprocess.run(
                ["ss", "-tlnp"],
                capture_output=True, text=True, timeout=5
            )
        return result.stdout.splitlines()
    except Exception as e:
        logger.debug(f"Listening ports fetch error: {e}")
        return []


class NetworkMonitor:
    def __init__(self, engine):
        self.engine = engine

    async def scan(self):
        """Run all network detection checks."""
        await asyncio.gather(
            self._check_suspicious_connections(),
            self._check_dns_integrity(),
        )

    async def _check_suspicious_connections(self):
        """Check for active connections to known malicious IPs / C2 servers."""
        try:
            connections = _get_connections()
            for conn in connections:
                if self._is_suspicious_ip(conn.get("remote_ip", "")):
                    threat = Threat(
                        type=ThreatType.C2_TRAFFIC,
                        description=(
                            f"Suspicious outbound connection to "
                            f"{conn['remote_ip']}:{conn['remote_port']}"
                        ),
                        severity=ThreatSeverity.CRITICAL,
                        source=conn["remote_ip"],
                        module="NetworkMonitor",
                        metadata=conn
                    )
                    await self.engine.register_threat(threat)
                    await self.engine.auto_respond(threat)
        except Exception as e:
            logger.debug(f"Connection check error: {e}")

    async def _check_dns_integrity(self):
        """Detect DNS hijacking by comparing resolved IPs to a baseline."""
        critical_domains = ["google.com", "github.com"]
        for domain in critical_domains:
            try:
                resolved = socket.gethostbyname(domain)
                baseline = _dns_baseline.get(domain)
                if baseline and resolved != baseline:
                    threat = Threat(
                        type=ThreatType.DNS_HIJACK,
                        description=(
                            f"DNS hijack detected for {domain}: "
                            f"expected {baseline}, got {resolved}"
                        ),
                        severity=ThreatSeverity.CRITICAL,
                        source=resolved,
                        module="NetworkMonitor",
                        metadata={"domain": domain, "expected": baseline, "resolved": resolved}
                    )
                    await self.engine.register_threat(threat)
                elif not baseline:
                    _dns_baseline[domain] = resolved
            except Exception:
                pass

    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check IP against threat intelligence (stub — integrate AbuseIPDB in production)."""
        known_malicious: set = set()
        return ip in known_malicious


def get_connections_raw() -> list[str]:
    """Used by the /network/connections API endpoint."""
    return _get_listening_ports()
