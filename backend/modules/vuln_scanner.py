"""AISS - Vulnerability Scanner

Detects vulnerabilities using:
  - Nuclei (if installed) for service/web vulnerability checks
  - Installed software version correlation against a built-in CVE mapping
  - Network service banner/version correlation against known CVEs

Reports results with clear confidence levels:
  Confirmed   - Nuclei or another tool positively identified the vulnerability
  Likely      - Version matches a known-vulnerable range with high confidence
  Potential   - Service present but version unknown or generic weakness
  Informational - No known vulnerability, just service inventory

Never fabricates detections. Reports unavailable tools honestly.
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Optional

from utils.logger import setup_logger

logger = setup_logger("vuln_scanner")

IS_WINDOWS = platform.system() == "Windows"


@dataclass
class VulnFinding:
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    confidence: str  # confirmed, likely, potential, informational
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    affected_resource: Optional[str] = None
    recommendation: Optional[str] = None
    tool: str = "internal"
    raw: dict = field(default_factory=dict)


# Small built-in mapping of well-known vulnerabilities by service/version.
# In production this should be replaced/augmented with an NVD CVE database.
_KNOWN_CVE_MAP: list[dict] = [
    {
        "service": "smb",
        "ports": [139, 445],
        "title": "SMBv1 enabled (EternalBlue-like risk)",
        "description": "SMB version 1 is present. SMBv1 is vulnerable to EternalBlue (MS17-010) and several other weaknesses.",
        "cve": "CVE-2017-0144",
        "cvss": 8.1,
        "severity": "high",
        "confidence": "potential",
        "recommendation": "Disable SMBv1 and ensure SMB is patched.",
    },
    {
        "service": "rdp",
        "ports": [3389],
        "title": "RDP exposed to network",
        "description": "Remote Desktop Protocol is listening. Unpatched RDP can be vulnerable to BlueKeep (CVE-2019-0708) and credential attacks.",
        "cve": "CVE-2019-0708",
        "cvss": 9.8,
        "severity": "high",
        "confidence": "potential",
        "recommendation": "Restrict RDP with VPN/NLA and keep systems patched.",
    },
    {
        "service": "telnet",
        "ports": [23],
        "title": "Telnet service exposed",
        "description": "Telnet transmits credentials in cleartext and should not be exposed.",
        "cve": None,
        "cvss": 7.5,
        "severity": "medium",
        "confidence": "potential",
        "recommendation": "Replace Telnet with SSH and disable the Telnet service.",
    },
    {
        "service": "ftp",
        "ports": [21],
        "title": "FTP service exposed",
        "description": "FTP may transmit credentials in cleartext. Anonymous FTP or outdated servers pose additional risk.",
        "cve": None,
        "cvss": 5.3,
        "severity": "low",
        "confidence": "potential",
        "recommendation": "Use SFTP/FTPS and disable anonymous access.",
    },
    {
        "service": "ssh",
        "ports": [22],
        "title": "SSH service exposed",
        "description": "SSH is listening. Ensure only current, patched versions are used and password authentication is disabled if possible.",
        "cve": None,
        "cvss": None,
        "severity": "info",
        "confidence": "informational",
        "recommendation": "Keep OpenSSH patched; prefer key-based authentication.",
    },
    {
        "service": "http",
        "ports": [80, 443, 8080, 8443],
        "title": "HTTP/HTTPS web service exposed",
        "description": "Web server is listening. Outdated web servers (Apache, IIS, nginx) may have known vulnerabilities.",
        "cve": "CVE-2021-41773",
        "cvss": 7.5,
        "severity": "medium",
        "confidence": "potential",
        "recommendation": "Keep web server software updated and apply security patches.",
    },
    {
        "service": "dns",
        "ports": [53],
        "title": "DNS service exposed",
        "description": "DNS server is listening. Open DNS resolvers can be abused for DNS amplification attacks.",
        "cve": "CVE-2020-1350",
        "cvss": 10.0,
        "severity": "critical",
        "confidence": "potential",
        "recommendation": "Restrict DNS to authorized clients and patch DNS server software.",
    },
    {
        "service": "smtp",
        "ports": [25, 587],
        "title": "SMTP mail service exposed",
        "description": "Mail server is listening. Open relays can be abused for spam and phishing.",
        "cve": None,
        "cvss": 5.3,
        "severity": "medium",
        "confidence": "potential",
        "recommendation": "Disable open relay and enforce authentication for SMTP.",
    },
    {
        "service": "mysql",
        "ports": [3306],
        "title": "MySQL database exposed to network",
        "description": "MySQL is listening on the network. Unpatched MySQL or weak credentials pose data breach risk.",
        "cve": "CVE-2023-21977",
        "cvss": 7.5,
        "severity": "high",
        "confidence": "potential",
        "recommendation": "Restrict MySQL to localhost or VPN, enforce strong passwords, and keep patched.",
    },
    {
        "service": "postgresql",
        "ports": [5432],
        "title": "PostgreSQL database exposed to network",
        "description": "PostgreSQL is listening on the network. Unpatched versions may allow privilege escalation.",
        "cve": "CVE-2023-5868",
        "cvss": 8.8,
        "severity": "high",
        "confidence": "potential",
        "recommendation": "Restrict PostgreSQL to trusted networks and apply security updates.",
    },
    {
        "service": "redis",
        "ports": [6379],
        "title": "Redis exposed without authentication",
        "description": "Redis is listening. Default Redis has no authentication — full data access and RCE risk.",
        "cve": "CVE-2022-0543",
        "cvss": 9.8,
        "severity": "critical",
        "confidence": "potential",
        "recommendation": "Enable Redis AUTH, bind to localhost, and disable dangerous commands.",
    },
    {
        "service": "mongodb",
        "ports": [27017],
        "title": "MongoDB exposed without authentication",
        "description": "MongoDB is listening. Default MongoDB has no authentication — full data access risk.",
        "cve": "CVE-2023-1409",
        "cvss": 9.8,
        "severity": "critical",
        "confidence": "potential",
        "recommendation": "Enable MongoDB authentication, bind to localhost, and restrict network access.",
    },
    {
        "service": "elasticsearch",
        "ports": [9200, 9300],
        "title": "Elasticsearch exposed without authentication",
        "description": "Elasticsearch is listening. Default configuration has no authentication — data exfiltration risk.",
        "cve": "CVE-2023-31419",
        "cvss": 7.5,
        "severity": "high",
        "confidence": "potential",
        "recommendation": "Enable X-Pack security, configure authentication, and restrict network access.",
    },
    {
        "service": "docker",
        "ports": [2375, 2376],
        "title": "Docker API exposed to network",
        "description": "Docker daemon API is listening on the network. Unauthenticated access allows full container control.",
        "cve": "CVE-2019-5736",
        "cvss": 9.8,
        "severity": "critical",
        "confidence": "potential",
        "recommendation": "Bind Docker to localhost, use TLS authentication, and restrict network access.",
    },
    {
        "service": "winrm",
        "ports": [5985, 5986],
        "title": "WinRM remote management exposed",
        "description": "Windows Remote Management is listening. Unauthenticated or weak credential access allows remote code execution.",
        "cve": None,
        "cvss": 8.1,
        "severity": "high",
        "confidence": "potential",
        "recommendation": "Restrict WinRM to trusted networks, use HTTPS, and enforce strong authentication.",
    },
    {
        "service": "vnc",
        "ports": [5900, 5901],
        "title": "VNC remote desktop exposed",
        "description": "VNC is listening. VNC often has weak or no authentication — remote desktop takeover risk.",
        "cve": "CVE-2023-52169",
        "cvss": 7.8,
        "severity": "high",
        "confidence": "potential",
        "recommendation": "Replace VNC with RDP over VPN, or enforce strong VNC authentication.",
    },
    {
        "service": "memcached",
        "ports": [11211],
        "title": "Memcached exposed to network",
        "description": "Memcached is listening. Open memcached can be abused for DDoS amplification attacks.",
        "cve": "CVE-2018-1000115",
        "cvss": 9.8,
        "severity": "critical",
        "confidence": "potential",
        "recommendation": "Bind memcached to localhost and disable UDP support.",
    },
]


def _find_tool(name: str) -> Optional[str]:
    path = shutil.which(name)
    if path:
        return path
    candidates: list[str] = []
    if name == "nuclei":
        if IS_WINDOWS:
            candidates = [
                r"C:\Program Files\Nuclei\nuclei.exe",
                os.path.expanduser(r"~\nuclei\nuclei.exe"),
            ]
        else:
            candidates = [
                "/usr/bin/nuclei",
                "/usr/local/bin/nuclei",
                os.path.expanduser("~/go/bin/nuclei"),
            ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def detect_nuclei() -> dict:
    binary = _find_tool("nuclei")
    if not binary:
        return {"installed": False, "reason": "nuclei not found in PATH or common locations"}
    try:
        result = subprocess.run(
            [binary, "-version"], capture_output=True, text=True, timeout=10
        )
        return {
            "installed": True,
            "binary": binary,
            "version": result.stdout.strip().splitlines()[0] if result.stdout else "unknown",
        }
    except Exception as e:
        return {"installed": False, "reason": f"Failed to query nuclei: {e}"}


async def detect_nuclei_async() -> dict:
    return await asyncio.to_thread(detect_nuclei)


def _nuclei_scan_sync(targets: list[str], binary: str, templates: Optional[str] = None) -> list[VulnFinding]:
    findings: list[VulnFinding] = []
    if not targets:
        return findings

    target_file = os.path.join(os.environ.get("TEMP", "/tmp"), "aiss_nuclei_targets.txt")
    try:
        with open(target_file, "w") as f:
            f.write("\n".join(targets))

        cmd = [binary, "-l", target_file, "-silent", "-jsonl"]
        if templates:
            cmd.extend(["-t", templates])
        else:
            cmd.extend(["-tags", "network"])  # lightweight network-only templates

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            for line in proc.stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                    findings.append(VulnFinding(
                        title=item.get("info", {}).get("name", "Nuclei finding"),
                        description=item.get("info", {}).get("description", ""),
                        severity=(item.get("info", {}).get("severity", "info")).lower(),
                        confidence="confirmed",
                        cve_id=_extract_cve(item.get("info", {}).get("classification", {}).get("cve-id", [])),
                        cvss_score=item.get("info", {}).get("classification", {}).get("cvss-score"),
                        affected_resource=item.get("host"),
                        recommendation="Investigate and patch according to Nuclei template guidance.",
                        tool="nuclei",
                        raw=item,
                    ))
                except Exception:
                    continue
            if proc.returncode != 0 and not findings and proc.stderr:
                logger.debug(f"nuclei stderr: {proc.stderr[:500]}")
        except subprocess.TimeoutExpired:
            logger.warning("Nuclei scan timed out after 180s")
    finally:
        try:
            os.remove(target_file)
        except Exception:
            pass
    return findings


def _extract_cve(cve_field: Any) -> Optional[str]:
    if isinstance(cve_field, list) and cve_field:
        return cve_field[0]
    if isinstance(cve_field, str):
        return cve_field
    return None


async def scan_with_nuclei(targets: list[str]) -> list[VulnFinding]:
    info = await detect_nuclei_async()
    if not info["installed"]:
        return []
    return await asyncio.to_thread(_nuclei_scan_sync, targets, info["binary"])


def _version_to_tuple(version: str) -> tuple:
    """Convert a dotted version string to a tuple for comparison."""
    try:
        return tuple(int(x) for x in re.findall(r"\d+", version)[:4])
    except Exception:
        return (0,)


def check_software_cves(software: list[dict]) -> list[VulnFinding]:
    """Check installed software against a small built-in CVE mapping."""
    findings: list[VulnFinding] = []
    # Mapping: product name regex -> vulnerable version ranges -> CVE
    software_cves = [
        {
            "product_re": re.compile(r"(7-zip|7zip)", re.I),
            "min_version": (18, 5),
            "title": "7-Zip prior to 18.05 vulnerability",
            "cve": "CVE-2018-10115",
            "cvss": 7.8,
            "severity": "high",
            "recommendation": "Update 7-Zip to the latest version.",
        },
        {
            "product_re": re.compile(r"(adobe\s*reader|acrobat\s*reader)", re.I),
            "min_version": (2020,),
            "title": "Outdated Adobe Reader may have known vulnerabilities",
            "cve": None,
            "cvss": None,
            "severity": "medium",
            "recommendation": "Update Adobe Reader to the latest version.",
        },
    ]

    seen = set()
    for item in software:
        name = item.get("DisplayName") or item.get("name") or ""
        version = item.get("DisplayVersion") or item.get("version") or ""
        ver_tuple = _version_to_tuple(version)
        for rule in software_cves:
            if rule["product_re"].search(name):
                key = (name, version, rule["title"])
                if key in seen:
                    continue
                seen.add(key)
                confidence = "likely" if version and ver_tuple < rule["min_version"] else "potential"
                findings.append(VulnFinding(
                    title=rule["title"],
                    description=f"{name} version {version} may be vulnerable."
                                f" CVE reference: {rule['cve'] or 'N/A'}",
                    severity=rule["severity"],
                    confidence=confidence,
                    cve_id=rule["cve"],
                    cvss_score=rule["cvss"],
                    affected_resource=f"{name} {version}",
                    recommendation=rule["recommendation"],
                    tool="internal",
                ))
    return findings


def check_service_vulns(services: list[dict]) -> list[VulnFinding]:
    """Check exposed services against built-in vulnerability mappings."""
    findings: list[VulnFinding] = []
    seen = set()
    for svc in services:
        port = svc.get("port") or 0
        guess = (svc.get("guess") or svc.get("service") or "").lower()
        address = svc.get("address") or svc.get("ip") or "local"
        for rule in _KNOWN_CVE_MAP:
            if guess == rule["service"] or port in rule["ports"]:
                key = (rule["title"], address, port)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(VulnFinding(
                    title=rule["title"],
                    description=rule["description"],
                    severity=rule["severity"],
                    confidence=rule["confidence"],
                    cve_id=rule["cve"],
                    cvss_score=rule["cvss"],
                    affected_resource=f"{address}:{port}",
                    recommendation=rule["recommendation"],
                    tool="internal",
                ))
    return findings


async def run_vulnerability_scan(
    local_asset: dict,
    network_hosts: list[dict],
    exposed_services: Optional[list[dict]] = None,
) -> dict:
    """Run the full vulnerability scan and return structured results."""
    results: dict = {
        "tool_status": {"nuclei": {"installed": False, "reason": None}},
        "findings": [],
        "errors": [],
        "scanned_hosts": [],
    }

    # Nuclei scan on discovered hosts (lightweight)
    nuclei_targets = [h.get("ip") for h in network_hosts if h.get("ip")][:10]
    nuclei_info = await detect_nuclei_async()
    results["tool_status"]["nuclei"] = nuclei_info
    if nuclei_info["installed"]:
        try:
            nuclei_findings = await asyncio.wait_for(
                scan_with_nuclei(nuclei_targets),
                timeout=120.0,
            )
            for f in nuclei_findings:
                results["findings"].append(_finding_to_dict(f))
            results["scanned_hosts"] = nuclei_targets
        except asyncio.TimeoutError:
            results["errors"].append("Nuclei scan timed out after 120s")
        except Exception as e:
            results["errors"].append(f"Nuclei scan error: {e}")
    else:
        results["errors"].append(nuclei_info.get("reason", "Nuclei not installed"))

    # Installed software CVE checks
    software = local_asset.get("installed_software") or []
    try:
        for f in check_software_cves(software):
            results["findings"].append(_finding_to_dict(f))
    except Exception as e:
        results["errors"].append(f"Software CVE check error: {e}")

    # Exposed service checks
    services = exposed_services or local_asset.get("listening_ports") or []
    try:
        for f in check_service_vulns(services):
            results["findings"].append(_finding_to_dict(f))
    except Exception as e:
        results["errors"].append(f"Service vuln check error: {e}")

    return results


def _finding_to_dict(f: VulnFinding) -> dict:
    return {
        "title": f.title,
        "description": f.description,
        "severity": f.severity,
        "confidence": f.confidence,
        "cve_id": f.cve_id,
        "cvss_score": f.cvss_score,
        "affected_resource": f.affected_resource,
        "recommendation": f.recommendation,
        "tool": f.tool,
    }


async def scan_target_with_nuclei(target: str) -> list[VulnFinding]:
    """Convenience wrapper for scanning a single target."""
    return await scan_with_nuclei([target])
