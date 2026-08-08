"""Network Discovery — Pydantic schemas for request/response validation."""

from __future__ import annotations
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator
import ipaddress


# ── Request schemas ───────────────────────────────────────────────────

class HostDiscoveryRequest(BaseModel):
    target: str = Field(..., description="IP, CIDR (192.168.1.0/24), or hostname")
    timeout: float = Field(2.0, ge=0.1, le=30.0, description="Ping timeout in seconds")
    method: str = Field("ping", description="ping | arp | syn | icmp")

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")
        return v


class PortScanRequest(BaseModel):
    target: str = Field(..., description="IP address or hostname")
    ports: str = Field("1-1024", description="Port range e.g. '1-1024', '80,443,8080', 'common'")
    scan_type: str = Field("syn", description="syn | connect | udp | fin | xmas | null")
    timeout: float = Field(5.0, ge=0.1, le=60.0)
    max_rate: int = Field(500, ge=1, le=5000, description="Max packets per second")

    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, v: str) -> str:
        allowed = {"syn", "connect", "udp", "fin", "xmas", "null"}
        if v not in allowed:
            raise ValueError(f"scan_type must be one of: {allowed}")
        return v


class ServiceDetectionRequest(BaseModel):
    target: str
    ports: List[int] = Field(..., description="List of open ports to probe")
    timeout: float = Field(3.0, ge=0.1, le=30.0)
    grab_banners: bool = Field(True, description="Attempt banner grabbing")


class FullScanRequest(BaseModel):
    target: str = Field(..., description="IP, CIDR, or hostname")
    port_range: str = Field("1-1024", description="Port range to scan")
    scan_type: str = Field("syn", description="syn | connect")
    detect_os: bool = Field(True)
    detect_services: bool = Field(True)
    grab_banners: bool = Field(True)
    timeout: float = Field(5.0, ge=0.1, le=120.0)
    max_rate: int = Field(500, ge=1, le=5000)


class NetworkRangeRequest(BaseModel):
    cidr: str = Field(..., description="CIDR notation e.g. 192.168.1.0/24")
    timeout: float = Field(2.0, ge=0.1, le=30.0)

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError(f"Invalid CIDR notation: {v}")
        return v


# ── Response schemas ──────────────────────────────────────────────────

class PortInfo(BaseModel):
    port: int
    protocol: str = "tcp"
    state: str          # open | closed | filtered
    service: str = ""
    version: str = ""
    banner: str = ""
    cpe: str = ""


class HostInfo(BaseModel):
    ip: str
    hostname: str = ""
    mac: str = ""
    mac_vendor: str = ""
    os_guess: str = ""
    os_confidence: int = 0
    status: str = "up"   # up | down
    response_time_ms: float = 0.0
    ports: List[PortInfo] = []
    open_ports: List[int] = []
    services: Dict[str, str] = {}
    ttl: int = 0
    hops: int = 0


class DiscoveryResult(BaseModel):
    target: str
    scan_type: str
    hosts_found: int
    hosts_up: int
    hosts_down: int
    scan_duration_secs: float
    hosts: List[HostInfo]
    raw_nmap: Optional[Dict[str, Any]] = None
    errors: List[str] = []


class PortScanResult(BaseModel):
    target: str
    ip: str
    scan_type: str
    ports_scanned: int
    open_ports: List[PortInfo]
    filtered_ports: int
    closed_ports: int
    scan_duration_secs: float
    errors: List[str] = []


class NetworkInterfaceInfo(BaseModel):
    name: str
    ip: str = ""
    netmask: str = ""
    broadcast: str = ""
    mac: str = ""
    is_up: bool = False
    mtu: int = 0
