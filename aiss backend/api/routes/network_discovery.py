"""Module 1 — Network Discovery Engine API Routes

Endpoints:
  POST /api/network-discovery/hosts          — Live host discovery
  POST /api/network-discovery/ports          — Port scan
  POST /api/network-discovery/full           — Full scan (hosts+ports+OS)
  GET  /api/network-discovery/interfaces     — Local network interfaces
  GET  /api/network-discovery/scans          — Scan history
  GET  /api/network-discovery/scans/{id}     — Specific scan result
  POST /api/network-discovery/banner         — Banner grabbing
"""

from __future__ import annotations

import asyncio
import os
import shutil
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from core.dependencies import get_db_session, get_engine_authenticated
from core.threat_engine import ThreatEngine
from modules.network_discovery.schemas import (
    HostDiscoveryRequest, PortScanRequest, FullScanRequest,
    DiscoveryResult, PortScanResult, NetworkInterfaceInfo,
)
from modules.network_discovery.discovery_service import discovery_service
from modules.network_discovery.utils import get_local_interfaces
from utils.logger import setup_logger

logger = setup_logger("network_discovery.routes")
router = APIRouter()


def _detect_nmap() -> dict:
    """
    Detect nmap binary in PATH or common install locations.
    Returns dict with 'available', 'path', and 'install_hint'.
    """
    # Check PATH first
    nmap_path = shutil.which("nmap")
    if nmap_path:
        return {"available": True, "path": nmap_path, "install_hint": None}

    # Common Windows install locations
    common_paths = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        os.path.expanduser(r"~\AppData\Local\Nmap\nmap.exe"),
    ]
    for p in common_paths:
        if os.path.isfile(p):
            return {"available": True, "path": p, "install_hint": None}

    return {
        "available": False,
        "path": None,
        "install_hint": (
            "Nmap not found. Install it from https://nmap.org/download.html "
            "or run: winget install nmap"
        ),
    }


@router.get("/nmap-status", summary="Check if nmap is installed")
async def nmap_status():
    """Return nmap availability and install instructions."""
    return _detect_nmap()


# ── POST /api/network-discovery/hosts ────────────────────────────────

@router.post("/hosts", response_model=DiscoveryResult, summary="Live host discovery")
async def discover_hosts(
    req:    HostDiscoveryRequest,
    db:     AsyncSession  = Depends(get_db_session),
    engine: ThreatEngine  = Depends(get_engine_authenticated),
):
    """
    Discover live hosts in a target (IP, CIDR, or hostname).
    Methods: ping (ICMP), arp (LAN only), nmap (most reliable).
    """
    result = await discovery_service.discover_hosts(
        target=req.target,
        method=req.method,
        timeout=req.timeout,
        db=db,
    )

    # Register threat if unexpected hosts found in restricted ranges
    if result.hosts_up > 0:
        try:
            from models.threat import Threat, ThreatType, ThreatSeverity
            if result.hosts_up > 50:
                threat = Threat(
                    type=ThreatType.PORT_SCAN,
                    description=f"Large network sweep: {result.hosts_up} live hosts found in {req.target}",
                    severity=ThreatSeverity.MEDIUM,
                    source=req.target,
                    module="NetworkDiscovery",
                    metadata={"hosts_up": result.hosts_up, "scan_type": "host_discovery"},
                )
                await engine.register_threat(threat)
        except Exception:
            pass

    return result


# ── POST /api/network-discovery/ports ────────────────────────────────

@router.post("/ports", response_model=PortScanResult, summary="Port scan a target")
async def scan_ports(
    req:    PortScanRequest,
    db:     AsyncSession  = Depends(get_db_session),
    engine: ThreatEngine  = Depends(get_engine_authenticated),
):
    """
    Scan ports on a target host.
    scan_type: syn | connect | udp | fin | xmas | null
    ports: '1-1024', '80,443,8080', 'common', 'top100'
    """
    result = await discovery_service.scan_ports(
        target=req.target,
        ports=req.ports,
        scan_type=req.scan_type,
        timeout=req.timeout,
        max_rate=req.max_rate,
        grab_banners=True,
        db=db,
    )

    # Register high-risk open ports as threats
    dangerous_ports = {21, 23, 135, 139, 445, 1433, 3389, 4444, 5900, 6379}
    found_dangerous = [p.port for p in result.open_ports if p.port in dangerous_ports]
    if found_dangerous:
        try:
            from models.threat import Threat, ThreatType, ThreatSeverity
            threat = Threat(
                type=ThreatType.PORT_SCAN,
                description=(
                    f"High-risk ports open on {req.target}: {found_dangerous}. "
                    f"Services: {', '.join(p.service for p in result.open_ports if p.port in dangerous_ports)}"
                ),
                severity=ThreatSeverity.HIGH,
                source=req.target,
                module="NetworkDiscovery",
                metadata={
                    "open_ports":      [p.port for p in result.open_ports],
                    "dangerous_ports": found_dangerous,
                    "scan_type":       req.scan_type,
                },
            )
            await engine.register_threat(threat)
        except Exception:
            pass

    return result


# ── POST /api/network-discovery/full ─────────────────────────────────

@router.post("/full", response_model=DiscoveryResult, summary="Full network scan")
async def full_scan(
    req:    FullScanRequest,
    db:     AsyncSession = Depends(get_db_session),
    engine: ThreatEngine = Depends(get_engine_authenticated),
):
    """
    Full discovery pipeline:
    1. Live host discovery
    2. Port scan with service detection
    3. OS fingerprinting
    4. Banner grabbing
    5. MAC address resolution
    """
    result = await discovery_service.full_scan(
        target=req.target,
        port_range=req.port_range,
        scan_type=req.scan_type,
        detect_os=req.detect_os,
        detect_services=req.detect_services,
        grab_banners=req.grab_banners,
        timeout=req.timeout,
        max_rate=req.max_rate,
        db=db,
    )
    return result


# ── GET /api/network-discovery/interfaces ────────────────────────────

@router.get("/interfaces", summary="List local network interfaces")
async def list_interfaces():
    """Returns all local network interfaces with IP, MAC, and status."""
    ifaces = get_local_interfaces()
    return {"interfaces": ifaces, "count": len(ifaces)}


# ── GET /api/network-discovery/scans ─────────────────────────────────

@router.get("/scans", summary="List past network scans")
async def list_scans(
    limit:  int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db:     AsyncSession = Depends(get_db_session),
):
    """Returns paginated list of past scan records from the database."""
    try:
        from modules.network_discovery.models import NetworkScan
        result = await db.execute(
            select(NetworkScan)
            .order_by(desc(NetworkScan.started_at))
            .offset(offset)
            .limit(limit)
        )
        scans = result.scalars().all()
        return {
            "scans": [s.to_dict() for s in scans],
            "count": len(scans),
            "offset": offset,
            "limit": limit,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── GET /api/network-discovery/scans/{scan_id} ───────────────────────

@router.get("/scans/{scan_id}", summary="Get scan result by ID")
async def get_scan(
    scan_id: str,
    db:      AsyncSession = Depends(get_db_session),
):
    try:
        from modules.network_discovery.models import NetworkScan
        scan = await db.get(NetworkScan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        data = scan.to_dict()
        data["result"] = scan.result
        return data
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── POST /api/network-discovery/banner ───────────────────────────────

@router.post("/banner", summary="Grab banner from a specific port")
async def grab_banner(
    target:  str = Query(..., description="Host IP or hostname"),
    port:    int = Query(..., ge=1, le=65535),
    timeout: float = Query(3.0, ge=0.5, le=10.0),
):
    """Attempt to grab the service banner from a specific host:port."""
    banner = await discovery_service.port_engine._grab_banner(target, port, timeout)
    svc    = discovery_service.port_engine  # just for lookup
    from modules.network_discovery.utils import service_name as _svc
    return {
        "target":       target,
        "port":         port,
        "banner":       banner,
        "service_hint": _svc(port),
        "has_banner":   bool(banner),
    }
