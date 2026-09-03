"""AISS — Network Topology API Routes
Exposes the full network topology map, segment management,
interface discovery, and cross-network scanning.
"""
import asyncio
import time as _time
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
from core.dependencies import get_engine_authenticated
from core.threat_engine import ThreatEngine

router = APIRouter()

# ── Response cache ────────────────────────────────────────────────────
_topo_cache: dict = {"data": None, "ts": 0.0}
_TOPO_TTL = 20.0   # seconds


# ── Topology map ──────────────────────────────────────────────────────

@router.get("/map")
async def get_topology_map():
    """
    Get the full network topology map.
    Returns nodes (devices), edges (connections), and segments (subnets).
    Cached for 20 seconds to avoid blocking on repeated interface scans.
    """
    global _topo_cache
    now = _time.monotonic()
    if _topo_cache["data"] is not None and (now - _topo_cache["ts"]) < _TOPO_TTL:
        return _topo_cache["data"]

    from modules.network_topology import topology_manager
    try:
        data = await asyncio.wait_for(topology_manager.get_topology_map(), timeout=15.0)
        _topo_cache["data"] = data
        _topo_cache["ts"]   = _time.monotonic()
        return data
    except asyncio.TimeoutError:
        # Return cached data or fallback on timeout
        if _topo_cache["data"] is not None:
            return _topo_cache["data"]
        return {
            "nodes": [{"id": "aiss_server", "label": "AISS Server", "type": "server",
                       "status": "online", "is_center": True}],
            "edges": [], "segments": [], "interfaces": [],
            "generated_at": __import__("datetime").datetime.utcnow().isoformat(),
            "node_count": 1, "edge_count": 0,
        }


@router.post("/refresh")
async def refresh_interfaces():
    """Re-scan local network interfaces and update topology."""
    from modules.network_topology import topology_manager
    ifaces = await topology_manager.refresh_interfaces()
    return {
        "interfaces":  [i.to_dict() for i in ifaces],
        "count":       len(ifaces),
        "message":     f"Discovered {len(ifaces)} network interface(s)",
    }


# ── Segments ──────────────────────────────────────────────────────────

@router.get("/segments")
async def get_segments():
    """List all known network segments (subnets) being monitored."""
    from modules.network_topology import topology_manager
    return {
        "segments": topology_manager.get_known_networks(),
        "count":    len(topology_manager.get_known_networks()),
    }


class SegmentRequest(BaseModel):
    cidr:       str
    type:       str   = "lan"   # lan | wan | vpn | man
    label:      str   = ""
    auto_scan:  bool  = True


@router.post("/segments",
             dependencies=[Depends(get_engine_authenticated)])
async def add_segment(req: SegmentRequest):
    """
    Manually add a network segment to monitor.

    Examples:
      - LAN:  cidr="192.168.1.0/24", type="lan"
      - WAN:  cidr="203.0.113.0/24", type="wan"
      - VPN:  cidr="10.8.0.0/24",    type="vpn"
      - MAN:  cidr="10.0.0.0/8",     type="man"
    """
    from modules.network_topology import topology_manager
    try:
        import ipaddress
        ipaddress.ip_network(req.cidr, strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid CIDR: {req.cidr}")
    valid_types = {"lan", "wan", "vpn", "man"}
    if req.type not in valid_types:
        raise HTTPException(status_code=400,
                            detail=f"type must be one of: {valid_types}")
    seg = topology_manager.add_custom_segment(
        cidr=req.cidr, net_type=req.type,
        label=req.label, auto_scan=req.auto_scan
    )
    return {"segment": seg, "message": f"Network segment {req.cidr} added"}


# ── Interfaces ────────────────────────────────────────────────────────

@router.get("/interfaces")
async def get_interfaces():
    """Get all local network interfaces with IP, type, and CIDR."""
    from modules.network_topology import topology_manager
    if not topology_manager.get_interfaces():
        await topology_manager.refresh_interfaces()
    return {
        "interfaces": topology_manager.get_interfaces(),
        "count":      len(topology_manager.get_interfaces()),
    }


# ── Scan ─────────────────────────────────────────────────────────────

@router.post("/scan",
             dependencies=[Depends(get_engine_authenticated)])
async def scan_all_networks():
    """
    Trigger host discovery scan across all known network segments.
    Runs nmap ping sweep on each segment and updates the topology map.
    """
    from modules.network_topology import topology_manager
    results = await topology_manager.scan_all_segments()
    total_hosts = sum(
        v.get("hosts_up", 0) for v in results.values() if isinstance(v, dict)
    )
    return {
        "results":     results,
        "total_hosts": total_hosts,
        "message":     f"Scan complete — {total_hosts} host(s) found",
    }


# ── Agent connection info ─────────────────────────────────────────────

@router.get("/agents")
async def get_topology_agents():
    """Get all connected agents with their network positions."""
    from modules.remote_agent import agent_manager
    from modules.network_topology import topology_manager
    agents = agent_manager.get_all_agents()
    stats  = agent_manager.get_stats()
    return {
        "agents":   agents,
        "stats":    stats,
        "by_network": stats.get("by_network", {}),
        "connect_instructions": {
            "description": "Run aiss_agent.py on any computer to connect it to AISS",
            "step1": "Generate a token: POST /api/agents/token/generate",
            "step2": "On remote machine: python aiss_agent.py --server ws://THIS_IP:8000 --token TOKEN",
            "step3": "View connected agents: GET /api/topology/agents",
            "networks": {
                "lan": "Same local network — use internal IP e.g. ws://192.168.1.100:8000",
                "wan": "Over internet — use public IP or domain e.g. wss://your-domain.com",
                "vpn": "Via VPN — use VPN tunnel IP e.g. ws://10.8.0.1:8000",
                "man": "Metropolitan/multi-site — use site-to-site connection IP",
            },
        },
    }
