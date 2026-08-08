"""AISS — Network Topology Manager
Manages multi-network monitoring across LAN, WAN, MAN, and VPN.

Capabilities:
  - Auto-detect connected network interfaces and their types
  - Track connected agents per network segment
  - Generate network topology map (nodes + links)
  - Detect new devices joining monitored subnets
  - Monitor bandwidth and latency per segment
  - Classify each connection as LAN/WAN/VPN/MAN automatically

Used by:
  - Remote agent system (knows which network each agent is on)
  - Network discovery (knows which subnets to scan)
  - Dashboard (renders the topology map)

Usage:
    from modules.network_topology import topology_manager
    map_data = await topology_manager.get_topology_map()
    networks = topology_manager.get_known_networks()
"""
import asyncio
import ipaddress
import os
import platform
import socket
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional
from utils.logger import setup_logger

logger = setup_logger("network_topology")

IS_WIN   = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"


# ─────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────

@dataclass
class NetworkInterface:
    name:      str
    ip:        str
    netmask:   str
    cidr:      str
    type:      str   = "unknown"  # lan | wan | vpn | man | loopback
    is_up:     bool  = True
    mac:       str   = ""
    gateway:   str   = ""
    mtu:       int   = 1500

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class NetworkNode:
    """A device on the network — can be this machine, an agent, or a discovered host."""
    id:          str
    ip:          str
    hostname:    str
    type:        str   = "host"    # server | agent | router | switch | unknown
    network:     str   = "unknown"
    os_guess:    str   = ""
    open_ports:  list  = field(default_factory=list)
    services:    dict  = field(default_factory=dict)
    is_online:   bool  = True
    last_seen:   str   = ""
    threat_count:int   = 0
    agent_id:    str   = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class NetworkSegment:
    """A network segment (subnet) being monitored."""
    id:          str
    cidr:        str
    type:        str         # lan | wan | vpn | man
    label:       str         = ""
    gateway:     str         = ""
    interface:   str         = ""
    nodes:       list        = field(default_factory=list)
    agent_count: int         = 0
    threat_count:int         = 0
    last_scanned:str         = ""
    auto_scan:   bool        = True
    scan_interval_mins: int  = 30

    def to_dict(self) -> dict:
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────
# Network type classifier
# ─────────────────────────────────────────────────────────────────────

def classify_ip(ip: str) -> str:
    """Classify an IP address as lan/wan/vpn/man/loopback."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback:
            return "loopback"
        if addr.is_private:
            # Common VPN ranges
            if ip.startswith(("10.8.", "10.9.", "172.16.0.", "192.168.0.")):
                # Could be VPN — can't tell for certain without interface name
                return "lan"
            return "lan"
        # Carrier-grade NAT (100.64.0.0/10)
        if ipaddress.ip_address(ip) in ipaddress.ip_network("100.64.0.0/10"):
            return "man"
        return "wan"
    except ValueError:
        return "unknown"


def classify_interface(name: str, ip: str) -> str:
    """Classify a network interface by name + IP."""
    name_lower = name.lower()
    # VPN interfaces
    if any(vpn in name_lower for vpn in ["tun", "tap", "vpn", "wg", "zt", "ovpn"]):
        return "vpn"
    # Loopback
    if any(lo in name_lower for lo in ["lo", "loopback"]):
        return "loopback"
    # Wireless
    if any(w in name_lower for w in ["wlan", "wifi", "wi-fi", "wireless"]):
        return classify_ip(ip)
    return classify_ip(ip)


# ─────────────────────────────────────────────────────────────────────
# Topology Manager
# ─────────────────────────────────────────────────────────────────────

class NetworkTopologyManager:
    def __init__(self):
        self._interfaces:  dict[str, NetworkInterface] = {}
        self._segments:    dict[str, NetworkSegment]   = {}
        self._nodes:       dict[str, NetworkNode]      = {}
        self._last_refresh: float = 0

    # ── Interface discovery ───────────────────────────────────────────

    async def refresh_interfaces(self) -> list[NetworkInterface]:
        """Discover all active network interfaces on this machine."""
        loop = asyncio.get_event_loop()
        ifaces = await loop.run_in_executor(None, self._get_interfaces_sync)
        self._interfaces = {i.name: i for i in ifaces}
        self._last_refresh = time.time()

        # Auto-create segments from discovered interfaces
        for iface in ifaces:
            if iface.type in ("loopback",):
                continue
            seg_id = f"seg_{iface.cidr.replace('/', '_').replace('.', '_')}"
            if seg_id not in self._segments:
                self._segments[seg_id] = NetworkSegment(
                    id=seg_id,
                    cidr=iface.cidr,
                    type=iface.type,
                    label=f"{iface.type.upper()} — {iface.name} ({iface.cidr})",
                    gateway=iface.gateway,
                    interface=iface.name,
                )
        return ifaces

    def _get_interfaces_sync(self) -> list[NetworkInterface]:
        ifaces = []
        try:
            import psutil
            gateways = {}
            try:
                gw_info = psutil.net_if_stats()
            except Exception:
                gw_info = {}

            # Get default gateway
            try:
                if IS_WIN:
                    import subprocess
                    r = subprocess.run(
                        ["route", "print", "0.0.0.0"], capture_output=True, text=True
                    )
                    for line in r.stdout.splitlines():
                        parts = line.split()
                        if len(parts) >= 5 and parts[0] == "0.0.0.0":
                            gateways["default"] = parts[2]
                            break
                else:
                    import subprocess
                    r = subprocess.run(
                        ["ip", "route", "show", "default"],
                        capture_output=True, text=True
                    )
                    for line in r.stdout.splitlines():
                        if "default via" in line:
                            parts = line.split()
                            idx = parts.index("via")
                            gateways["default"] = parts[idx + 1]
                            break
            except Exception:
                pass

            for name, addrs in psutil.net_if_addrs().items():
                stats = gw_info.get(name)
                is_up = stats.isup if stats else True

                for addr in addrs:
                    import socket as _socket
                    if addr.family != _socket.AF_INET:
                        continue
                    ip      = addr.address
                    netmask = addr.netmask or "255.255.255.0"

                    # Calculate CIDR
                    try:
                        net  = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        cidr = str(net)
                    except Exception:
                        cidr = f"{ip}/24"

                    itype = classify_interface(name, ip)
                    ifaces.append(NetworkInterface(
                        name=name,
                        ip=ip,
                        netmask=netmask,
                        cidr=cidr,
                        type=itype,
                        is_up=is_up,
                        gateway=gateways.get("default", ""),
                    ))
        except ImportError:
            # Fallback without psutil
            try:
                hostname = socket.gethostname()
                ip       = socket.gethostbyname(hostname)
                ifaces.append(NetworkInterface(
                    name="eth0",
                    ip=ip,
                    netmask="255.255.255.0",
                    cidr=f"{ip}/24",
                    type=classify_ip(ip),
                ))
            except Exception:
                pass
        return ifaces

    # ── Node management ───────────────────────────────────────────────

    def register_node(self, node: NetworkNode) -> None:
        """Register a discovered network node (device)."""
        self._nodes[node.id] = node
        # Add to appropriate segment
        for seg in self._segments.values():
            try:
                net = ipaddress.ip_network(seg.cidr, strict=False)
                if ipaddress.ip_address(node.ip) in net:
                    if node.id not in seg.nodes:
                        seg.nodes.append(node.id)
            except Exception:
                pass

    def register_agent_node(self, agent_id: str, hostname: str, ip: str,
                            network_type: str) -> None:
        """Register a remote agent as a network node."""
        node = NetworkNode(
            id=f"agent_{agent_id[:8]}",
            ip=ip,
            hostname=hostname,
            type="agent",
            network=network_type,
            is_online=True,
            last_seen=datetime.now(timezone.utc).isoformat(),
            agent_id=agent_id,
        )
        self.register_node(node)

    def get_node(self, node_id: str) -> Optional[NetworkNode]:
        return self._nodes.get(node_id)

    # ── Topology map ──────────────────────────────────────────────────

    async def get_topology_map(self) -> dict:
        """
        Generate a complete network topology map for the frontend.
        Returns nodes and edges in a format suitable for graph visualisation
        (e.g., D3.js, Cytoscape, React-Flow).
        """
        if not self._interfaces or time.time() - self._last_refresh > 300:
            await self.refresh_interfaces()

        # This machine as the central node
        my_ip   = "127.0.0.1"
        try:
            my_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            pass

        nodes = [{
            "id":       "aiss_server",
            "label":    f"AISS Server\n{socket.gethostname()}",
            "ip":       my_ip,
            "type":     "server",
            "status":   "online",
            "is_center":True,
            "details":  {
                "hostname": socket.gethostname(),
                "os":       platform.system(),
                "version":  platform.version()[:40],
            },
        }]

        edges = []

        # Add network segments
        segments_out = []
        for seg in self._segments.values():
            if seg.type == "loopback":
                continue
            seg_node = {
                "id":     seg.id,
                "label":  seg.label or seg.cidr,
                "type":   "segment",
                "cidr":   seg.cidr,
                "net_type": seg.type,
                "status": "active",
            }
            nodes.append(seg_node)
            edges.append({"source": "aiss_server", "target": seg.id,
                          "label": seg.type.upper()})
            segments_out.append(seg.to_dict())

        # Add connected agents
        try:
            from modules.remote_agent import _agent_registry
            for agent_id, agent in _agent_registry.items():
                node_id = f"agent_{agent_id[:8]}"
                nodes.append({
                    "id":     node_id,
                    "label":  f"{agent.hostname}\n({agent.ip})",
                    "type":   "agent",
                    "ip":     agent.ip,
                    "status": agent.status,
                    "net_type": agent.network_type,
                    "details": {
                        "hostname":     agent.hostname,
                        "os":           agent.os_name,
                        "cpu":          agent.cpu_percent,
                        "ram":          agent.ram_percent,
                        "threats":      agent.threat_count,
                        "connected_at": agent.connected_at,
                    },
                })
                # Connect agent to its segment
                connected_seg = next(
                    (s.id for s in self._segments.values()
                     if _ip_in_cidr(agent.ip, s.cidr)),
                    None
                )
                if connected_seg:
                    edges.append({"source": connected_seg, "target": node_id,
                                  "label": agent.network_type.upper()})
                else:
                    # Direct connection to AISS (WAN/VPN)
                    edges.append({"source": "aiss_server", "target": node_id,
                                  "label": agent.network_type.upper()})
        except ImportError:
            pass

        # Add discovered hosts from network scans
        for nid, node in self._nodes.items():
            if not any(n["id"] == nid for n in nodes):
                nodes.append({
                    "id":     nid,
                    "label":  node.hostname or node.ip,
                    "type":   node.type,
                    "ip":     node.ip,
                    "status": "online" if node.is_online else "offline",
                    "details": {
                        "os":       node.os_guess,
                        "ports":    node.open_ports[:10],
                        "services": node.services,
                    },
                })

        return {
            "nodes":        nodes,
            "edges":        edges,
            "segments":     segments_out,
            "interfaces":   [i.to_dict() for i in self._interfaces.values()],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "node_count":   len(nodes),
            "edge_count":   len(edges),
        }

    def get_known_networks(self) -> list[dict]:
        return [s.to_dict() for s in self._segments.values()]

    def get_interfaces(self) -> list[dict]:
        return [i.to_dict() for i in self._interfaces.values()]

    def add_custom_segment(self, cidr: str, net_type: str,
                           label: str = "", auto_scan: bool = True) -> dict:
        """Manually add a network segment to monitor."""
        seg_id = f"seg_{cidr.replace('/', '_').replace('.', '_')}"
        seg    = NetworkSegment(
            id=seg_id, cidr=cidr, type=net_type,
            label=label or f"{net_type.upper()} — {cidr}",
            auto_scan=auto_scan,
        )
        self._segments[seg_id] = seg
        logger.info(f"Network segment added: {cidr} ({net_type})")
        return seg.to_dict()

    async def scan_all_segments(self) -> dict:
        """Trigger discovery scan across all known segments."""
        results = {}
        try:
            from modules.network_discovery.discovery_service import NetworkDiscoveryService
            svc = NetworkDiscoveryService()
            for seg_id, seg in self._segments.items():
                if not seg.auto_scan or seg.type == "loopback":
                    continue
                try:
                    result = await svc.discover_hosts(seg.cidr, method="nmap", timeout=10)
                    seg.last_scanned = datetime.now(timezone.utc).isoformat()
                    for host in result.hosts:
                        self.register_node(NetworkNode(
                            id=f"host_{host.ip.replace('.','_')}",
                            ip=host.ip,
                            hostname=host.hostname or host.ip,
                            type="host",
                            network=seg.type,
                            is_online=host.status == "up",
                            last_seen=datetime.now(timezone.utc).isoformat(),
                        ))
                    results[seg_id] = {
                        "cidr":       seg.cidr,
                        "hosts_up":   result.hosts_up,
                        "hosts_found":result.hosts_found,
                    }
                except Exception as e:
                    results[seg_id] = {"error": str(e)}
        except ImportError:
            results["error"] = "network_discovery module not available"
        return results


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return False


# Singleton
topology_manager = NetworkTopologyManager()
