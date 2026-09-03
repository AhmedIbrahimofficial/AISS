"""
NETWORK tool handlers — psutil + existing network modules.
Never fabricates data; returns explicit gap messages on unavailability.
"""
from __future__ import annotations
import asyncio
import subprocess
from typing import Any

_NA = "No real data available for {tool}"


async def get_network_interfaces(**_: Any) -> dict:
    try:
        import psutil
        ifaces = []
        for name, addrs in psutil.net_if_addrs().items():
            stats = psutil.net_if_stats().get(name)
            ifaces.append({
                "name": name,
                "is_up": stats.isup if stats else None,
                "speed": stats.speed if stats else None,
                "addresses": [{"family": str(a.family), "address": a.address} for a in addrs],
            })
        return {"status": "ok", "interfaces": ifaces}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="get_network_interfaces")}


async def get_network_connections(**_: Any) -> dict:
    try:
        import psutil
        conns = []
        for c in psutil.net_connections(kind="all"):
            try:
                conns.append({
                    "fd": c.fd, "family": str(c.family), "type": str(c.type),
                    "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                    "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                    "status": c.status, "pid": c.pid,
                })
            except Exception:
                pass
        return {"status": "ok", "count": len(conns), "connections": conns[:300]}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="get_network_connections")}


async def scan_network(target: str = "192.168.1.0/24", **_: Any) -> dict:
    try:
        import nmap
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments="-sn")
        hosts = [{"host": h, "state": nm[h].state()} for h in nm.all_hosts()]
        return {"status": "ok", "target": target, "hosts_found": len(hosts), "hosts": hosts}
    except ImportError:
        return {"status": "error", "message": _NA.format(tool="scan_network") + " (nmap not available)"}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="scan_network")}


async def scan_ports(target: str = "127.0.0.1", port_range: str = "1-1024", **_: Any) -> dict:
    try:
        import nmap
        nm = nmap.PortScanner()
        nm.scan(target, port_range)
        open_ports = []
        if target in nm.all_hosts():
            for proto in nm[target].all_protocols():
                for port in nm[target][proto]:
                    state = nm[target][proto][port]["state"]
                    if state == "open":
                        open_ports.append({"port": port, "protocol": proto,
                                           "service": nm[target][proto][port].get("name","")})
        return {"status": "ok", "target": target, "open_ports": open_ports}
    except ImportError:
        return {"status": "error", "message": _NA.format(tool="scan_ports") + " (nmap not available)"}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="scan_ports")}


async def discover_devices(subnet: str = "192.168.1.0/24", **_: Any) -> dict:
    try:
        from modules.network_discovery import discovery  # existing module
        result = await discovery.discover_hosts(subnet)
        return {"status": "ok", "devices": result}
    except Exception:
        # Fallback to nmap
        return await scan_network(target=subnet)


async def get_connected_devices(**_: Any) -> dict:
    try:
        import psutil
        import re
        result = await asyncio.to_thread(
            subprocess.run, ["arp", "-a"], capture_output=True, text=True, timeout=15
        )
        devices = []
        for line in result.stdout.splitlines():
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F:.-]+)", line)
            if match:
                devices.append({"ip": match.group(1), "mac": match.group(2)})
        return {"status": "ok", "count": len(devices), "devices": devices}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="get_connected_devices")}


async def analyze_network_activity(**_: Any) -> dict:
    try:
        import psutil
        net_io = psutil.net_io_counters()
        per_nic = psutil.net_io_counters(pernic=True)
        return {
            "status": "ok",
            "total": {
                "bytes_sent": net_io.bytes_sent,
                "bytes_recv": net_io.bytes_recv,
                "packets_sent": net_io.packets_sent,
                "packets_recv": net_io.packets_recv,
                "errin": net_io.errin,
                "errout": net_io.errout,
            },
            "per_interface": {
                k: {"bytes_sent": v.bytes_sent, "bytes_recv": v.bytes_recv}
                for k, v in per_nic.items()
            },
        }
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="analyze_network_activity")}
