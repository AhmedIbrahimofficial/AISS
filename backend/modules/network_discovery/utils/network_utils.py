"""Network Discovery — utility functions used across the engine."""

from __future__ import annotations
import ipaddress
import socket
import re
import sys
from typing import List, Optional, Tuple
from utils.logger import setup_logger

logger = setup_logger("network_discovery.utils")

# ── Well-known port → service name map ───────────────────────────────
COMMON_PORTS: dict[int, str] = {
    21: "FTP",       22: "SSH",       23: "Telnet",    25: "SMTP",
    53: "DNS",       67: "DHCP",      68: "DHCP",      69: "TFTP",
    80: "HTTP",      110: "POP3",     111: "RPC",      119: "NNTP",
    123: "NTP",      135: "MSRPC",    137: "NetBIOS",  138: "NetBIOS",
    139: "NetBIOS",  143: "IMAP",     161: "SNMP",     162: "SNMP-trap",
    179: "BGP",      194: "IRC",      389: "LDAP",     443: "HTTPS",
    445: "SMB",      465: "SMTPS",    514: "Syslog",   515: "LPD",
    587: "SMTP",     636: "LDAPS",    873: "rsync",    902: "VMware",
    993: "IMAPS",    995: "POP3S",    1080: "SOCKS",   1194: "OpenVPN",
    1433: "MSSQL",   1521: "Oracle",  1723: "PPTP",    2049: "NFS",
    2181: "ZooKeeper", 2375: "Docker", 2376: "Docker",
    3306: "MySQL",   3389: "RDP",     3690: "SVN",     4444: "Metasploit",
    4789: "VXLAN",   5432: "PostgreSQL", 5900: "VNC",  5985: "WinRM",
    5986: "WinRM",   6379: "Redis",   6443: "Kubernetes", 7001: "WebLogic",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 8888: "Jupyter",
    9000: "PHP-FPM", 9200: "Elasticsearch", 9300: "Elasticsearch",
    10250: "Kubelet", 27017: "MongoDB", 28015: "RethinkDB",
}

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 119, 135, 139, 143, 161, 194,
    389, 443, 445, 465, 514, 587, 636, 873, 993, 995, 1080, 1194,
    1433, 1521, 1723, 2049, 2375, 3306, 3389, 3690, 4444, 5432, 5900,
    5985, 6379, 7001, 8080, 8443, 8888, 9000, 9200, 27017, 28015,
]

# ── OUI / MAC vendor lookup (top vendors only — avoids internet dependency)
_OUI_MAP: dict[str, str] = {
    "00:50:56": "VMware",       "00:0c:29": "VMware",      "00:1b:21": "Intel",
    "00:1a:4b": "Intel",        "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi", "00:14:22": "Dell",         "00:21:9b": "Dell",
    "18:66:da": "Dell",         "f8:bc:12": "Dell",         "00:0f:1f": "Dell",
    "00:23:ae": "Cisco",        "00:1a:a1": "Cisco",        "00:17:5a": "Cisco",
    "3c:22:fb": "Apple",        "f0:18:98": "Apple",        "a4:83:e7": "Apple",
    "00:1c:42": "Parallels",    "00:03:ff": "Microsoft",    "00:15:5d": "Microsoft",
    "52:54:00": "QEMU/KVM",     "08:00:27": "VirtualBox",
}


def get_mac_vendor(mac: str) -> str:
    """Return vendor name from MAC OUI prefix."""
    if not mac:
        return ""
    prefix = mac[:8].upper().replace("-", ":").lower()
    return _OUI_MAP.get(prefix[:8], _OUI_MAP.get(prefix[:5], "Unknown"))


def resolve_hostname(ip: str) -> str:
    """Reverse DNS lookup. Returns empty string on failure."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def resolve_ip(hostname: str) -> str:
    """Forward DNS. Returns empty string on failure."""
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return ""


def is_valid_ip(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr: str) -> bool:
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def expand_cidr(cidr: str) -> List[str]:
    """Return list of all host IPs in the CIDR range (max 1024)."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        hosts = list(net.hosts())
        return [str(h) for h in hosts[:1024]]
    except ValueError:
        return []


def parse_port_spec(spec: str) -> List[int]:
    """
    Parse port specification into a list of integers.
    Supports: '80', '80,443', '1-1024', 'common', 'top100'
    """
    spec = spec.strip().lower()
    if spec in ("common", "top100"):
        return TOP_100_PORTS
    if spec == "all":
        return list(range(1, 65536))

    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                for p in range(int(start), int(end) + 1):
                    if 1 <= p <= 65535:
                        ports.add(p)
            except ValueError:
                pass
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                pass
    return sorted(ports)


def service_name(port: int, protocol: str = "tcp") -> str:
    """Look up well-known service name for a port."""
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    try:
        return socket.getservbyport(port, protocol)
    except Exception:
        return ""


def is_windows() -> bool:
    return sys.platform == "win32"


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def ttl_to_os_guess(ttl: int) -> str:
    """Guess OS from initial TTL value."""
    if ttl <= 0:
        return "Unknown"
    if ttl <= 64:
        return "Linux/Unix"
    if ttl <= 128:
        return "Windows"
    if ttl <= 255:
        return "Cisco/Network Device"
    return "Unknown"


def get_local_interfaces() -> List[dict]:
    """Return list of local network interfaces with IP/MAC info."""
    interfaces = []
    try:
        import psutil
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()

        for iface_name, iface_addrs in addrs.items():
            info: dict = {
                "name": iface_name,
                "ip": "",
                "netmask": "",
                "broadcast": "",
                "mac": "",
                "is_up": stats.get(iface_name, None) is not None and stats[iface_name].isup,
                "mtu": stats.get(iface_name).mtu if iface_name in stats else 0,
            }

            import psutil
            AF_INET  = psutil.AF_INET   if hasattr(psutil, "AF_INET")  else 2
            AF_LINK  = -1

            import socket as _s
            for addr in iface_addrs:
                if addr.family == _s.AF_INET:
                    info["ip"]        = addr.address or ""
                    info["netmask"]   = addr.netmask or ""
                    info["broadcast"] = addr.broadcast or ""
                elif addr.family not in (_s.AF_INET, _s.AF_INET6):
                    # MAC address (platform-specific family number)
                    if addr.address and ":" in addr.address or "-" in addr.address:
                        info["mac"] = addr.address.replace("-", ":").lower()

            if info["ip"]:
                interfaces.append(info)
    except Exception as e:
        logger.warning(f"Interface enumeration error: {e}")
    return interfaces
