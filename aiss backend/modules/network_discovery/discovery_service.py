"""Network Discovery Engine — Core Service

Implements:
  1. Live Host Discovery  (ping3 ICMP, Scapy ARP, nmap ping sweep)
  2. Port Scanning        (nmap: SYN/Connect/UDP/FIN/Xmas/Null)
  3. Service Detection    (nmap -sV + banner grabbing)
  4. MAC Address Detection (Scapy ARP, psutil)
  5. OS Detection         (nmap -O + TTL heuristic)
  6. Banner Grabbing      (raw socket TCP connect)
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from utils.logger import setup_logger
from modules.network_discovery.schemas import (
    HostInfo, PortInfo, DiscoveryResult, PortScanResult,
)
from modules.network_discovery.utils import (
    get_mac_vendor, resolve_hostname, parse_port_spec,
    service_name, ttl_to_os_guess, expand_cidr, is_valid_cidr,
)

logger = setup_logger("network_discovery")

# ── Optional heavy imports — graceful degradation if not available ────
try:
    import nmap as _nmap
    _NMAP_OK = True
    logger.info("✅ python-nmap available")
except ImportError:
    _NMAP_OK = False
    logger.warning("⚠  python-nmap not available — nmap scans disabled")

try:
    import ping3
    _PING3_OK = True
except ImportError:
    _PING3_OK = False

try:
    from scapy.all import ARP, Ether, srp, IP, ICMP, sr1, TCP, sr
    _SCAPY_OK = True
    logger.info("✅ scapy available")
except ImportError:
    _SCAPY_OK = False
    logger.warning("⚠  scapy not available — ARP scans disabled")


# ══════════════════════════════════════════════════════════════════════
# Host Discovery
# ══════════════════════════════════════════════════════════════════════

class HostDiscoveryEngine:
    """
    Discovers live hosts using multiple methods:
      1. ICMP ping  (ping3)
      2. ARP scan   (scapy — LAN only, requires root/admin)
      3. nmap ping  (nmap -sn)
    Falls back gracefully if tools are unavailable.
    """

    async def ping_host(self, ip: str, timeout: float = 2.0) -> Optional[float]:
        """
        ICMP ping using ping3.
        Returns RTT in ms or None if unreachable.
        Runs in executor to avoid blocking the event loop.
        """
        if not _PING3_OK:
            return await self._socket_ping(ip, timeout)

        loop = asyncio.get_event_loop()
        try:
            rtt = await loop.run_in_executor(
                None,
                lambda: ping3.ping(ip, timeout=timeout, unit="ms")
            )
            return rtt if rtt is not None else None
        except Exception:
            return None

    async def _socket_ping(self, ip: str, timeout: float) -> Optional[float]:
        """Fallback TCP ping on port 80 to check host liveliness."""
        loop = asyncio.get_event_loop()
        t0   = time.monotonic()
        try:
            conn = asyncio.open_connection(ip, 80)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            return (time.monotonic() - t0) * 1000
        except Exception:
            pass
        # Also try port 443
        try:
            conn = asyncio.open_connection(ip, 443)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            return (time.monotonic() - t0) * 1000
        except Exception:
            return None

    async def arp_scan(self, cidr: str, timeout: float = 2.0) -> List[HostInfo]:
        """
        ARP sweep across a LAN subnet using Scapy.
        More accurate than ICMP for local network discovery.
        Requires root/admin privileges.
        """
        if not _SCAPY_OK:
            logger.warning("Scapy not available — skipping ARP scan")
            return []

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._arp_scan_sync, cidr, timeout)

    def _arp_scan_sync(self, cidr: str, timeout: float) -> List[HostInfo]:
        hosts = []
        try:
            arp_req   = ARP(pdst=cidr)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet    = broadcast / arp_req

            answered, _ = srp(packet, timeout=timeout, verbose=False)

            for sent, received in answered:
                mac    = received.hwsrc.lower()
                ip     = received.psrc
                vendor = get_mac_vendor(mac)
                host   = HostInfo(
                    ip=ip,
                    mac=mac,
                    mac_vendor=vendor,
                    hostname=resolve_hostname(ip),
                    status="up",
                )
                hosts.append(host)
        except Exception as e:
            logger.error(f"ARP scan error: {e}")
        return hosts

    async def nmap_ping_sweep(self, target: str, timeout: float = 5.0) -> List[HostInfo]:
        """
        nmap -sn (ping sweep) — most reliable host discovery.
        Works across subnets, doesn't require admin for basic pings.
        """
        if not _NMAP_OK:
            return await self._manual_ping_sweep(target, timeout)

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._nmap_ping_sync, target, timeout)

    def _nmap_ping_sync(self, target: str, timeout: float) -> List[HostInfo]:
        hosts = []
        try:
            nm = _nmap.PortScanner()
            nm.scan(hosts=target, arguments=f"-sn -T4 --host-timeout {int(timeout)}s")

            for host in nm.all_hosts():
                state    = nm[host].state()
                hostname = ""
                try:
                    hostnames = nm[host].hostname()
                    hostname  = hostnames if isinstance(hostnames, str) else ""
                except Exception:
                    pass

                mac    = nm[host].get("addresses", {}).get("mac", "")
                vendor = get_mac_vendor(mac) if mac else ""
                os_info = ""
                try:
                    osmatch = nm[host].get("osmatch", [])
                    if osmatch:
                        os_info = osmatch[0].get("name", "")
                except Exception:
                    pass

                hosts.append(HostInfo(
                    ip=host,
                    hostname=hostname or resolve_hostname(host),
                    mac=mac.lower() if mac else "",
                    mac_vendor=vendor,
                    status=state,
                    os_guess=os_info,
                ))
        except Exception as e:
            logger.error(f"nmap ping sweep error: {e}")
        return hosts

    async def _manual_ping_sweep(self, target: str, timeout: float) -> List[HostInfo]:
        """Fallback: concurrent asyncio pings when nmap is unavailable."""
        if is_valid_cidr(target):
            ips = expand_cidr(target)
        else:
            ips = [target]

        tasks = [self.ping_host(ip, timeout) for ip in ips]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        hosts = []
        for ip, rtt in zip(ips, results):
            if isinstance(rtt, float) and rtt is not None:
                hosts.append(HostInfo(
                    ip=ip,
                    hostname=resolve_hostname(ip),
                    status="up",
                    response_time_ms=rtt,
                ))
        return hosts


# ══════════════════════════════════════════════════════════════════════
# Port Scanner
# ══════════════════════════════════════════════════════════════════════

class PortScanEngine:
    """
    Port scanning via nmap (primary) with asyncio connect fallback.
    Scan types: SYN (-sS), Connect (-sT), UDP (-sU), FIN (-sF), Xmas (-sX), Null (-sN)
    """

    NMAP_FLAGS = {
        "syn":     "-sS",
        "connect": "-sT",
        "udp":     "-sU",
        "fin":     "-sF",
        "xmas":    "-sX",
        "null":    "-sN",
    }

    async def scan(
        self,
        target: str,
        ports: str = "1-1024",
        scan_type: str = "connect",
        timeout: float = 5.0,
        max_rate: int = 500,
        grab_banners: bool = True,
    ) -> PortScanResult:
        t0 = time.monotonic()

        # On Windows or without root, fall back to connect scan
        import sys
        if sys.platform == "win32" and scan_type == "syn":
            scan_type = "connect"

        if _NMAP_OK:
            result = await self._nmap_scan(target, ports, scan_type, timeout, max_rate)
        else:
            result = await self._asyncio_scan(target, ports, timeout)

        # Banner grabbing for open ports
        if grab_banners and result.open_ports:
            loop = asyncio.get_event_loop()
            for port_info in result.open_ports:
                if port_info.state == "open" and not port_info.banner:
                    banner = await self._grab_banner(target, port_info.port, timeout=3.0)
                    if banner:
                        port_info.banner = banner

        result.scan_duration_secs = round(time.monotonic() - t0, 3)
        return result

    async def _nmap_scan(
        self,
        target: str,
        ports: str,
        scan_type: str,
        timeout: float,
        max_rate: int,
    ) -> PortScanResult:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._nmap_scan_sync, target, ports, scan_type, timeout, max_rate
        )

    def _nmap_scan_sync(
        self,
        target: str,
        ports: str,
        scan_type: str,
        timeout: float,
        max_rate: int,
    ) -> PortScanResult:
        open_ports   = []
        filtered     = 0
        closed       = 0
        errors       = []
        ip           = ""

        try:
            nm    = _nmap.PortScanner()
            flag  = self.NMAP_FLAGS.get(scan_type, "-sT")
            # -sV: version detection, -T4: aggressive timing, --max-rate: rate limit
            args  = f"{flag} -sV -T4 --max-rate {max_rate} --host-timeout {int(timeout)}s"

            if ports.lower() in ("common", "top100"):
                port_arg = ",".join(str(p) for p in [21,22,23,25,53,80,110,443,445,3306,3389,8080])
            else:
                port_arg = ports

            nm.scan(hosts=target, ports=port_arg, arguments=args)

            for host in nm.all_hosts():
                ip = host
                for proto in nm[host].all_protocols():
                    for port, data in nm[host][proto].items():
                        state = data.get("state", "unknown")
                        if state == "open":
                            svc_name = data.get("name", service_name(port, proto))
                            version  = f"{data.get('product','')} {data.get('version','')}".strip()
                            cpe      = data.get("cpe", "")

                            open_ports.append(PortInfo(
                                port=port,
                                protocol=proto,
                                state="open",
                                service=svc_name,
                                version=version,
                                cpe=cpe,
                            ))
                        elif state == "filtered":
                            filtered += 1
                        else:
                            closed += 1

        except Exception as e:
            errors.append(str(e))
            logger.error(f"nmap port scan error on {target}: {e}")

        if not ip:
            try:
                ip = socket.gethostbyname(target)
            except Exception:
                ip = target

        return PortScanResult(
            target=target,
            ip=ip,
            scan_type=scan_type,
            ports_scanned=len(open_ports) + filtered + closed,
            open_ports=open_ports,
            filtered_ports=filtered,
            closed_ports=closed,
            scan_duration_secs=0.0,
            errors=errors,
        )

    async def _asyncio_scan(self, target: str, ports: str, timeout: float) -> PortScanResult:
        """
        Pure asyncio port scanner — no nmap dependency.
        Uses TCP connect to probe each port concurrently.
        """
        port_list  = parse_port_spec(ports)
        semaphore  = asyncio.Semaphore(200)   # max 200 concurrent connections
        open_ports = []
        closed     = 0

        try:
            ip = socket.gethostbyname(target)
        except Exception:
            ip = target

        async def probe(port: int) -> Optional[PortInfo]:
            async with semaphore:
                try:
                    conn = asyncio.open_connection(ip, port)
                    reader, writer = await asyncio.wait_for(conn, timeout=timeout)
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    return PortInfo(
                        port=port,
                        protocol="tcp",
                        state="open",
                        service=service_name(port),
                    )
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    return None

        tasks   = [probe(p) for p in port_list]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, PortInfo):
                open_ports.append(r)
            elif r is None:
                closed += 1

        return PortScanResult(
            target=target,
            ip=ip,
            scan_type="connect",
            ports_scanned=len(port_list),
            open_ports=open_ports,
            filtered_ports=0,
            closed_ports=closed,
            scan_duration_secs=0.0,
        )

    async def _grab_banner(self, host: str, port: int, timeout: float = 3.0) -> str:
        """
        Attempt banner grabbing via raw TCP connect.
        Sends a generic HTTP/probe and reads first 1024 bytes.
        """
        banner = ""
        probes = [
            b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n",
            b"\r\n",
            b"HELP\r\n",
            b"",  # just read banner without sending
        ]
        for probe in probes:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=timeout
                )
                if probe:
                    writer.write(probe)
                    await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                banner = data.decode("utf-8", errors="replace").strip()[:512]
                if banner:
                    return banner
            except Exception:
                continue
        return banner


# ══════════════════════════════════════════════════════════════════════
# OS Detection
# ══════════════════════════════════════════════════════════════════════

class OSDetectionEngine:
    """OS fingerprinting via nmap -O + TTL heuristic fallback."""

    async def detect(self, target: str, timeout: float = 10.0) -> tuple[str, int]:
        """Returns (os_guess, confidence_percent)."""
        if _NMAP_OK:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._nmap_os_sync, target, timeout)
        return await self._ttl_os_guess(target)

    def _nmap_os_sync(self, target: str, timeout: float) -> tuple[str, int]:
        try:
            nm = _nmap.PortScanner()
            nm.scan(hosts=target, arguments=f"-O -T4 --host-timeout {int(timeout)}s")
            for host in nm.all_hosts():
                osmatch = nm[host].get("osmatch", [])
                if osmatch:
                    best = osmatch[0]
                    name = best.get("name", "Unknown")
                    acc  = int(best.get("accuracy", 0))
                    return name, acc
        except Exception as e:
            logger.warning(f"nmap OS detect error on {target}: {e}")
        return "Unknown", 0

    async def _ttl_os_guess(self, target: str) -> tuple[str, int]:
        """Guess OS from ICMP TTL value — works without nmap."""
        if not _SCAPY_OK:
            return "Unknown", 0
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._scapy_ttl_sync, target)

    def _scapy_ttl_sync(self, target: str) -> tuple[str, int]:
        try:
            pkt  = IP(dst=target) / ICMP()
            resp = sr1(pkt, timeout=2, verbose=False)
            if resp:
                ttl  = resp.ttl
                os   = ttl_to_os_guess(ttl)
                conf = 50  # TTL-based is only 50% confidence
                return os, conf
        except Exception:
            pass
        return "Unknown", 0


# ══════════════════════════════════════════════════════════════════════
# Full Discovery Orchestrator
# ══════════════════════════════════════════════════════════════════════

class NetworkDiscoveryService:
    """
    Orchestrates all discovery phases and persists results to MySQL.
    This is the main entry point used by the API routes.
    """

    def __init__(self):
        self.host_engine = HostDiscoveryEngine()
        self.port_engine = PortScanEngine()
        self.os_engine   = OSDetectionEngine()

    async def discover_hosts(
        self,
        target: str,
        method: str = "nmap",
        timeout: float = 5.0,
        db: Optional[AsyncSession] = None,
    ) -> DiscoveryResult:
        t0 = time.monotonic()
        scan_id = None
        errors  = []

        # Persist scan record
        if db:
            scan_id = await self._create_scan_record(db, "host_discovery", target)

        try:
            if method == "arp" and is_valid_cidr(target):
                hosts = await self.host_engine.arp_scan(target, timeout)
            else:
                hosts = await self.host_engine.nmap_ping_sweep(target, timeout)

            up   = [h for h in hosts if h.status == "up"]
            down = [h for h in hosts if h.status != "up"]
            dur  = round(time.monotonic() - t0, 3)

            result = DiscoveryResult(
                target=target,
                scan_type=f"host_discovery_{method}",
                hosts_found=len(hosts),
                hosts_up=len(up),
                hosts_down=len(down),
                scan_duration_secs=dur,
                hosts=hosts,
            )

            if db and scan_id:
                await self._complete_scan_record(
                    db, scan_id, "completed",
                    hosts_found=len(hosts),
                    hosts_up=len(up),
                    result=result.model_dump(),
                    duration=dur,
                )
            return result

        except Exception as e:
            errors.append(str(e))
            logger.error(f"Host discovery failed: {e}")
            if db and scan_id:
                await self._fail_scan_record(db, scan_id, str(e))
            return DiscoveryResult(
                target=target, scan_type="host_discovery",
                hosts_found=0, hosts_up=0, hosts_down=0,
                scan_duration_secs=round(time.monotonic() - t0, 3),
                hosts=[], errors=errors,
            )

    async def scan_ports(
        self,
        target: str,
        ports: str = "1-1024",
        scan_type: str = "connect",
        timeout: float = 5.0,
        max_rate: int = 500,
        grab_banners: bool = True,
        db: Optional[AsyncSession] = None,
    ) -> PortScanResult:
        t0      = time.monotonic()
        scan_id = None

        if db:
            scan_id = await self._create_scan_record(db, "port_scan", target)

        result = await self.port_engine.scan(
            target=target,
            ports=ports,
            scan_type=scan_type,
            timeout=timeout,
            max_rate=max_rate,
            grab_banners=grab_banners,
        )

        dur = round(time.monotonic() - t0, 3)
        result.scan_duration_secs = dur

        if db and scan_id:
            await self._complete_scan_record(
                db, scan_id, "completed",
                hosts_found=1,
                hosts_up=1 if result.open_ports else 0,
                result=result.model_dump(),
                duration=dur,
                open_ports_count=len(result.open_ports),
            )
        return result

    async def full_scan(
        self,
        target: str,
        port_range: str = "1-1024",
        scan_type: str = "connect",
        detect_os: bool = True,
        detect_services: bool = True,
        grab_banners: bool = True,
        timeout: float = 30.0,
        max_rate: int = 500,
        db: Optional[AsyncSession] = None,
    ) -> DiscoveryResult:
        """
        Full discovery pipeline:
          1. Host discovery
          2. Port scan
          3. Service/version detection
          4. OS fingerprinting
          5. MAC + hostname resolution
        """
        t0      = time.monotonic()
        scan_id = None
        errors  = []

        if db:
            scan_id = await self._create_scan_record(db, "full_scan", target)

        try:
            # Phase 1: discover live hosts
            if is_valid_cidr(target):
                discovery = await self.discover_hosts(target, timeout=timeout)
                live_hosts = [h.ip for h in discovery.hosts if h.status == "up"]
            else:
                live_hosts = [target]

            enriched_hosts: List[HostInfo] = []

            for ip in live_hosts:
                host_info = HostInfo(ip=ip, hostname=resolve_hostname(ip), status="up")

                # Phase 2: port scan
                port_result = await self.scan_ports(
                    target=ip,
                    ports=port_range,
                    scan_type=scan_type,
                    timeout=timeout,
                    max_rate=max_rate,
                    grab_banners=grab_banners,
                )
                host_info.ports      = port_result.open_ports
                host_info.open_ports = [p.port for p in port_result.open_ports]
                host_info.services   = {
                    str(p.port): p.service for p in port_result.open_ports if p.service
                }

                # Phase 3: OS detection
                if detect_os:
                    os_guess, conf = await self.os_engine.detect(ip, timeout=min(timeout, 15))
                    host_info.os_guess       = os_guess
                    host_info.os_confidence  = conf

                enriched_hosts.append(host_info)

            dur    = round(time.monotonic() - t0, 3)
            result = DiscoveryResult(
                target=target,
                scan_type="full_scan",
                hosts_found=len(enriched_hosts),
                hosts_up=len([h for h in enriched_hosts if h.status == "up"]),
                hosts_down=0,
                scan_duration_secs=dur,
                hosts=enriched_hosts,
                errors=errors,
            )

            if db and scan_id:
                total_open = sum(len(h.open_ports) for h in enriched_hosts)
                await self._complete_scan_record(
                    db, scan_id, "completed",
                    hosts_found=len(enriched_hosts),
                    hosts_up=len(enriched_hosts),
                    result=result.model_dump(),
                    duration=dur,
                    open_ports_count=total_open,
                )
            return result

        except Exception as e:
            errors.append(str(e))
            logger.error(f"Full scan failed for {target}: {e}")
            if db and scan_id:
                await self._fail_scan_record(db, scan_id, str(e))
            return DiscoveryResult(
                target=target, scan_type="full_scan",
                hosts_found=0, hosts_up=0, hosts_down=0,
                scan_duration_secs=round(time.monotonic() - t0, 3),
                hosts=[], errors=errors,
            )

    # ── DB helpers ────────────────────────────────────────────────────

    async def _create_scan_record(
        self, db: AsyncSession, scan_type: str, target: str
    ) -> Optional[str]:
        try:
            from modules.network_discovery.models import NetworkScan
            import uuid as _uuid
            scan_id = str(_uuid.uuid4())
            db.add(NetworkScan(
                id=scan_id, scan_type=scan_type, target=target, status="running"
            ))
            await db.flush()
            return scan_id
        except Exception as e:
            logger.warning(f"Could not create scan record: {e}")
            return None

    async def _complete_scan_record(
        self,
        db: AsyncSession,
        scan_id: str,
        status: str,
        hosts_found: int = 0,
        hosts_up: int = 0,
        result: dict = None,
        duration: float = 0.0,
        open_ports_count: int = 0,
    ) -> None:
        try:
            from modules.network_discovery.models import NetworkScan
            from sqlalchemy import select
            rec = await db.get(NetworkScan, scan_id)
            if rec:
                rec.status           = status
                rec.hosts_found      = hosts_found
                rec.hosts_up         = hosts_up
                rec.open_ports_count = open_ports_count
                rec.duration_secs    = duration
                rec.result           = result
                rec.completed_at     = datetime.utcnow()
                await db.flush()
        except Exception as e:
            logger.warning(f"Could not update scan record: {e}")

    async def _fail_scan_record(
        self, db: AsyncSession, scan_id: str, error: str
    ) -> None:
        try:
            from modules.network_discovery.models import NetworkScan
            rec = await db.get(NetworkScan, scan_id)
            if rec:
                rec.status        = "failed"
                rec.error_message = error
                rec.completed_at  = datetime.utcnow()
                await db.flush()
        except Exception as e:
            logger.warning(f"Could not fail scan record: {e}")


# ── Module-level singleton ────────────────────────────────────────────
discovery_service = NetworkDiscoveryService()
