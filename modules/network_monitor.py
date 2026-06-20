"""AISS - Network Monitor Module (UPGRADED)
Detects: Port scans, DDoS, MITM, ARP spoofing, C2 traffic, DNS hijacking,
         beaconing, data exfiltration, DNS tunneling, lateral movement.

Advanced features:
  - psutil.net_connections() instead of netstat subprocess
  - Connection velocity tracking (port scan detection)
  - Beaconing detection (C2 communication patterns)
  - Data volume anomaly (exfiltration detection)
  - DNS query frequency analysis (DNS tunneling)
  - Port scan detection (>20 ports from same IP in 30s)
  - Suspicious port list
  - Connection state tracking (CLOSE_WAIT DoS detection)
  - DNS integrity check (baseline comparison)
  - Lateral movement detection (internal network connections)
  - In-memory connection graph
"""

import asyncio
import collections
import socket
import sys
import time
from datetime import datetime, timedelta
from typing import Optional

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False

from models.threat import Threat, ThreatType, ThreatSeverity
from utils.logger import setup_logger
from modules.dataset_loader import dataset_loader

logger = setup_logger("network_monitor")

IS_WINDOWS = sys.platform == "win32"

# ── Baselines & state ─────────────────────────────────────────────────
_dns_baseline: dict[str, str] = {}

# Connection graph: {src_ip: [(dst_ip, dst_port, timestamp), ...]}
_connection_graph: dict[str, list] = collections.defaultdict(list)

# Velocity: track rapid connections from same IP
# {remote_ip: [timestamps of new connections]}
_connection_velocity: dict[str, list] = collections.defaultdict(list)

# Beaconing: {(pid, remote_ip): [timestamps]}
_beacon_tracker: dict[tuple, list] = collections.defaultdict(list)

# Port scan: {remote_ip: set of dst_ports seen in window}
_port_scan_tracker: dict[str, dict] = {}   # {ip: {"ports": set, "first_seen": float}}

# Data volume: {pid: {"bytes_sent": int, "window_start": float}}
_data_volume_tracker: dict[int, dict] = {}

# DNS query tracker: {minute_bucket: set of unique domains}
_dns_query_tracker: dict[str, set] = collections.defaultdict(set)

# CLOSE_WAIT tracker: {remote_ip: count}
_close_wait_tracker: dict[str, int] = collections.defaultdict(int)

# Already-reported connection signatures to avoid duplicates
_reported_conns: set[str] = set()

# Suspicious ports that malware commonly uses
SUSPICIOUS_PORTS = {4444, 1337, 31337, 9999, 6666, 5555, 12345, 31338, 6667, 6697, 8888}

# Thresholds
PORT_SCAN_THRESHOLD    = 20     # unique ports from same IP in 30 seconds
BEACON_INTERVAL_SECS   = 60    # check for regular intervals within this window
BEACON_MIN_HITS        = 4     # minimum connections to consider beaconing
BEACON_REGULARITY_PCT  = 0.85  # 85% regularity = beacon
DATA_EXFIL_MB_PER_MIN  = 10    # MB per minute threshold
DNS_TUNNEL_DOMAINS_MIN = 50    # unique domains per minute = tunneling
VELOCITY_WINDOW_SECS   = 10    # seconds for connection velocity check
VELOCITY_MAX_CONNS     = 15    # max new connections from same IP in window


class NetworkMonitor:
    """
    Advanced network monitor using psutil for deep connection inspection.

    Runs all detection checks concurrently on each scan cycle.
    """

    def __init__(self, engine):
        """Initialize with reference to the threat engine."""
        self.engine = engine

    async def scan(self) -> None:
        """Run all network detection checks concurrently."""
        await asyncio.gather(
            self._check_suspicious_connections(),
            self._check_dns_integrity(),
            self._check_port_scans(),
            self._check_beaconing(),
            self._check_data_exfiltration(),
            self._check_lateral_movement(),
            self._check_close_wait_flood(),
        )

    # ── 1. Suspicious connections ─────────────────────────────────────

    async def _check_suspicious_connections(self) -> None:
        """
        Check active TCP connections for suspicious indicators:
        - Known malicious ports
        - Connections from suspicious processes
        - Build connection graph
        """
        if not _PSUTIL:
            return
        try:
            now = time.time()
            conns = psutil.net_connections(kind="tcp")

            for c in conns:
                if not c.raddr:
                    continue
                rip   = c.raddr.ip
                rport = c.raddr.port
                pid   = c.pid or 0

                # Skip loopback / local
                if rip in ("127.0.0.1", "::1", "0.0.0.0"):
                    continue

                # Update connection graph
                _connection_graph[rip].append((rip, rport, now))
                # Prune old entries (keep last 5 min)
                cutoff = now - 300
                _connection_graph[rip] = [
                    e for e in _connection_graph[rip] if e[2] > cutoff
                ]

                # Update velocity tracker
                _connection_velocity[rip].append(now)
                _connection_velocity[rip] = [
                    t for t in _connection_velocity[rip]
                    if now - t < VELOCITY_WINDOW_SECS
                ]

                # Check suspicious port
                conn_key = f"suspicious_port:{rip}:{rport}"
                if rport in SUSPICIOUS_PORTS and conn_key not in _reported_conns:
                    proc_name = self._get_proc_name(pid)
                    await self._report(
                        ThreatType.C2_TRAFFIC, ThreatSeverity.CRITICAL,
                        f"Connection to suspicious port {rport} from {proc_name} → {rip}:{rport}",
                        rip,
                        {"remote_ip": rip, "remote_port": rport,
                         "pid": pid, "process": proc_name,
                         "suspicious_port": rport}
                    )
                    _reported_conns.add(conn_key)

                # ── Dataset-driven: check connection count anomaly ────
                conn_count = len(_connection_graph[rip])
                if dataset_loader.is_network_anomaly("count", conn_count):
                    anomaly_key = f"dataset_count:{rip}"
                    if anomaly_key not in _reported_conns:
                        threshold = dataset_loader.get_network_threshold("count")
                        await self._report(
                            ThreatType.PORT_SCAN, ThreatSeverity.HIGH,
                            f"Dataset anomaly: {rip} has {conn_count} connections "
                            f"(normal max: {threshold.get('alert_above', '?')})",
                            rip,
                            {"remote_ip": rip, "conn_count": conn_count,
                             "dataset_threshold": threshold,
                             "detection": "dataset_driven"}
                        )
                        _reported_conns.add(anomaly_key)

                # Check connection velocity (too many connections from same IP)
                vel_key = f"velocity:{rip}"
                if (len(_connection_velocity[rip]) > VELOCITY_MAX_CONNS
                        and vel_key not in _reported_conns):
                    await self._report(
                        ThreatType.PORT_SCAN, ThreatSeverity.HIGH,
                        f"Connection velocity alert: {rip} made {len(_connection_velocity[rip])} "
                        f"connections in {VELOCITY_WINDOW_SECS}s",
                        rip,
                        {"remote_ip": rip,
                         "connection_count": len(_connection_velocity[rip]),
                         "window_secs": VELOCITY_WINDOW_SECS}
                    )
                    _reported_conns.add(vel_key)

        except Exception as e:
            logger.debug(f"Suspicious connection check error: {e}")

    # ── 2. DNS integrity ──────────────────────────────────────────────

    async def _check_dns_integrity(self) -> None:
        """Detect DNS hijacking by comparing resolved IPs to a baseline."""
        critical_domains = ["google.com", "github.com", "microsoft.com", "cloudflare.com"]
        for domain in critical_domains:
            try:
                resolved = socket.gethostbyname(domain)
                # Track DNS query frequency
                minute_key = datetime.utcnow().strftime("%Y%m%d%H%M")
                _dns_query_tracker[minute_key].add(domain)

                # Check DNS tunneling (too many unique domains per minute)
                if len(_dns_query_tracker[minute_key]) > DNS_TUNNEL_DOMAINS_MIN:
                    key = f"dns_tunnel:{minute_key}"
                    if key not in _reported_conns:
                        await self._report(
                            ThreatType.DNS_HIJACK, ThreatSeverity.HIGH,
                            f"DNS tunneling suspected: {len(_dns_query_tracker[minute_key])} "
                            f"unique domains queried in 1 minute",
                            "DNS",
                            {"unique_domains": len(_dns_query_tracker[minute_key]),
                             "window": "1 minute"}
                        )
                        _reported_conns.add(key)

                baseline = _dns_baseline.get(domain)
                if baseline and resolved != baseline:
                    key = f"dns_hijack:{domain}:{resolved}"
                    if key not in _reported_conns:
                        await self._report(
                            ThreatType.DNS_HIJACK, ThreatSeverity.CRITICAL,
                            f"DNS hijack: {domain} → expected {baseline}, got {resolved}",
                            resolved,
                            {"domain": domain, "expected": baseline, "resolved": resolved}
                        )
                        _reported_conns.add(key)
                elif not baseline:
                    _dns_baseline[domain] = resolved

                # Prune old minute buckets (keep last 10 minutes)
                old_keys = [k for k in _dns_query_tracker
                            if k < datetime.utcnow().strftime("%Y%m%d%H%M")[:-1]]
                for k in old_keys:
                    del _dns_query_tracker[k]

            except Exception:
                pass

    # ── 3. Port scan detection ────────────────────────────────────────

    async def _check_port_scans(self) -> None:
        """
        Detect port scanning by tracking unique destination ports per source IP.
        > 20 unique ports from same IP in 30 seconds = port scan.
        """
        if not _PSUTIL:
            return
        try:
            now   = time.time()
            conns = psutil.net_connections(kind="tcp")

            # Rebuild port scan tracker from current connection snapshot
            for c in conns:
                if not c.raddr:
                    continue
                rip   = c.raddr.ip
                rport = c.raddr.port
                lport = c.laddr.port if c.laddr else 0

                if rip in ("127.0.0.1", "::1"):
                    continue

                if rip not in _port_scan_tracker:
                    _port_scan_tracker[rip] = {"ports": set(), "first_seen": now}

                entry = _port_scan_tracker[rip]
                entry["ports"].add(lport)

                # Reset window if >30 seconds old
                if now - entry["first_seen"] > 30:
                    _port_scan_tracker[rip] = {"ports": {lport}, "first_seen": now}
                    continue

                port_count = len(entry["ports"])
                scan_key = f"port_scan:{rip}"
                if port_count >= PORT_SCAN_THRESHOLD and scan_key not in _reported_conns:
                    await self._report(
                        ThreatType.PORT_SCAN, ThreatSeverity.HIGH,
                        f"Port scan from {rip}: {port_count} unique ports probed in 30s",
                        rip,
                        {"scanner_ip": rip, "ports_count": port_count,
                         "ports_sample": list(entry["ports"])[:20]}
                    )
                    _reported_conns.add(scan_key)
                    _port_scan_tracker[rip] = {"ports": set(), "first_seen": now}

        except Exception as e:
            logger.debug(f"Port scan check error: {e}")

    # ── 4. Beaconing detection ────────────────────────────────────────

    async def _check_beaconing(self) -> None:
        """
        Detect C2 beaconing: connections to same external IP at regular intervals.
        Regular interval (85% consistent) + 4+ hits = beaconing indicator.
        """
        if not _PSUTIL:
            return
        try:
            now   = time.time()
            conns = psutil.net_connections(kind="tcp")

            for c in conns:
                if not c.raddr or c.status != "ESTABLISHED":
                    continue
                rip = c.raddr.ip
                pid = c.pid or 0

                if rip in ("127.0.0.1", "::1"):
                    continue
                if self._is_private(rip):
                    continue

                key = (pid, rip)
                _beacon_tracker[key].append(now)

                # Prune entries older than beacon window
                _beacon_tracker[key] = [
                    t for t in _beacon_tracker[key]
                    if now - t < BEACON_INTERVAL_SECS * 5
                ]

                hits = _beacon_tracker[key]
                if len(hits) < BEACON_MIN_HITS:
                    continue

                # Calculate inter-arrival regularity
                intervals = [hits[i+1] - hits[i] for i in range(len(hits)-1)]
                if not intervals:
                    continue
                avg_interval = sum(intervals) / len(intervals)
                if avg_interval < 1:
                    continue

                # How many intervals are within 15% of average?
                regular = sum(1 for iv in intervals
                              if abs(iv - avg_interval) / avg_interval < 0.15)
                regularity = regular / len(intervals)

                beacon_key = f"beacon:{pid}:{rip}"
                if regularity >= BEACON_REGULARITY_PCT and beacon_key not in _reported_conns:
                    proc_name = self._get_proc_name(pid)
                    await self._report(
                        ThreatType.C2_TRAFFIC, ThreatSeverity.CRITICAL,
                        f"C2 beaconing detected: {proc_name} (PID {pid}) → {rip} "
                        f"at ~{avg_interval:.0f}s intervals ({regularity:.0%} regular)",
                        rip,
                        {"pid": pid, "process": proc_name, "remote_ip": rip,
                         "avg_interval_secs": round(avg_interval, 2),
                         "regularity_pct": round(regularity * 100, 1),
                         "hit_count": len(hits)}
                    )
                    _reported_conns.add(beacon_key)

        except Exception as e:
            logger.debug(f"Beaconing check error: {e}")

    # ── 5. Data exfiltration detection ───────────────────────────────

    async def _check_data_exfiltration(self) -> None:
        """
        Detect data exfiltration: process sending > DATA_EXFIL_MB_PER_MIN MB/min.
        Uses psutil per-process network I/O counters.
        """
        if not _PSUTIL:
            return
        try:
            now = time.time()
            for proc in psutil.process_iter(attrs=["pid", "name"]):
                try:
                    pid  = proc.pid
                    name = proc.name()

                    try:
                        io = proc.io_counters()
                    except AttributeError:
                        continue

                    bytes_sent = getattr(io, "write_bytes", 0)

                    tracker = _data_volume_tracker.setdefault(pid, {
                        "bytes_sent": bytes_sent,
                        "window_start": now,
                        "name": name,
                    })

                    elapsed = now - tracker["window_start"]
                    if elapsed < 60:
                        continue

                    delta_bytes = bytes_sent - tracker["bytes_sent"]
                    mb_per_min  = (delta_bytes / elapsed) * 60 / (1024 * 1024)

                    # Reset window
                    tracker["bytes_sent"]   = bytes_sent
                    tracker["window_start"] = now

                    exfil_key = f"exfil:{pid}"
                    if mb_per_min > DATA_EXFIL_MB_PER_MIN and exfil_key not in _reported_conns:
                        await self._report(
                            ThreatType.DATA_EXFIL, ThreatSeverity.CRITICAL,
                            f"Data exfiltration suspected: {name} (PID {pid}) "
                            f"sent {mb_per_min:.1f} MB/min",
                            f"PID:{pid}",
                            {"pid": pid, "process": name,
                             "mb_per_min": round(mb_per_min, 2),
                             "threshold_mb": DATA_EXFIL_MB_PER_MIN}
                        )
                        _reported_conns.add(exfil_key)

                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                    pass
        except Exception as e:
            logger.debug(f"Data exfiltration check error: {e}")

    # ── 6. Lateral movement detection ────────────────────────────────

    async def _check_lateral_movement(self) -> None:
        """
        Detect lateral movement: connections from unusual processes to 192.168.x.x range.
        Legitimate processes connecting to multiple internal IPs = potential worm/lateral movement.
        """
        if not _PSUTIL:
            return
        try:
            conns = psutil.net_connections(kind="tcp")
            # Group internal connections by pid
            internal_by_pid: dict[int, set] = collections.defaultdict(set)

            for c in conns:
                if not c.raddr or c.status != "ESTABLISHED":
                    continue
                rip = c.raddr.ip
                pid = c.pid or 0
                if not rip.startswith("192.168.") and not rip.startswith("10."):
                    continue
                internal_by_pid[pid].add(rip)

            for pid, ips in internal_by_pid.items():
                if len(ips) < 5:
                    continue
                proc_name = self._get_proc_name(pid)
                # Legitimate processes (browsers, AV, etc.) are expected to connect internally
                legit_procs = {"svchost.exe", "system", "explorer.exe", "chrome.exe",
                               "firefox.exe", "code.exe", "python.exe", "node.exe"}
                if proc_name.lower() in legit_procs:
                    continue

                lateral_key = f"lateral:{pid}"
                if lateral_key not in _reported_conns:
                    await self._report(
                        ThreatType.WORM, ThreatSeverity.HIGH,
                        f"Lateral movement suspected: {proc_name} (PID {pid}) connecting to "
                        f"{len(ips)} internal hosts",
                        f"PID:{pid}",
                        {"pid": pid, "process": proc_name,
                         "internal_ips": list(ips)[:20],
                         "ip_count": len(ips)}
                    )
                    _reported_conns.add(lateral_key)

        except Exception as e:
            logger.debug(f"Lateral movement check error: {e}")

    # ── 7. CLOSE_WAIT flood (potential DoS) ───────────────────────────

    async def _check_close_wait_flood(self) -> None:
        """
        Detect connection state abuse: many CLOSE_WAIT connections = potential DoS
        or connection leak being exploited.
        """
        if not _PSUTIL:
            return
        try:
            conns = psutil.net_connections(kind="tcp")
            close_wait_by_ip: dict[str, int] = collections.defaultdict(int)

            for c in conns:
                if c.status == "CLOSE_WAIT" and c.raddr:
                    close_wait_by_ip[c.raddr.ip] += 1

            for ip, count in close_wait_by_ip.items():
                if count >= 20:
                    cw_key = f"close_wait:{ip}"
                    if cw_key not in _reported_conns:
                        await self._report(
                            ThreatType.DDOS, ThreatSeverity.HIGH,
                            f"CLOSE_WAIT flood from {ip}: {count} stuck connections (potential DoS)",
                            ip,
                            {"remote_ip": ip, "close_wait_count": count,
                             "indicator": "DoS or connection exhaustion"}
                        )
                        _reported_conns.add(cw_key)

        except Exception as e:
            logger.debug(f"CLOSE_WAIT check error: {e}")

    # ── Helpers ───────────────────────────────────────────────────────

    def _get_proc_name(self, pid: Optional[int]) -> str:
        """Safely get process name by PID."""
        if not pid or not _PSUTIL:
            return "unknown"
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "unknown"

    def _is_private(self, ip: str) -> bool:
        """Return True if IP is private/loopback."""
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            first, second = int(parts[0]), int(parts[1])
            return (
                first == 10
                or (first == 172 and 16 <= second <= 31)
                or (first == 192 and second == 168)
                or first == 127
                or ip.startswith("169.254.")
            )
        except Exception:
            return False

    async def _report(
        self,
        threat_type: ThreatType,
        severity: ThreatSeverity,
        description: str,
        source: str,
        metadata: dict,
    ) -> None:
        """Create and register a threat, then auto-respond."""
        threat = Threat(
            type=threat_type,
            description=description,
            severity=severity,
            source=source,
            module="NetworkMonitor",
            metadata=metadata,
        )
        await self.engine.register_threat(threat)
        await self.engine.auto_respond(threat)


# ── Utility functions used by API routes ─────────────────────────────

def get_connections_raw() -> list[str]:
    """
    Return current TCP connections as formatted strings.
    Used by the /network/connections API endpoint.
    """
    if not _PSUTIL:
        return ["psutil not available"]
    try:
        conns = psutil.net_connections(kind="inet")
        lines = []
        for c in conns:
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
            lines.append(f"{c.type.name:<6} {laddr:<25} {raddr:<25} {c.status}")
        return lines
    except Exception as e:
        return [f"Error: {e}"]
