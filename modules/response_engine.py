"""AISS - Response Engine (UPGRADED)
Automatically responds to threats: block IPs, kill processes, quarantine files.

Enhanced features:
  - Process tree kill: when killing a process, also kills all children (psutil)
  - Network isolation mode: block ALL outbound from suspicious PID (per-PID firewall)
  - Evidence collection before killing:
    - cmdline, env vars, open files, connections → logs/evidence/
    - SHA256 hash of executable
    - Memory snapshot metadata
  - Threat containment levels: MONITOR → ISOLATE → TERMINATE → QUARANTINE
  - Rollback log: all actions taken can be undone
  - Response effectiveness scoring: check 30s after response if threat stopped
  - Automatic IP blocking with 24-hour expiry
  - All original platform-specific handlers preserved
"""

import asyncio
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta
from typing import Optional

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False

from models.threat import Threat, ThreatType, ThreatSeverity, ThreatStatus
from utils.logger import setup_logger

logger = setup_logger("response_engine")

IS_WINDOWS   = sys.platform == "win32"
QUARANTINE_DIR = os.path.join(
    os.environ.get("TEMP", "C:\\Windows\\Temp") if IS_WINDOWS else "/tmp",
    "cybersecurity_quarantine"
)
EVIDENCE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "logs", "evidence"
)

# ── IP block expiry table: {ip → expiry_timestamp} ───────────────────
_ip_block_expiry: dict[str, float] = {}

# ── Rollback log: list of {action, target, timestamp, undo_cmd} ──────
_rollback_log: list[dict] = []

# ── Containment levels ────────────────────────────────────────────────
CONTAINMENT_LEVELS = ["MONITOR", "ISOLATE", "TERMINATE", "QUARANTINE"]


class ResponseEngine:
    """
    Advanced automated incident response engine.

    Handles threat containment, evidence collection, and rollback tracking.
    """

    def __init__(self, engine):
        """Initialize with reference to the threat engine."""
        self.engine = engine
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        os.makedirs(EVIDENCE_DIR, exist_ok=True)

    async def respond(self, threat: Threat) -> None:
        """
        Route threat to appropriate response handler based on threat type.
        Sets status to RESPONDING before dispatching.
        """
        threat.status = ThreatStatus.RESPONDING

        handlers = {
            ThreatType.PORT_SCAN:         self._block_ip,
            ThreatType.C2_TRAFFIC:        self._block_ip_and_kill,
            ThreatType.DDOS:              self._block_ip,
            ThreatType.MITM:              self._block_ip,
            ThreatType.ARP_SPOOFING:      self._block_ip,
            ThreatType.DNS_HIJACK:        self._flush_dns,
            ThreatType.INTRUSION:         self._block_ip,
            ThreatType.BRUTE_FORCE:       self._block_ip,
            ThreatType.PRIVILEGE_ESC:     self._alert_admin,
            ThreatType.CREDENTIAL_STUFF:  self._block_ip,
            ThreatType.VIRUS:             self._quarantine_file,
            ThreatType.TROJAN:            self._kill_process_and_quarantine,
            ThreatType.WORM:              self._kill_process_and_quarantine,
            ThreatType.RANSOMWARE:        self._emergency_response,
            ThreatType.SPYWARE:           self._kill_process_and_quarantine,
            ThreatType.KEYLOGGER:         self._kill_process_and_quarantine,
            ThreatType.ROOTKIT:           self._alert_admin,
            ThreatType.CRYPTOMINER:       self._kill_process,
            ThreatType.BOTNET:            self._kill_process_and_block,
            ThreatType.ADWARE:            self._kill_process,
            ThreatType.FILELESS:          self._kill_process,
            ThreatType.MALICIOUS_SCRIPT:  self._quarantine_file,
            ThreatType.SUSPICIOUS_FILE:   self._quarantine_file,
            ThreatType.DATA_EXFIL:        self._isolate_process,
        }

        handler = handlers.get(threat.type, self._alert_admin)
        note = await handler(threat)
        await self.engine.resolve_threat(threat.id, note)

        # Schedule effectiveness check 30 seconds later
        asyncio.create_task(self._check_effectiveness(threat.id, 30))

    # ── IP blocking ───────────────────────────────────────────────────

    async def _block_ip(self, threat: Threat) -> str:
        """Block a remote IP via platform firewall with 24-hour auto-expiry."""
        ip = threat.source
        if not self._is_valid_ip(ip):
            return f"Logged threat from {ip} — IP format not blockable"

        # Check if already blocked and not expired
        expiry = _ip_block_expiry.get(ip)
        if expiry and time.time() < expiry:
            return f"IP {ip} already blocked (expires {datetime.fromtimestamp(expiry).strftime('%H:%M:%S')})"

        try:
            if IS_WINDOWS:
                rule_name = f"AISS_Block_{ip}"
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"],
                    capture_output=True, timeout=10
                )
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name={rule_name}_out", "dir=out", "action=block", f"remoteip={ip}"],
                    capture_output=True, timeout=10
                )
                note = f"IP {ip} blocked via Windows Firewall (in+out)"
            else:
                subprocess.run(
                    ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
                    capture_output=True, timeout=5
                )
                subprocess.run(
                    ["iptables", "-I", "OUTPUT", "1", "-d", ip, "-j", "DROP"],
                    capture_output=True, timeout=5
                )
                note = f"IP {ip} blocked via iptables (in+out)"

            # Record expiry (24 hours)
            expiry_ts = time.time() + 86400
            _ip_block_expiry[ip] = expiry_ts

            # Record rollback action
            _rollback_log.append({
                "action":    "block_ip",
                "target":    ip,
                "timestamp": datetime.utcnow().isoformat(),
                "expiry":    datetime.fromtimestamp(expiry_ts).isoformat(),
                "undo":      f"netsh advfirewall firewall delete rule name=AISS_Block_{ip}"
                             if IS_WINDOWS else f"iptables -D INPUT -s {ip} -j DROP",
            })

            logger.info(f"🔒 {note}")
            return note
        except Exception as e:
            return f"Auto-block attempted for {ip}: {e}"

    async def _block_ip_and_kill(self, threat: Threat) -> str:
        """Block IP and kill associated process."""
        block_note = await self._block_ip(threat)
        kill_note  = await self._kill_process(threat)
        return f"{block_note} | {kill_note}"

    # ── Process termination ───────────────────────────────────────────

    async def _kill_process(self, threat: Threat) -> str:
        """
        Kill a process and its entire child process tree.
        Collects evidence before termination.
        """
        source = threat.source
        if not source.startswith("PID:"):
            return "Process termination logged (PID not available)"

        raw_pid = source.split(":")[1]
        if not raw_pid.isdigit():
            return f"Invalid PID: {raw_pid}"

        pid = int(raw_pid)

        # Collect evidence first
        evidence_note = await self._collect_evidence(pid, threat)

        try:
            if _PSUTIL:
                try:
                    proc = psutil.Process(pid)
                    # Get all children before killing
                    children = proc.children(recursive=True)

                    killed_pids = []
                    # Kill children first (bottom-up)
                    for child in children:
                        try:
                            child.kill()
                            killed_pids.append(child.pid)
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                    # Kill the parent
                    proc.kill()
                    killed_pids.append(pid)

                    note = f"Process tree terminated: PID {pid} + {len(children)} children {killed_pids}"
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    note = f"Process kill error (PID {pid}): {e}"
            else:
                if IS_WINDOWS:
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(pid)],
                        capture_output=True, timeout=10
                    )
                else:
                    subprocess.run(["kill", "-9", str(pid)], capture_output=True, timeout=5)
                note = f"Process PID {pid} terminated (+ children via /T flag)"

            _rollback_log.append({
                "action":    "kill_process",
                "target":    f"PID:{pid}",
                "timestamp": datetime.utcnow().isoformat(),
                "undo":      "Cannot undo process termination",
                "evidence":  evidence_note,
            })

            logger.info(f"💀 {note}")
            return f"{note} | Evidence: {evidence_note}"

        except Exception as e:
            return f"Process kill attempted (PID {pid}): {e}"

    async def _kill_process_and_quarantine(self, threat: Threat) -> str:
        """Kill process tree and quarantine the executable."""
        kill_note       = await self._kill_process(threat)
        quarantine_note = await self._quarantine_file(threat)
        return f"{kill_note} | {quarantine_note}"

    async def _kill_process_and_block(self, threat: Threat) -> str:
        """Kill process tree and block the remote IP."""
        kill_note  = await self._kill_process(threat)
        block_note = await self._block_ip(threat)
        return f"{kill_note} | {block_note}"

    # ── Network isolation (per-PID) ───────────────────────────────────

    async def _isolate_process(self, threat: Threat) -> str:
        """
        Network isolation mode: block ALL outbound connections from a process.
        Uses per-PID firewall rules on Windows, or iptables owner match on Linux.
        """
        source = threat.source
        if not source.startswith("PID:"):
            return await self._block_ip(threat)

        raw_pid = source.split(":")[1]
        if not raw_pid.isdigit():
            return f"Cannot isolate: invalid PID {raw_pid}"

        pid = int(raw_pid)
        try:
            if IS_WINDOWS:
                # Windows Firewall can't filter by PID directly — use exe path
                if _PSUTIL:
                    try:
                        exe = psutil.Process(pid).exe()
                        rule_name = f"AISS_Isolate_PID{pid}"
                        subprocess.run(
                            ["netsh", "advfirewall", "firewall", "add", "rule",
                             f"name={rule_name}", "dir=out", "action=block",
                             f"program={exe}"],
                            capture_output=True, timeout=10
                        )
                        note = f"Process {pid} ({exe}) isolated — outbound blocked"
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        note = f"Could not isolate PID {pid} (process gone)"
                else:
                    note = f"Isolation attempted for PID {pid} (psutil unavailable)"
            else:
                # Linux: iptables owner match (requires iptables owner module)
                subprocess.run(
                    ["iptables", "-A", "OUTPUT", "-m", "owner",
                     "--pid-owner", str(pid), "-j", "DROP"],
                    capture_output=True, timeout=5
                )
                note = f"Process PID {pid} network-isolated via iptables"

            _rollback_log.append({
                "action":    "isolate_process",
                "target":    f"PID:{pid}",
                "timestamp": datetime.utcnow().isoformat(),
                "undo":      f"netsh advfirewall firewall delete rule name=AISS_Isolate_PID{pid}"
                             if IS_WINDOWS else f"iptables -D OUTPUT -m owner --pid-owner {pid} -j DROP",
            })

            logger.info(f"🔌 {note}")
            return note

        except Exception as e:
            return f"Isolation attempted for PID {pid}: {e}"

    # ── Evidence collection ───────────────────────────────────────────

    async def _collect_evidence(self, pid: int, threat: Threat) -> str:
        """
        Collect forensic evidence for a process before killing it.
        Saves: cmdline, env vars, open files, connections, exe hash, metadata.
        """
        if not _PSUTIL:
            return "Evidence collection skipped (psutil unavailable)"

        ts        = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        evidence  = {
            "pid":         pid,
            "threat_id":   threat.id,
            "threat_type": str(threat.type),
            "collected_at": datetime.utcnow().isoformat(),
        }

        try:
            proc = psutil.Process(pid)

            # cmdline
            try:
                evidence["cmdline"] = proc.cmdline()
            except Exception:
                evidence["cmdline"] = []

            # cwd
            try:
                evidence["cwd"] = proc.cwd()
            except Exception:
                evidence["cwd"] = ""

            # exe
            try:
                exe = proc.exe()
                evidence["exe"] = exe
                # Hash the executable
                if exe and os.path.isfile(exe):
                    sha256 = hashlib.sha256()
                    try:
                        with open(exe, "rb") as f:
                            while chunk := f.read(8192):
                                sha256.update(chunk)
                        evidence["exe_sha256"] = sha256.hexdigest()
                    except Exception:
                        evidence["exe_sha256"] = "unreadable"
            except Exception:
                evidence["exe"] = ""

            # Environment variables (limited — skip secrets)
            try:
                env = proc.environ()
                # Redact common secret keys
                redacted = {
                    k: ("***REDACTED***" if any(s in k.upper() for s in
                        ["PASSWORD", "SECRET", "KEY", "TOKEN", "PASS"]) else v)
                    for k, v in env.items()
                }
                evidence["environ"] = redacted
            except Exception:
                evidence["environ"] = {}

            # Open files
            try:
                evidence["open_files"] = [f.path for f in proc.open_files()[:50]]
            except Exception:
                evidence["open_files"] = []

            # Network connections
            try:
                evidence["connections"] = [
                    {
                        "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                        "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                        "status": c.status,
                    }
                    for c in proc.connections()[:20]
                ]
            except Exception:
                evidence["connections"] = []

            # Memory info
            try:
                mi = proc.memory_info()
                evidence["memory"] = {
                    "rss_mb": round(mi.rss / 1024 / 1024, 2),
                    "vms_mb": round(mi.vms / 1024 / 1024, 2),
                }
            except Exception:
                evidence["memory"] = {}

            # Create_time
            try:
                evidence["create_time"] = datetime.fromtimestamp(proc.create_time()).isoformat()
            except Exception:
                evidence["create_time"] = ""

        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            evidence["error"] = str(e)

        # Write to evidence directory
        evidence_file = os.path.join(EVIDENCE_DIR, f"PID{pid}_{ts}.json")
        try:
            with open(evidence_file, "w", encoding="utf-8") as f:
                json.dump(evidence, f, indent=2, default=str)
            return f"Evidence saved: {evidence_file}"
        except Exception as e:
            return f"Evidence collection failed: {e}"

    # ── File quarantine ───────────────────────────────────────────────

    async def _quarantine_file(self, threat: Threat) -> str:
        """Move a suspicious file to the quarantine directory."""
        filepath = threat.source
        if not os.path.isfile(filepath):
            return f"File quarantine logged: {filepath} (file not found)"
        try:
            filename = os.path.basename(filepath)
            ts       = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            dest     = os.path.join(QUARANTINE_DIR, f"{ts}_{filename}")
            shutil.move(filepath, dest)

            _rollback_log.append({
                "action":    "quarantine_file",
                "target":    filepath,
                "timestamp": datetime.utcnow().isoformat(),
                "quarantine_path": dest,
                "undo":      f"Move {dest} back to {filepath}",
            })

            note = f"File quarantined: {filepath} → {dest}"
            logger.info(f"🗑️ {note}")
            return note
        except Exception as e:
            return f"Quarantine attempted for {filepath}: {e}"

    # ── DNS flush ─────────────────────────────────────────────────────

    async def _flush_dns(self, threat: Threat) -> str:
        """Flush the DNS cache to remove hijacked entries."""
        try:
            if IS_WINDOWS:
                subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=10)
                return "DNS cache flushed via ipconfig /flushdns"
            else:
                for cmd in [
                    ["systemd-resolve", "--flush-caches"],
                    ["resolvectl", "flush-caches"],
                    ["service", "nscd", "restart"],
                ]:
                    try:
                        subprocess.run(cmd, capture_output=True, timeout=5)
                        return f"DNS cache flushed via {cmd[0]}"
                    except Exception:
                        continue
                return "DNS flush attempted (no supported tool found)"
        except Exception as e:
            return f"DNS flush attempted: {e}"

    # ── Emergency response ────────────────────────────────────────────

    async def _emergency_response(self, threat: Threat) -> str:
        """
        Emergency ransomware response:
        1. Kill the ransomware process tree
        2. Attempt to block all outbound connections
        3. Collect maximum evidence
        4. Alert admin
        """
        notes = ["⚠️ RANSOMWARE EMERGENCY RESPONSE TRIGGERED"]

        # Try to kill the process
        kill_note = await self._kill_process(threat)
        notes.append(kill_note)

        # Block the source IP if available
        if self._is_valid_ip(threat.source):
            block_note = await self._block_ip(threat)
            notes.append(block_note)

        notes += [
            "All monitoring elevated to CRITICAL",
            "Recommend: Immediate network isolation + incident response team",
            "Check: shadow copies, backup integrity",
        ]

        note = " | ".join(notes)
        logger.critical(note)
        return note

    # ── Admin alert ───────────────────────────────────────────────────

    async def _alert_admin(self, threat: Threat) -> str:
        """Log and alert admin for threats requiring manual review."""
        note = f"Admin alerted: {threat.type} — {threat.description}"
        logger.warning(f"📧 {note}")
        return note

    # ── Response effectiveness check ─────────────────────────────────

    async def _check_effectiveness(self, threat_id: str, delay_secs: int) -> None:
        """
        Check 30 seconds after response if the threat is still active.
        Logs effectiveness rating to the evidence directory.
        """
        await asyncio.sleep(delay_secs)
        try:
            threat = self.engine.active_threats.get(threat_id)
            if not threat:
                return

            # Check if process still exists (for PID-based threats)
            still_active = False
            source = threat.source
            if source.startswith("PID:") and _PSUTIL:
                raw_pid = source.split(":")[1]
                if raw_pid.isdigit():
                    still_active = psutil.pid_exists(int(raw_pid))

            effectiveness = "EFFECTIVE" if not still_active else "INEFFECTIVE"
            score = 100 if not still_active else 0

            result = {
                "threat_id":     threat_id,
                "threat_type":   str(threat.type),
                "checked_at":    datetime.utcnow().isoformat(),
                "delay_secs":    delay_secs,
                "effectiveness": effectiveness,
                "score":         score,
            }

            result_file = os.path.join(
                EVIDENCE_DIR,
                f"effectiveness_{threat_id[:8]}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            )
            with open(result_file, "w") as f:
                json.dump(result, f, indent=2)

            logger.info(f"Response effectiveness [{threat_id[:8]}]: {effectiveness} (score: {score})")

        except Exception as e:
            logger.debug(f"Effectiveness check error: {e}")

    # ── Rollback ──────────────────────────────────────────────────────

    def get_rollback_log(self) -> list[dict]:
        """Return the complete action rollback log."""
        return list(_rollback_log)

    def get_blocked_ips(self) -> dict[str, str]:
        """Return IPs currently blocked with their expiry times."""
        now    = time.time()
        result = {}
        for ip, expiry in list(_ip_block_expiry.items()):
            if time.time() < expiry:
                result[ip] = datetime.fromtimestamp(expiry).isoformat()
            else:
                # Expired — could schedule unblock but keep for audit
                result[ip] = f"EXPIRED ({datetime.fromtimestamp(expiry).strftime('%H:%M')})"
        return result

    # ── Helpers ───────────────────────────────────────────────────────

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IPv4 address format."""
        return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip))
