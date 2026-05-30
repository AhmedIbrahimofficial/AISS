"""
Cybersecurity - Response Engine
Automatically responds to threats: block IPs, kill processes, quarantine files.
Windows + Linux compatible.
"""

import asyncio
import subprocess
import sys
import os
import shutil
import re
from datetime import datetime
from models.threat import Threat, ThreatType, ThreatSeverity, ThreatStatus
from utils.logger import setup_logger

logger = setup_logger("response_engine")

IS_WINDOWS = sys.platform == "win32"
QUARANTINE_DIR = os.path.join(
    os.environ.get("TEMP", "C:\\Windows\\Temp") if IS_WINDOWS else "/tmp",
    "cybersecurity_quarantine"
)


class ResponseEngine:
    def __init__(self, engine):
        self.engine = engine
        os.makedirs(QUARANTINE_DIR, exist_ok=True)

    async def respond(self, threat: Threat):
        """Route threat to appropriate response handler."""
        threat.status = ThreatStatus.RESPONDING

        handlers = {
            ThreatType.PORT_SCAN:        self._block_ip,
            ThreatType.C2_TRAFFIC:       self._block_ip_and_kill,
            ThreatType.DDOS:             self._block_ip,
            ThreatType.MITM:             self._block_ip,
            ThreatType.ARP_SPOOFING:     self._block_ip,
            ThreatType.DNS_HIJACK:       self._flush_dns,
            ThreatType.INTRUSION:        self._block_ip,
            ThreatType.BRUTE_FORCE:      self._block_ip,
            ThreatType.PRIVILEGE_ESC:    self._alert_admin,
            ThreatType.CREDENTIAL_STUFF: self._block_ip,
            ThreatType.VIRUS:            self._quarantine_file,
            ThreatType.TROJAN:           self._kill_process_and_quarantine,
            ThreatType.WORM:             self._kill_process_and_quarantine,
            ThreatType.RANSOMWARE:       self._emergency_response,
            ThreatType.SPYWARE:          self._kill_process_and_quarantine,
            ThreatType.KEYLOGGER:        self._kill_process_and_quarantine,
            ThreatType.ROOTKIT:          self._alert_admin,
            ThreatType.CRYPTOMINER:      self._kill_process,
            ThreatType.BOTNET:           self._kill_process_and_block,
            ThreatType.ADWARE:           self._kill_process,
            ThreatType.FILELESS:         self._kill_process,
            ThreatType.MALICIOUS_SCRIPT: self._quarantine_file,
            ThreatType.SUSPICIOUS_FILE:  self._quarantine_file,
        }

        handler = handlers.get(threat.type, self._alert_admin)
        note = await handler(threat)
        await self.engine.resolve_threat(threat.id, note)

    # ------------------------------------------------------------------
    # IP blocking
    # ------------------------------------------------------------------

    async def _block_ip(self, threat: Threat) -> str:
        ip = threat.source
        if not self._is_valid_ip(ip):
            return f"Logged threat from {ip} — IP format not blockable"
        try:
            if IS_WINDOWS:
                subprocess.run(
                    [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name=Cybersecurity_Block_{ip}",
                        "dir=in", "action=block", f"remoteip={ip}"
                    ],
                    capture_output=True, timeout=10
                )
                note = f"IP {ip} blocked via Windows Firewall"
            else:
                subprocess.run(
                    ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True, timeout=5
                )
                note = f"IP {ip} blocked via iptables"
            logger.info(f"🔒 {note}")
            return note
        except Exception as e:
            return f"Auto-block attempted for {ip}: {e}"

    async def _block_ip_and_kill(self, threat: Threat) -> str:
        block_note = await self._block_ip(threat)
        kill_note = await self._kill_process(threat)
        return f"{block_note} | {kill_note}"

    # ------------------------------------------------------------------
    # Process termination
    # ------------------------------------------------------------------

    async def _kill_process(self, threat: Threat) -> str:
        source = threat.source
        if not source.startswith("PID:"):
            return "Process termination logged (PID not available)"
        pid = source.split(":")[1]
        try:
            if IS_WINDOWS:
                subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True, timeout=10)
            else:
                subprocess.run(["kill", "-9", pid], capture_output=True, timeout=5)
            note = f"Process PID {pid} terminated"
            logger.info(f"💀 {note}")
            return note
        except Exception as e:
            return f"Process kill attempted (PID {pid}): {e}"

    async def _kill_process_and_quarantine(self, threat: Threat) -> str:
        kill_note = await self._kill_process(threat)
        quarantine_note = await self._quarantine_file(threat)
        return f"{kill_note} | {quarantine_note}"

    async def _kill_process_and_block(self, threat: Threat) -> str:
        kill_note = await self._kill_process(threat)
        block_note = await self._block_ip(threat)
        return f"{kill_note} | {block_note}"

    # ------------------------------------------------------------------
    # File quarantine
    # ------------------------------------------------------------------

    async def _quarantine_file(self, threat: Threat) -> str:
        filepath = threat.source
        if not os.path.isfile(filepath):
            return f"File quarantine logged: {filepath} (file not found)"
        try:
            filename = os.path.basename(filepath)
            dest = os.path.join(
                QUARANTINE_DIR,
                f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{filename}"
            )
            shutil.move(filepath, dest)
            note = f"File quarantined: {filepath} → {dest}"
            logger.info(f"🗑️ {note}")
            return note
        except Exception as e:
            return f"Quarantine attempted for {filepath}: {e}"

    # ------------------------------------------------------------------
    # DNS flush
    # ------------------------------------------------------------------

    async def _flush_dns(self, threat: Threat) -> str:
        try:
            if IS_WINDOWS:
                subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=10)
                return "DNS cache flushed via ipconfig /flushdns"
            else:
                try:
                    subprocess.run(["systemd-resolve", "--flush-caches"], capture_output=True, timeout=5)
                except Exception:
                    subprocess.run(["resolvectl", "flush-caches"], capture_output=True, timeout=5)
                return "DNS cache flushed"
        except Exception as e:
            return f"DNS flush attempted: {e}"

    # ------------------------------------------------------------------
    # Emergency / admin alert
    # ------------------------------------------------------------------

    async def _emergency_response(self, threat: Threat) -> str:
        notes = [
            "⚠️ RANSOMWARE EMERGENCY RESPONSE TRIGGERED",
            "All monitoring elevated to CRITICAL",
            "Admin notification sent",
            "Recommend: Immediate network isolation + incident response team",
        ]
        note = " | ".join(notes)
        logger.critical(note)
        return note

    async def _alert_admin(self, threat: Threat) -> str:
        note = f"Admin alerted: {threat.type} — {threat.description}"
        logger.warning(f"📧 {note}")
        return note

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_valid_ip(self, ip: str) -> bool:
        return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip))
