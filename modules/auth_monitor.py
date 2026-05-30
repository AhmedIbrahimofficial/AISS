"""
Cybersecurity - Auth Monitor Module
Detects: Brute force, credential stuffing, privilege escalation, failed logins.
Windows + Linux compatible.
"""

import asyncio
import subprocess
import sys
import re
from collections import defaultdict
from datetime import datetime, timedelta
from models.threat import Threat, ThreatType, ThreatSeverity
from utils.logger import setup_logger

logger = setup_logger("auth_monitor")

IS_WINDOWS = sys.platform == "win32"

# In-memory tracking of failed login attempts
_failed_attempts: dict[str, list] = defaultdict(list)
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_SECS = 60


class AuthMonitor:
    def __init__(self, engine):
        self.engine = engine

    async def scan(self):
        """Run all auth detection checks."""
        if IS_WINDOWS:
            await asyncio.gather(
                self._check_windows_failed_logins(),
                self._check_windows_privilege_events(),
            )
        else:
            await asyncio.gather(
                self._check_linux_failed_logins(),
                self._check_privilege_escalation(),
                self._check_sudo_abuse(),
            )

    # ------------------------------------------------------------------
    # Windows
    # ------------------------------------------------------------------

    async def _check_windows_failed_logins(self):
        """Parse Windows Security event log for failed logon events (Event ID 4625)."""
        try:
            result = subprocess.run(
                [
                    "powershell", "-NoProfile", "-Command",
                    (
                        "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} "
                        "-MaxEvents 50 -ErrorAction SilentlyContinue | "
                        "Select-Object -ExpandProperty Message"
                    )
                ],
                capture_output=True, text=True, timeout=15
            )
            await self._analyze_windows_logon_events(result.stdout)
        except Exception as e:
            logger.debug(f"Windows auth log check skipped: {e}")

    async def _analyze_windows_logon_events(self, log_content: str):
        """Parse Windows event log output for brute force patterns."""
        ip_pattern = re.compile(r"Source Network Address:\s+([\d.]+)")
        user_pattern = re.compile(r"Account Name:\s+(\S+)")
        now = datetime.utcnow()

        ips = ip_pattern.findall(log_content)
        users = user_pattern.findall(log_content)

        for ip, username in zip(ips, users):
            if ip in ("-", "::1", "127.0.0.1"):
                continue
            key = f"{ip}:{username}"
            _failed_attempts[key].append(now)

            window_start = now - timedelta(seconds=BRUTE_FORCE_WINDOW_SECS)
            _failed_attempts[key] = [t for t in _failed_attempts[key] if t > window_start]

            count = len(_failed_attempts[key])
            if count >= BRUTE_FORCE_THRESHOLD:
                severity = ThreatSeverity.CRITICAL if count > 20 else ThreatSeverity.HIGH
                threat = Threat(
                    type=ThreatType.BRUTE_FORCE,
                    description=(
                        f"Brute force attack on user '{username}' from {ip} — "
                        f"{count} attempts in {BRUTE_FORCE_WINDOW_SECS}s"
                    ),
                    severity=severity,
                    source=ip,
                    module="AuthMonitor",
                    metadata={
                        "target_user": username,
                        "source_ip": ip,
                        "attempt_count": count,
                        "window_seconds": BRUTE_FORCE_WINDOW_SECS,
                        "platform": "windows"
                    }
                )
                await self.engine.register_threat(threat)
                await self.engine.auto_respond(threat)
                _failed_attempts[key] = []

    async def _check_windows_privilege_events(self):
        """Check for privilege escalation events (Event ID 4672 — special privileges assigned)."""
        try:
            result = subprocess.run(
                [
                    "powershell", "-NoProfile", "-Command",
                    (
                        "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672} "
                        "-MaxEvents 20 -ErrorAction SilentlyContinue | "
                        "Select-Object -ExpandProperty Message"
                    )
                ],
                capture_output=True, text=True, timeout=15
            )
            # Only flag if unexpected accounts received special privileges
            suspicious = re.findall(r"Account Name:\s+((?!SYSTEM|LOCAL SERVICE|NETWORK SERVICE)\S+)", result.stdout)
            for account in set(suspicious):
                threat = Threat(
                    type=ThreatType.PRIVILEGE_ESC,
                    description=f"Special privileges assigned to account: {account}",
                    severity=ThreatSeverity.MEDIUM,
                    source="local",
                    module="AuthMonitor",
                    metadata={"account": account, "event_id": 4672, "platform": "windows"}
                )
                await self.engine.register_threat(threat)
        except Exception as e:
            logger.debug(f"Windows privilege check skipped: {e}")

    # ------------------------------------------------------------------
    # Linux
    # ------------------------------------------------------------------

    async def _check_linux_failed_logins(self):
        """Parse auth logs for failed login attempts."""
        try:
            log_files = ["/var/log/auth.log", "/var/log/secure"]
            for log_file in log_files:
                try:
                    result = subprocess.run(
                        ["tail", "-n", "100", log_file],
                        capture_output=True, text=True, timeout=5
                    )
                    await self._analyze_linux_auth_log(result.stdout)
                    break
                except FileNotFoundError:
                    continue
        except Exception as e:
            logger.debug(f"Linux auth log check skipped: {e}")

    async def _analyze_linux_auth_log(self, log_content: str):
        failed_pattern = re.compile(
            r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)"
        )
        now = datetime.utcnow()
        for match in failed_pattern.finditer(log_content):
            username, ip = match.group(1), match.group(2)
            key = f"{ip}:{username}"
            _failed_attempts[key].append(now)

            window_start = now - timedelta(seconds=BRUTE_FORCE_WINDOW_SECS)
            _failed_attempts[key] = [t for t in _failed_attempts[key] if t > window_start]

            count = len(_failed_attempts[key])
            if count >= BRUTE_FORCE_THRESHOLD:
                severity = ThreatSeverity.CRITICAL if count > 20 else ThreatSeverity.HIGH
                threat = Threat(
                    type=ThreatType.BRUTE_FORCE,
                    description=(
                        f"Brute force attack on user '{username}' from {ip} — "
                        f"{count} attempts in {BRUTE_FORCE_WINDOW_SECS}s"
                    ),
                    severity=severity,
                    source=ip,
                    module="AuthMonitor",
                    metadata={
                        "target_user": username,
                        "source_ip": ip,
                        "attempt_count": count,
                        "window_seconds": BRUTE_FORCE_WINDOW_SECS
                    }
                )
                await self.engine.register_threat(threat)
                await self.engine.auto_respond(threat)
                _failed_attempts[key] = []

    async def _check_privilege_escalation(self):
        try:
            result = subprocess.run(
                ["find", "/usr/bin", "/bin", "-perm", "-4000", "-type", "f"],
                capture_output=True, text=True, timeout=10
            )
            suid_files = set(result.stdout.strip().split("\n"))
            known_suid = {
                "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
                "/bin/su", "/usr/bin/newgrp", "/usr/bin/gpasswd"
            }
            for filepath in suid_files - known_suid - {""}:
                threat = Threat(
                    type=ThreatType.PRIVILEGE_ESC,
                    description=f"Unexpected SUID binary found: {filepath}",
                    severity=ThreatSeverity.HIGH,
                    source=filepath,
                    module="AuthMonitor",
                    metadata={"file": filepath, "permission": "SUID"}
                )
                await self.engine.register_threat(threat)
        except Exception as e:
            logger.debug(f"Privilege escalation check skipped: {e}")

    async def _check_sudo_abuse(self):
        try:
            result = subprocess.run(
                ["grep", "-i", "sudo", "/var/log/auth.log"],
                capture_output=True, text=True, timeout=5
            )
            abuse_pattern = re.compile(r"sudo.*NOT in sudoers|sudo.*command not allowed")
            for line in result.stdout.split("\n"):
                if abuse_pattern.search(line):
                    threat = Threat(
                        type=ThreatType.PRIVILEGE_ESC,
                        description="Unauthorized sudo attempt detected",
                        severity=ThreatSeverity.HIGH,
                        source="local",
                        module="AuthMonitor",
                        metadata={"log_line": line.strip()}
                    )
                    await self.engine.register_threat(threat)
        except Exception as e:
            logger.debug(f"Sudo check skipped: {e}")
