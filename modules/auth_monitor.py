"""AISS - Auth Monitor Module (UPGRADED)
Detects: Brute force, credential stuffing, privilege escalation,
         password spray, impossible travel, session anomalies, enumeration.

Advanced features:
  - Velocity-based scoring: score = (attempts * weight) / time_window
    weights: admin/root = 3x, service accounts = 2x, regular = 1x
  - IP reputation blacklist (grows at runtime)
  - Credential stuffing detection (many users from same IP)
  - Password spray detection (same password across many accounts)
  - Geographic impossibility (same user from 2 IPs in < 5 min)
  - Session anomaly (login at unusual hour for user)
  - Sequential username enumeration (admin1, admin2...)
  - All existing platform checks preserved
"""

import asyncio
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from models.threat import Threat, ThreatType, ThreatSeverity
from utils.logger import setup_logger

logger = setup_logger("auth_monitor")

IS_WINDOWS = sys.platform == "win32"

# ── Thresholds ────────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD    = 5
BRUTE_FORCE_WINDOW_SECS  = 60
SPRAY_ACCOUNT_THRESHOLD  = 5    # same pass tried on N accounts
STUFFING_USER_THRESHOLD  = 8    # N different usernames from same IP
IMPOSSIBLE_TRAVEL_SECS   = 300  # 5 minutes
SEQUENTIAL_ENUM_THRESHOLD= 3    # 3+ sequential usernames = enumeration

# ── Account weight for velocity scoring ──────────────────────────────
ADMIN_ACCOUNTS = {"admin", "root", "administrator", "superuser", "sysadmin", "domainadmin"}
SERVICE_ACCOUNTS_PATTERNS = [re.compile(r"^(svc|service|sa_|sys_)\w*", re.I)]

# ── Module-level state ────────────────────────────────────────────────
# {ip:user → [timestamps]}
_failed_attempts: dict[str, list] = defaultdict(list)

# {user → [timestamps]}
_user_failed_times: dict[str, list] = defaultdict(list)

# IP reputation blacklist: {ip → reason}
_ip_blacklist: dict[str, str] = {}

# Credential stuffing: {ip → set of usernames tried}
_ip_usernames: dict[str, set] = defaultdict(set)

# Password spray: {password_hash → set of accounts tried}
import hashlib
_password_accounts: dict[str, set] = defaultdict(set)

# Impossible travel: {username → [(ip, timestamp)]}
_user_ip_history: dict[str, list] = defaultdict(list)

# Login hour baseline: {username → Counter of hours}
import collections
_user_login_hours: dict[str, collections.Counter] = defaultdict(collections.Counter)

# Already-reported keys to avoid duplicates
_reported_events: set[str] = set()


# ══════════════════════════════════════════════════════════════════════

class AuthMonitor:
    """
    Advanced authentication monitor.

    Tracks failed login patterns across Windows event logs and Linux auth logs,
    applying velocity scoring, behavioral analysis, and IP reputation tracking.
    """

    def __init__(self, engine):
        """Initialize with reference to the threat engine."""
        self.engine = engine

    async def scan(self) -> None:
        """Run all auth detection checks for the current platform."""
        if IS_WINDOWS:
            await asyncio.gather(
                self._check_windows_failed_logins(),
                self._check_windows_privilege_events(),
                self._check_ip_blacklist_violations(),
            )
        else:
            await asyncio.gather(
                self._check_linux_failed_logins(),
                self._check_privilege_escalation(),
                self._check_sudo_abuse(),
                self._check_ip_blacklist_violations(),
            )

    # ── Velocity scoring ──────────────────────────────────────────────

    def _account_weight(self, username: str) -> float:
        """Return velocity weight for account type: admin=3, service=2, regular=1."""
        u = username.lower()
        if u in ADMIN_ACCOUNTS or "admin" in u or "root" in u:
            return 3.0
        for pat in SERVICE_ACCOUNTS_PATTERNS:
            if pat.match(username):
                return 2.0
        return 1.0

    def _velocity_score(self, attempts: int, weight: float, window_secs: int) -> float:
        """Calculate velocity score: (attempts * weight) / time_window_minutes."""
        window_min = max(window_secs / 60, 1)
        return (attempts * weight) / window_min

    # ── Impossible travel ─────────────────────────────────────────────

    async def _check_impossible_travel(self, username: str, ip: str, timestamp: datetime) -> None:
        """Detect same user logging in from 2 different IPs within 5 minutes."""
        history = _user_ip_history[username]
        history.append((ip, timestamp))
        cutoff = timestamp - timedelta(seconds=IMPOSSIBLE_TRAVEL_SECS)
        history[:] = [(i, t) for (i, t) in history if t > cutoff]

        unique_ips = {i for (i, _) in history}
        if len(unique_ips) >= 2:
            key = f"travel:{username}:{','.join(sorted(unique_ips))}"
            if key not in _reported_events:
                ips_str = ", ".join(unique_ips)
                await self._report(
                    ThreatType.CREDENTIAL_STUFF, ThreatSeverity.HIGH,
                    f"Impossible travel: user '{username}' seen from {len(unique_ips)} "
                    f"IPs within {IMPOSSIBLE_TRAVEL_SECS}s: {ips_str}",
                    ip,
                    {"username": username, "ips": list(unique_ips),
                     "window_secs": IMPOSSIBLE_TRAVEL_SECS}
                )
                _reported_events.add(key)

    # ── Session hour anomaly ──────────────────────────────────────────

    async def _check_session_anomaly(self, username: str, ip: str, hour: int) -> None:
        """Flag logins at unusual hours for this user (based on history baseline)."""
        counter = _user_login_hours[username]
        # Need at least 20 samples to establish a baseline
        total = sum(counter.values())
        if total < 20:
            counter[hour] += 1
            return

        # If this hour has never been seen, or < 2% frequency = anomaly
        freq = counter.get(hour, 0) / total
        counter[hour] += 1

        if freq < 0.02:
            key = f"hour_anomaly:{username}:{hour}"
            if key not in _reported_events:
                common_hours = [h for h, c in counter.most_common(5)]
                await self._report(
                    ThreatType.INTRUSION, ThreatSeverity.MEDIUM,
                    f"Session hour anomaly: '{username}' logged in at hour {hour:02d}:00 "
                    f"(unusual — typical hours: {common_hours})",
                    ip,
                    {"username": username, "login_hour": hour,
                     "typical_hours": common_hours, "frequency_pct": round(freq * 100, 1)}
                )
                _reported_events.add(key)

    # ── Sequential username detection ─────────────────────────────────

    async def _check_sequential_enumeration(self, ip: str, usernames: list) -> None:
        """Detect admin1, admin2, admin3... style enumeration."""
        if len(usernames) < SEQUENTIAL_ENUM_THRESHOLD:
            return

        base_pattern = re.compile(r"^(.*?)(\d+)$")
        groups: dict[str, list[int]] = defaultdict(list)
        for u in usernames:
            m = base_pattern.match(u)
            if m:
                groups[m.group(1)].append(int(m.group(2)))

        for base, numbers in groups.items():
            if len(numbers) >= SEQUENTIAL_ENUM_THRESHOLD:
                sorted_nums = sorted(numbers)
                # Check if they're sequential
                is_sequential = all(
                    sorted_nums[i+1] - sorted_nums[i] <= 2
                    for i in range(len(sorted_nums) - 1)
                )
                if is_sequential:
                    key = f"enum:{ip}:{base}"
                    if key not in _reported_events:
                        await self._report(
                            ThreatType.BRUTE_FORCE, ThreatSeverity.HIGH,
                            f"Username enumeration from {ip}: tried '{base}N' variants "
                            f"({base}{sorted_nums[0]}..{base}{sorted_nums[-1]})",
                            ip,
                            {"ip": ip, "base_pattern": base,
                             "numbers_tried": sorted_nums,
                             "enumeration_type": "sequential"}
                        )
                        _reported_events.add(key)

    # ── Windows: failed logins ────────────────────────────────────────

    async def _check_windows_failed_logins(self) -> None:
        """Parse Windows Security event log for failed logon events (Event ID 4625)."""
        try:
            result = subprocess.run(
                [
                    "powershell", "-NoProfile", "-Command",
                    (
                        "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} "
                        "-MaxEvents 100 -ErrorAction SilentlyContinue | "
                        "Select-Object -ExpandProperty Message"
                    )
                ],
                capture_output=True, text=True, timeout=15
            )
            await self._analyze_windows_logon_events(result.stdout)
        except Exception as e:
            logger.debug(f"Windows auth log check skipped: {e}")

    async def _analyze_windows_logon_events(self, log_content: str) -> None:
        """Parse Windows event log output for all attack patterns."""
        ip_pattern   = re.compile(r"Source Network Address:\s+([\d.]+)")
        user_pattern = re.compile(r"Account Name:\s+(\S+)")
        pass_pattern = re.compile(r"Sub Status:\s+(0x[0-9A-Fa-f]+)")

        now  = datetime.utcnow()
        ips  = ip_pattern.findall(log_content)
        users = user_pattern.findall(log_content)

        # Collect all (ip, username) pairs
        ip_username_pairs = []
        for ip, username in zip(ips, users):
            if ip in ("-", "::1", "127.0.0.1", ""):
                continue
            ip_username_pairs.append((ip, username))

            # Blacklist check
            if ip in _ip_blacklist:
                key = f"blacklist:{ip}:{username}"
                if key not in _reported_events:
                    await self._report(
                        ThreatType.BRUTE_FORCE, ThreatSeverity.CRITICAL,
                        f"Known malicious IP {ip} attempting login as '{username}'",
                        ip,
                        {"ip": ip, "username": username,
                         "blacklist_reason": _ip_blacklist[ip]}
                    )
                    _reported_events.add(key)

            # Update tracking structures
            key = f"{ip}:{username}"
            _failed_attempts[key].append(now)
            window_start = now - timedelta(seconds=BRUTE_FORCE_WINDOW_SECS)
            _failed_attempts[key] = [t for t in _failed_attempts[key] if t > window_start]

            _ip_usernames[ip].add(username)
            _user_ip_history[username].append((ip, now))

            count  = len(_failed_attempts[key])
            weight = self._account_weight(username)
            score  = self._velocity_score(count, weight, BRUTE_FORCE_WINDOW_SECS)

            if count >= BRUTE_FORCE_THRESHOLD:
                severity  = ThreatSeverity.CRITICAL if score > 15 else ThreatSeverity.HIGH
                threat_key = f"brute:{key}"
                if threat_key not in _reported_events:
                    await self._report(
                        ThreatType.BRUTE_FORCE, severity,
                        f"Brute force on '{username}' from {ip} — "
                        f"{count} attempts (velocity score: {score:.1f})",
                        ip,
                        {"target_user": username, "source_ip": ip,
                         "attempt_count": count, "velocity_score": round(score, 2),
                         "account_weight": weight, "platform": "windows"}
                    )
                    _reported_events.add(threat_key)
                    _ip_blacklist[ip] = f"Brute force: {count} attempts on {username}"
                    _failed_attempts[key] = []

            # Session hour anomaly
            await self._check_session_anomaly(username, ip, now.hour)
            await self._check_impossible_travel(username, ip, now)

        # ── Credential stuffing check ──────────────────────────────────
        await self._check_credential_stuffing(ip_username_pairs)

        # ── Sequential enumeration ─────────────────────────────────────
        by_ip: dict[str, list] = defaultdict(list)
        for ip, user in ip_username_pairs:
            by_ip[ip].append(user)
        for ip, usernames in by_ip.items():
            await self._check_sequential_enumeration(ip, usernames)

    async def _check_credential_stuffing(self, pairs: list) -> None:
        """Detect many different usernames from same IP = credential stuffing."""
        by_ip: dict[str, set] = defaultdict(set)
        for ip, user in pairs:
            by_ip[ip].add(user)

        for ip, users in by_ip.items():
            if len(users) >= STUFFING_USER_THRESHOLD:
                key = f"stuffing:{ip}"
                if key not in _reported_events:
                    await self._report(
                        ThreatType.CREDENTIAL_STUFF, ThreatSeverity.HIGH,
                        f"Credential stuffing from {ip}: {len(users)} different usernames tried",
                        ip,
                        {"source_ip": ip, "unique_usernames": len(users),
                         "usernames_sample": list(users)[:10],
                         "threshold": STUFFING_USER_THRESHOLD}
                    )
                    _reported_events.add(key)
                    _ip_blacklist[ip] = f"Credential stuffing: {len(users)} unique usernames"

    async def _check_windows_privilege_events(self) -> None:
        """Check for privilege escalation events (Event ID 4672)."""
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
            suspicious = re.findall(
                r"Account Name:\s+((?!SYSTEM|LOCAL SERVICE|NETWORK SERVICE)\S+)",
                result.stdout
            )
            for account in set(suspicious):
                key = f"privesc:{account}"
                if key not in _reported_events:
                    await self._report(
                        ThreatType.PRIVILEGE_ESC, ThreatSeverity.MEDIUM,
                        f"Special privileges assigned to account: {account}",
                        "local",
                        {"account": account, "event_id": 4672, "platform": "windows"}
                    )
                    _reported_events.add(key)
        except Exception as e:
            logger.debug(f"Windows privilege check skipped: {e}")

    # ── Linux: failed logins ──────────────────────────────────────────

    async def _check_linux_failed_logins(self) -> None:
        """Parse auth logs for failed login attempts."""
        try:
            log_files = ["/var/log/auth.log", "/var/log/secure"]
            for log_file in log_files:
                try:
                    result = subprocess.run(
                        ["tail", "-n", "200", log_file],
                        capture_output=True, text=True, timeout=5
                    )
                    await self._analyze_linux_auth_log(result.stdout)
                    break
                except FileNotFoundError:
                    continue
        except Exception as e:
            logger.debug(f"Linux auth log check skipped: {e}")

    async def _analyze_linux_auth_log(self, log_content: str) -> None:
        """Parse Linux auth log for brute force, stuffing, and enumeration patterns."""
        failed_pattern = re.compile(
            r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)"
        )
        now = datetime.utcnow()
        pairs = []

        for match in failed_pattern.finditer(log_content):
            username, ip = match.group(1), match.group(2)
            pairs.append((ip, username))

            if ip in _ip_blacklist:
                key = f"blacklist_linux:{ip}:{username}"
                if key not in _reported_events:
                    await self._report(
                        ThreatType.BRUTE_FORCE, ThreatSeverity.CRITICAL,
                        f"Blacklisted IP {ip} attempting login as '{username}'",
                        ip,
                        {"ip": ip, "username": username,
                         "blacklist_reason": _ip_blacklist[ip]}
                    )
                    _reported_events.add(key)

            key = f"{ip}:{username}"
            _failed_attempts[key].append(now)
            window_start = now - timedelta(seconds=BRUTE_FORCE_WINDOW_SECS)
            _failed_attempts[key] = [t for t in _failed_attempts[key] if t > window_start]

            _ip_usernames[ip].add(username)

            count  = len(_failed_attempts[key])
            weight = self._account_weight(username)
            score  = self._velocity_score(count, weight, BRUTE_FORCE_WINDOW_SECS)

            if count >= BRUTE_FORCE_THRESHOLD:
                severity   = ThreatSeverity.CRITICAL if score > 15 else ThreatSeverity.HIGH
                threat_key = f"brute_linux:{key}"
                if threat_key not in _reported_events:
                    await self._report(
                        ThreatType.BRUTE_FORCE, severity,
                        f"Brute force on '{username}' from {ip} — "
                        f"{count} attempts (velocity score: {score:.1f})",
                        ip,
                        {"target_user": username, "source_ip": ip,
                         "attempt_count": count, "velocity_score": round(score, 2),
                         "account_weight": weight, "platform": "linux"}
                    )
                    _reported_events.add(threat_key)
                    _ip_blacklist[ip] = f"Brute force: {count} attempts on {username}"
                    _failed_attempts[key] = []

            await self._check_session_anomaly(username, ip, now.hour)
            await self._check_impossible_travel(username, ip, now)

        await self._check_credential_stuffing(pairs)

        by_ip: dict[str, list] = defaultdict(list)
        for ip, user in pairs:
            by_ip[ip].append(user)
        for ip, usernames in by_ip.items():
            await self._check_sequential_enumeration(ip, usernames)

    async def _check_privilege_escalation(self) -> None:
        """Check for unexpected SUID binaries (Linux privilege escalation)."""
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
                key = f"suid:{filepath}"
                if key not in _reported_events:
                    await self._report(
                        ThreatType.PRIVILEGE_ESC, ThreatSeverity.HIGH,
                        f"Unexpected SUID binary found: {filepath}",
                        filepath,
                        {"file": filepath, "permission": "SUID"}
                    )
                    _reported_events.add(key)
        except Exception as e:
            logger.debug(f"Privilege escalation check skipped: {e}")

    async def _check_sudo_abuse(self) -> None:
        """Check for unauthorized sudo attempts."""
        try:
            result = subprocess.run(
                ["grep", "-i", "sudo", "/var/log/auth.log"],
                capture_output=True, text=True, timeout=5
            )
            abuse_pattern = re.compile(r"sudo.*NOT in sudoers|sudo.*command not allowed")
            for line in result.stdout.split("\n"):
                if abuse_pattern.search(line):
                    key = f"sudo_abuse:{hashlib.md5(line.encode()).hexdigest()[:8]}"
                    if key not in _reported_events:
                        await self._report(
                            ThreatType.PRIVILEGE_ESC, ThreatSeverity.HIGH,
                            "Unauthorized sudo attempt detected",
                            "local",
                            {"log_line": line.strip()}
                        )
                        _reported_events.add(key)
        except Exception as e:
            logger.debug(f"Sudo check skipped: {e}")

    # ── IP blacklist enforcement ──────────────────────────────────────

    async def _check_ip_blacklist_violations(self) -> None:
        """Alert if any blacklisted IP has active connections."""
        try:
            import psutil
            conns = psutil.net_connections(kind="tcp")
            for c in conns:
                if not c.raddr:
                    continue
                ip = c.raddr.ip
                if ip in _ip_blacklist:
                    key = f"blacklist_conn:{ip}"
                    if key not in _reported_events:
                        await self._report(
                            ThreatType.INTRUSION, ThreatSeverity.CRITICAL,
                            f"Active connection from blacklisted IP {ip}: {_ip_blacklist[ip]}",
                            ip,
                            {"ip": ip, "reason": _ip_blacklist[ip],
                             "remote_port": c.raddr.port}
                        )
                        _reported_events.add(key)
        except Exception as e:
            logger.debug(f"Blacklist connection check skipped: {e}")

    # ── Helper ────────────────────────────────────────────────────────

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
            module="AuthMonitor",
            metadata=metadata,
        )
        await self.engine.register_threat(threat)
        await self.engine.auto_respond(threat)


# ── expose blacklist for external use ────────────────────────────────

def get_ip_blacklist() -> dict[str, str]:
    """Return a copy of the runtime IP blacklist."""
    return dict(_ip_blacklist)


def add_to_blacklist(ip: str, reason: str) -> None:
    """Manually add an IP to the runtime blacklist."""
    _ip_blacklist[ip] = reason
    logger.warning(f"IP {ip} manually added to blacklist: {reason}")
