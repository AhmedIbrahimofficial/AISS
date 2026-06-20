"""AISS - File Monitor Module (UPGRADED)
Detects: Suspicious files, malicious scripts, ransomware patterns, data exfiltration.

Advanced features:
  - Real-time file entropy calculation (>7.2 = encrypted/packed = ransomware/malware)
  - Ransomware honeypot files: 5 fake .docx/.xlsx in temp, watched for modification
  - File extension mass-change detection (>10 in 60s = ransomware)
  - Shadow copy deletion detection (vssadmin delete shadows)
  - Sensitive file access detection (/etc/passwd, SAM, NTDS.dit, etc.)
  - Script injection: deeper content scan with more patterns
  - File creation velocity (>100 new files/60s in same dir)
  - Existing hash checking + MALICIOUS_PATTERNS preserved
"""

import asyncio
import collections
import hashlib
import math
import os
import re
import sys
import time
import threading
from pathlib import Path
from datetime import datetime

from models.threat import Threat, ThreatType, ThreatSeverity
from utils.logger import setup_logger
from modules.dataset_loader import dataset_loader

logger = setup_logger("file_monitor")

IS_WINDOWS = sys.platform == "win32"

# ── Known malicious file hashes (SHA256 / MD5) ────────────────────────
MALICIOUS_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f",
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
}

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta",
    ".scr", ".pif", ".com", ".jar", ".py", ".sh", ".dll",
    ".msi", ".wsf", ".reg", ".cpl",
}

RANSOMWARE_EXTENSIONS = {
    ".encrypted", ".locked", ".crypt", ".crypted", ".enc",
    ".wnry", ".wncry", ".cerber", ".locky", ".zepto",
    ".thor", ".micro", ".zzzzz", ".osiris", ".aaa", ".abc",
}

MALICIOUS_PATTERNS = [
    re.compile(r"base64_decode\s*\(",          re.I),
    re.compile(r"eval\s*\(\s*base64",          re.I),
    re.compile(r"powershell.*-enc",            re.I),
    re.compile(r"wget.*http.*&&.*chmod.*\+x",  re.I),
    re.compile(r"curl.*\|.*bash",              re.I),
    re.compile(r"rm\s+-rf\s+/",               re.I),
    re.compile(r"nc\s+-e\s+/bin/(bash|sh)",   re.I),
    re.compile(r"/bin/bash\s+-i\s+>&\s+/dev/tcp", re.I),
    re.compile(r"mimikatz",                    re.I),
    re.compile(r"meterpreter",                 re.I),
    re.compile(r"IEX\s*\(.*DownloadString",   re.I),
    re.compile(r"certutil.*-decode",           re.I),
    re.compile(r"regsvr32.*scrobj",            re.I),
    # Additional patterns
    re.compile(r"Invoke-Expression.*http",     re.I),
    re.compile(r"Net\.WebClient.*Download",    re.I),
    re.compile(r"Start-Process.*-Hidden",      re.I),
    re.compile(r"Add-MpPreference.*Exclusion", re.I),
    re.compile(r"vssadmin.*delete.*shadows",   re.I),
    re.compile(r"wbadmin.*delete.*catalog",    re.I),
    re.compile(r"bcdedit.*recoveryenabled.*no",re.I),
    re.compile(r"__import__.*os.*system",      re.I),
    re.compile(r"socket\.connect.*\d{1,3}\.\d{1,3}", re.I),
    re.compile(r"os\.popen|subprocess\.call|subprocess\.Popen", re.I),
]

# Sensitive files that should never be read by unknown processes
SENSITIVE_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "C:\\Windows\\System32\\config\\SAM",
    "C:\\Windows\\System32\\config\\SYSTEM",
    "C:\\Windows\\NTDS\\ntds.dit",
    "C:\\Windows\\System32\\config\\SECURITY",
    ".ssh/id_rsa", ".ssh/id_ed25519",
]

# ── Honeypot files ────────────────────────────────────────────────────
_HONEYPOT_CONTENT_DOCX = b"FAKE_HONEYPOT_DOCUMENT_DO_NOT_MODIFY" * 100
_HONEYPOT_CONTENT_XLSX = b"FAKE_HONEYPOT_SPREADSHEET_DO_NOT_MODIFY" * 100
_honeypot_files: list[str] = []
_honeypot_mtimes: dict[str, float] = {}

# ── Tracking state ────────────────────────────────────────────────────
# Extension change tracker: {directory → {timestamp: count_of_ext_changes}}
_ext_change_tracker: dict[str, list] = collections.defaultdict(list)  # dir → [timestamps]

# File creation velocity: {directory → [timestamps of new files]}
_file_creation_tracker: dict[str, list] = collections.defaultdict(list)

# Already-reported keys to avoid duplicates
_reported_files: set[str] = set()

# Shadow copy deletion: track if vssadmin was seen running
_shadow_delete_seen: bool = False


# ══════════════════════════════════════════════════════════════════════
# Entropy calculation
# ══════════════════════════════════════════════════════════════════════

def file_entropy(path: str, max_bytes: int = 65536) -> float:
    """
    Calculate Shannon entropy of a file.

    Args:
        path: File path to analyze
        max_bytes: Maximum bytes to read (default 64KB)

    Returns:
        Entropy value 0.0-8.0. Values > 7.2 indicate encryption/packing.
    """
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        if not data:
            return 0.0
        freq  = collections.Counter(data)
        total = len(data)
        return -sum((c / total) * math.log2(c / total) for c in freq.values())
    except Exception:
        return 0.0


# ══════════════════════════════════════════════════════════════════════
# Honeypot file setup
# ══════════════════════════════════════════════════════════════════════

def setup_honeypot_files() -> None:
    """
    Create 5 fake honeypot files (.docx/.xlsx) in the temp directory.
    These are watched — any modification triggers an immediate ransomware alert.
    """
    global _honeypot_files, _honeypot_mtimes
    temp_dir = _get_temp_dir()
    names = [
        "~backup_report_Q4.docx",
        "~financial_summary_2024.xlsx",
        "~employee_list.docx",
        "~project_budget.xlsx",
        "~contracts_2024.docx",
    ]
    for name in names:
        path = os.path.join(temp_dir, name)
        try:
            if not os.path.exists(path):
                content = _HONEYPOT_CONTENT_DOCX if name.endswith(".docx") else _HONEYPOT_CONTENT_XLSX
                with open(path, "wb") as f:
                    f.write(content)
            stat = os.stat(path)
            _honeypot_mtimes[path] = stat.st_mtime
            _honeypot_files.append(path)
            logger.debug(f"Honeypot file ready: {path}")
        except Exception as e:
            logger.debug(f"Could not create honeypot file {path}: {e}")


def _get_temp_dir() -> str:
    """Return platform temp directory."""
    if IS_WINDOWS:
        return os.environ.get("TEMP", "C:\\Windows\\Temp")
    return "/tmp"


def _get_watch_dirs() -> list[str]:
    """
    Return ALL critical system directories to watch.
    Covers: temp, downloads, startup folders, system dirs,
    user profile, desktop, documents, program files.
    """
    if IS_WINDOWS:
        user     = os.path.expanduser("~")
        temp     = os.environ.get("TEMP", "C:\\Windows\\Temp")
        appdata  = os.environ.get("APPDATA", "")
        localapp = os.environ.get("LOCALAPPDATA", "")
        windir   = os.environ.get("WINDIR", "C:\\Windows")
        progdata = os.environ.get("PROGRAMDATA", "C:\\ProgramData")

        dirs = [
            # ── Temp / staging areas (highest risk) ────────────────
            temp,
            "C:\\Windows\\Temp",
            os.path.join(localapp, "Temp"),

            # ── User locations ──────────────────────────────────────
            os.path.join(user, "Downloads"),
            os.path.join(user, "Desktop"),
            os.path.join(user, "Documents"),
            os.path.join(user, "AppData", "Roaming"),
            os.path.join(user, "AppData", "Local"),
            os.path.join(user, "AppData", "Local", "Temp"),

            # ── Windows startup locations (malware persistence) ─────
            os.path.join(appdata, "Microsoft", "Windows", "Start Menu",
                         "Programs", "Startup"),
            os.path.join(progdata, "Microsoft", "Windows", "Start Menu",
                         "Programs", "Startup"),

            # ── System directories ──────────────────────────────────
            os.path.join(windir, "System32"),
            os.path.join(windir, "SysWOW64"),
            os.path.join(windir, "Tasks"),                  # scheduled tasks
            os.path.join(windir, "System32", "drivers"),    # kernel drivers

            # ── Program installs ────────────────────────────────────
            "C:\\Program Files",
            "C:\\Program Files (x86)",
            progdata,

            # ── Network / shared ────────────────────────────────────
            "C:\\Users\\Public",
            "C:\\Users\\Public\\Downloads",
        ]
        return [d for d in dirs if d and os.path.exists(d)]
    else:
        # Linux: cover all critical locations
        home = os.path.expanduser("~")
        return [d for d in [
            "/tmp", "/var/tmp", "/dev/shm",
            os.path.join(home, "Downloads"),
            os.path.join(home, "Desktop"),
            "/etc/cron.d", "/etc/cron.hourly", "/etc/init.d",
            "/var/spool/cron",
            "/usr/local/bin", "/usr/bin",
            "/etc",
        ] if os.path.exists(d)]


# ══════════════════════════════════════════════════════════════════════
# Main monitor class
# ══════════════════════════════════════════════════════════════════════

class FileMonitor:
    """
    Advanced file monitor with entropy analysis, honeypot protection,
    and ransomware behavioral detection.
    """

    def __init__(self, engine):
        """Initialize with reference to the threat engine."""
        self.engine = engine
        self._scanned_files: set[str] = set()
        # Set up honeypot files on first instantiation
        if not _honeypot_files:
            setup_honeypot_files()

    async def scan(self) -> None:
        """Run all file monitoring checks concurrently."""
        await asyncio.gather(
            self._scan_directories(),
            self._check_ransomware_activity(),
            self._check_honeypot_files(),
            self._check_shadow_copy_deletion(),
            self._check_sensitive_file_access(),
        )

    # ── 1. Directory scan ─────────────────────────────────────────────

    # Directories that should only scan for RECENT changes (not all files)
    # to avoid performance issues with large system dirs
    _RECENT_ONLY_DIRS = {
        "system32", "syswow64", "drivers", "program files",
        "program files (x86)", "programdata",
    }

    async def _scan_directories(self) -> None:
        """
        Scan all watched directories.
        - High-risk dirs (temp, downloads, startup): scan ALL files
        - System dirs (System32 etc): scan only files modified in last 60s
        """
        now = time.time()
        for watch_dir in _get_watch_dirs():
            try:
                # Determine if this is a system dir (scan recent only)
                dir_lower = watch_dir.lower()
                recent_only = any(
                    s in dir_lower for s in self._RECENT_ONLY_DIRS
                )

                for entry in os.scandir(watch_dir):
                    if not entry.is_file():
                        continue
                    try:
                        stat = entry.stat()

                        # For system dirs: only check files modified in last 60s
                        if recent_only and (now - stat.st_mtime) > 60:
                            continue

                        key  = f"{entry.path}:{stat.st_mtime}"
                        is_new = key not in self._scanned_files
                        self._scanned_files.add(key)

                        if is_new:
                            _file_creation_tracker[watch_dir].append(now)

                        await self._inspect_file(entry.path, stat)

                    except (PermissionError, FileNotFoundError, OSError):
                        pass

                # Prune velocity tracker to last 60s
                _file_creation_tracker[watch_dir] = [
                    t for t in _file_creation_tracker[watch_dir]
                    if now - t < 60
                ]
                # File creation velocity alert
                velocity = len(_file_creation_tracker[watch_dir])
                vel_key  = f"velocity:{watch_dir}"
                if velocity > 100 and vel_key not in _reported_files:
                    await self._report(
                        ThreatType.RANSOMWARE, ThreatSeverity.HIGH,
                        f"File creation velocity alert: {velocity} new files in 60s in {watch_dir}",
                        watch_dir,
                        {"directory": watch_dir, "files_per_minute": velocity,
                         "threshold": 100}
                    )
                    _reported_files.add(vel_key)

            except (PermissionError, OSError):
                pass

    async def _inspect_file(self, filepath: str, stat: os.stat_result) -> None:
        """Inspect a single file for all threat indicators."""
        try:
            ext = Path(filepath).suffix.lower()

            # Hash check
            file_hash = await self._hash_file(filepath)
            if file_hash in MALICIOUS_HASHES:
                await self._report(
                    ThreatType.VIRUS, ThreatSeverity.CRITICAL,
                    f"Known malware hash detected: {filepath}",
                    filepath,
                    {"hash": file_hash, "path": filepath}
                )
                await self.engine.auto_respond(
                    Threat(type=ThreatType.VIRUS,
                           description=f"Hash match: {filepath}",
                           severity=ThreatSeverity.CRITICAL,
                           source=filepath, module="FileMonitor")
                )
                return

            # Extension mass-change tracking
            if ext in RANSOMWARE_EXTENSIONS:
                now = time.time()
                parent = str(Path(filepath).parent)
                _ext_change_tracker[parent].append(now)
                _ext_change_tracker[parent] = [
                    t for t in _ext_change_tracker[parent] if now - t < 60
                ]
                count   = len(_ext_change_tracker[parent])
                ext_key = f"ext_change:{parent}"
                if count >= 10 and ext_key not in _reported_files:
                    await self._report(
                        ThreatType.RANSOMWARE, ThreatSeverity.CRITICAL,
                        f"Ransomware: {count} files changed to encrypted extension in 60s in {parent}",
                        parent,
                        {"directory": parent, "extension_count": count,
                         "sample_extension": ext}
                    )
                    _reported_files.add(ext_key)

            # Script content scan
            if ext in {".sh", ".py", ".js", ".ps1", ".vbs", ".bat", ".cmd", ".hta", ".wsf"}:
                await self._scan_script_content(filepath)

            # Entropy check for executables and suspicious extensions
            if ext in SUSPICIOUS_EXTENSIONS:
                entropy = file_entropy(filepath)
                if entropy > 7.2:
                    key = f"entropy:{filepath}"
                    if key not in _reported_files:
                        await self._report(
                            ThreatType.SUSPICIOUS_FILE, ThreatSeverity.HIGH,
                            f"High-entropy file (packed/encrypted, entropy={entropy:.2f}): {filepath}",
                            filepath,
                            {"path": filepath, "entropy": round(entropy, 4),
                             "extension": ext, "size": stat.st_size}
                        )
                        _reported_files.add(key)
                        return

                # Suspicious executable in temp dir
                temp_dir = _get_temp_dir().lower()
                if temp_dir in filepath.lower():
                    key = f"temp_exe:{filepath}"
                    if key not in _reported_files:
                        await self._report(
                            ThreatType.SUSPICIOUS_FILE, ThreatSeverity.HIGH,
                            f"Suspicious executable in temp directory: {filepath}",
                            filepath,
                            {"extension": ext, "path": filepath, "size": stat.st_size}
                        )
                        _reported_files.add(key)

        except (PermissionError, FileNotFoundError, OSError):
            pass

    async def _scan_script_content(self, filepath: str) -> None:
        """Scan script file content for malicious patterns and phishing URLs."""
        try:
            with open(filepath, "r", errors="ignore") as f:
                content = f.read(50000)

            # ── Malicious pattern check ───────────────────────────────
            for pattern in MALICIOUS_PATTERNS:
                if pattern.search(content):
                    key = f"script:{filepath}"
                    if key not in _reported_files:
                        snippet = pattern.pattern[:60]
                        await self._report(
                            ThreatType.MALICIOUS_SCRIPT, ThreatSeverity.HIGH,
                            f"Malicious pattern in script: {filepath}",
                            filepath,
                            {"pattern": snippet, "path": filepath,
                             "matched_pattern": pattern.pattern}
                        )
                        _reported_files.add(key)
                    return

            # ── Dataset-driven phishing URL detection ─────────────────
            import re as _re
            urls_found = _re.findall(r'https?://[^\s\'"<>]+', content)
            for url in urls_found[:20]:  # check first 20 URLs only
                score = dataset_loader.score_url(url)
                if score >= 0.5:  # 50%+ phishing score
                    key = f"phishing_url:{filepath}:{url[:60]}"
                    if key not in _reported_files:
                        await self._report(
                            ThreatType.SUSPICIOUS_FILE, ThreatSeverity.HIGH,
                            f"High-risk URL in script (score={score:.0%}): {url[:80]}",
                            filepath,
                            {"url": url[:200], "phishing_score": round(score, 3),
                             "path": filepath, "detection": "dataset_driven"}
                        )
                        _reported_files.add(key)
                    break

        except Exception:
            pass

    # ── 2. Ransomware activity (encrypted file count) ─────────────────

    async def _check_ransomware_activity(self) -> None:
        """Detect ransomware by counting files with encrypted extensions in home dir."""
        home = os.path.expanduser("~")
        encrypted_count = 0
        try:
            for root, _, files in os.walk(home):
                for fname in files:
                    if Path(fname).suffix.lower() in RANSOMWARE_EXTENSIONS:
                        encrypted_count += 1
                if encrypted_count >= 5:
                    key = f"ransomware_bulk:{home}"
                    if key not in _reported_files:
                        await self._report(
                            ThreatType.RANSOMWARE, ThreatSeverity.CRITICAL,
                            f"Ransomware activity: {encrypted_count}+ files with encrypted extensions",
                            home,
                            {"encrypted_file_count": encrypted_count, "directory": home}
                        )
                        _reported_files.add(key)
                    break
        except Exception as e:
            logger.debug(f"Ransomware check error: {e}")

    # ── 3. Honeypot file monitoring ───────────────────────────────────

    async def _check_honeypot_files(self) -> None:
        """Check if any honeypot files have been modified (ransomware indicator)."""
        for path in _honeypot_files:
            try:
                if not os.path.exists(path):
                    # Honeypot file deleted — recreation + alert
                    setup_honeypot_files()
                    key = f"honeypot_deleted:{path}"
                    if key not in _reported_files:
                        await self._report(
                            ThreatType.RANSOMWARE, ThreatSeverity.CRITICAL,
                            f"Honeypot file DELETED (ransomware wiper pattern): {path}",
                            path,
                            {"honeypot_path": path, "action": "deleted"}
                        )
                        _reported_files.add(key)
                    continue

                stat  = os.stat(path)
                mtime = stat.st_mtime

                baseline_mtime = _honeypot_mtimes.get(path)
                if baseline_mtime and mtime != baseline_mtime:
                    key = f"honeypot_modified:{path}"
                    if key not in _reported_files:
                        await self._report(
                            ThreatType.RANSOMWARE, ThreatSeverity.CRITICAL,
                            f"RANSOMWARE DETECTED: Honeypot file modified: {path}",
                            path,
                            {"honeypot_path": path, "action": "modified",
                             "original_mtime": baseline_mtime, "new_mtime": mtime}
                        )
                        _reported_files.add(key)
                    _honeypot_mtimes[path] = mtime

            except (PermissionError, OSError):
                pass

    # ── 4. Shadow copy deletion ───────────────────────────────────────

    async def _check_shadow_copy_deletion(self) -> None:
        """
        Detect shadow copy deletion commands (ransomware defense evasion).
        Checks running processes for vssadmin/wbadmin delete commands.
        """
        global _shadow_delete_seen
        try:
            import psutil
            for proc in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
                try:
                    cmdline = " ".join(proc.info.get("cmdline", []) or []).lower()
                    if any(pat in cmdline for pat in [
                        "vssadmin delete shadows",
                        "wbadmin delete catalog",
                        "bcdedit /set recoveryenabled no",
                        "wmic shadowcopy delete",
                    ]):
                        if not _shadow_delete_seen:
                            _shadow_delete_seen = True
                            await self._report(
                                ThreatType.RANSOMWARE, ThreatSeverity.CRITICAL,
                                f"Shadow copy deletion detected: {cmdline[:120]}",
                                f"PID:{proc.pid}",
                                {"pid": proc.pid, "cmdline": cmdline[:200],
                                 "indicator": "shadow_copy_deletion"}
                            )
                except (Exception,):
                    pass
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"Shadow copy check error: {e}")

    # ── 5. Sensitive file access detection ───────────────────────────

    async def _check_sensitive_file_access(self) -> None:
        """
        Detect access to sensitive files (passwd, SAM, NTDS.dit, etc.)
        by checking their atime against a baseline.
        """
        for filepath in SENSITIVE_FILES:
            # Expand ~ for home-relative paths
            if filepath.startswith(".ssh"):
                filepath = os.path.join(os.path.expanduser("~"), filepath)

            if not os.path.exists(filepath):
                continue
            try:
                stat  = os.stat(filepath)
                atime = stat.st_atime
                key   = f"sensitive:{filepath}"

                if key in _reported_files:
                    continue

                # If atime is within last 60 seconds — just accessed
                if time.time() - atime < 60:
                    await self._report(
                        ThreatType.DATA_EXFIL, ThreatSeverity.CRITICAL,
                        f"Sensitive file accessed: {filepath}",
                        filepath,
                        {"path": filepath, "accessed_ago_secs": int(time.time() - atime),
                         "indicator": "sensitive_file_access"}
                    )
                    _reported_files.add(key)
            except (PermissionError, OSError):
                pass

    # ── Helpers ───────────────────────────────────────────────────────

    async def _hash_file(self, filepath: str) -> str:
        """Calculate SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return ""

    async def _report(
        self,
        threat_type: ThreatType,
        severity: ThreatSeverity,
        description: str,
        source: str,
        metadata: dict,
    ) -> None:
        """Create and register a threat."""
        threat = Threat(
            type=threat_type,
            description=description,
            severity=severity,
            source=source,
            module="FileMonitor",
            metadata=metadata,
        )
        await self.engine.register_threat(threat)
        await self.engine.auto_respond(threat)
