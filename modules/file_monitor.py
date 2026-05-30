"""
Cybersecurity - File Monitor Module
Detects: Suspicious files, malicious scripts, ransomware patterns, data exfiltration.
Windows + Linux compatible.
"""

import asyncio
import os
import sys
import hashlib
import re
from pathlib import Path
from models.threat import Threat, ThreatType, ThreatSeverity
from utils.logger import setup_logger

logger = setup_logger("file_monitor")

IS_WINDOWS = sys.platform == "win32"

# Known malicious file hashes (SHA256)
MALICIOUS_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f",                                          # EICAR MD5
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",          # EICAR SHA256
}

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta",
    ".scr", ".pif", ".com", ".jar", ".py", ".sh", ".dll"
}

RANSOMWARE_EXTENSIONS = {
    ".encrypted", ".locked", ".crypt", ".crypted", ".enc",
    ".wnry", ".wncry", ".cerber", ".locky", ".zepto"
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
    # Windows-specific
    re.compile(r"IEX\s*\(.*DownloadString",   re.I),
    re.compile(r"certutil.*-decode",           re.I),
    re.compile(r"regsvr32.*scrobj",            re.I),
]


def _get_watch_dirs() -> list[str]:
    """Return platform-appropriate directories to watch."""
    if IS_WINDOWS:
        temp = os.environ.get("TEMP", "C:\\Windows\\Temp")
        appdata = os.environ.get("APPDATA", "")
        downloads = os.path.join(os.path.expanduser("~"), "Downloads")
        return [d for d in [temp, downloads, appdata] if d and os.path.exists(d)]
    else:
        return [d for d in ["/tmp", "/var/tmp", os.path.expanduser("~/Downloads")] if os.path.exists(d)]


def _get_temp_dir() -> str:
    if IS_WINDOWS:
        return os.environ.get("TEMP", "C:\\Windows\\Temp").lower()
    return "/tmp"


class FileMonitor:
    def __init__(self, engine):
        self.engine = engine
        self._scanned_files: set = set()

    async def scan(self):
        """Scan watched directories for threats."""
        await asyncio.gather(
            self._scan_directories(),
            self._check_ransomware_activity(),
        )

    async def _scan_directories(self):
        for watch_dir in _get_watch_dirs():
            try:
                for entry in os.scandir(watch_dir):
                    if entry.is_file():
                        await self._inspect_file(entry.path)
            except (PermissionError, OSError):
                pass

    async def _inspect_file(self, filepath: str):
        try:
            stat = os.stat(filepath)
            key = f"{filepath}:{stat.st_mtime}"
            if key in self._scanned_files:
                return
            self._scanned_files.add(key)

            ext = Path(filepath).suffix.lower()

            file_hash = await self._hash_file(filepath)
            if file_hash in MALICIOUS_HASHES:
                threat = Threat(
                    type=ThreatType.VIRUS,
                    description=f"Known malware hash detected: {filepath}",
                    severity=ThreatSeverity.CRITICAL,
                    source=filepath,
                    module="FileMonitor",
                    metadata={"hash": file_hash, "path": filepath}
                )
                await self.engine.register_threat(threat)
                await self.engine.auto_respond(threat)
                return

            if ext in {".sh", ".py", ".js", ".ps1", ".vbs", ".bat", ".cmd"}:
                await self._scan_script_content(filepath)

            temp_dir = _get_temp_dir()
            if ext in SUSPICIOUS_EXTENSIONS and temp_dir in filepath.lower():
                threat = Threat(
                    type=ThreatType.SUSPICIOUS_FILE,
                    description=f"Suspicious executable in temp directory: {filepath}",
                    severity=ThreatSeverity.HIGH,
                    source=filepath,
                    module="FileMonitor",
                    metadata={"extension": ext, "path": filepath, "size": stat.st_size}
                )
                await self.engine.register_threat(threat)

        except (PermissionError, FileNotFoundError, OSError):
            pass

    async def _scan_script_content(self, filepath: str):
        try:
            with open(filepath, "r", errors="ignore") as f:
                content = f.read(50000)
            for pattern in MALICIOUS_PATTERNS:
                if pattern.search(content):
                    threat = Threat(
                        type=ThreatType.MALICIOUS_SCRIPT,
                        description=f"Malicious pattern detected in script: {filepath}",
                        severity=ThreatSeverity.HIGH,
                        source=filepath,
                        module="FileMonitor",
                        metadata={"pattern": pattern.pattern, "path": filepath}
                    )
                    await self.engine.register_threat(threat)
                    return
        except Exception:
            pass

    async def _check_ransomware_activity(self):
        home = os.path.expanduser("~")
        encrypted_count = 0
        try:
            for root, _, files in os.walk(home):
                for fname in files:
                    if Path(fname).suffix.lower() in RANSOMWARE_EXTENSIONS:
                        encrypted_count += 1
                if encrypted_count >= 5:
                    threat = Threat(
                        type=ThreatType.RANSOMWARE,
                        description=f"Ransomware activity detected — {encrypted_count}+ files encrypted",
                        severity=ThreatSeverity.CRITICAL,
                        source=home,
                        module="FileMonitor",
                        metadata={"encrypted_file_count": encrypted_count}
                    )
                    await self.engine.register_threat(threat)
                    await self.engine.auto_respond(threat)
                    break
        except Exception as e:
            logger.debug(f"Ransomware check error: {e}")

    async def _hash_file(self, filepath: str) -> str:
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return ""
