"""
AISS - USB / Removable Device Monitor
───────────────────────────────────────
Monitors USB and removable drives as they connect to the system.

On every new device detected:
  1. Identify device: drive letter, label, size, filesystem
  2. Scan ALL files on the drive:
     - Known malware hashes (SHA256)
     - High entropy files (>7.2 = packed/encrypted)
     - Suspicious executables in root
     - Autorun.inf presence (classic autorun attack)
     - Malicious script patterns in text files
  3. Risk assessment:
     - CLEAN   → log quietly, no alert
     - WARN    → print yellow warning (suspicious but not confirmed malicious)
     - DANGER  → register threat + terminal alert (confirmed malicious indicator)

Ignored (mamuli cheezein - never alerted):
  - Normal documents: .pdf, .docx, .xlsx, .jpg, .png, .mp4, .mp3, etc.
  - Small drives with only media/document files
  - Drives with no executable content at all

Windows: uses win32api / psutil disk partition detection
Linux:   watches /proc/mounts or /media

Runs as a background asyncio task — polling every 3 seconds.
"""

import asyncio
import collections
import hashlib
import math
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False

from models.threat import Threat, ThreatType, ThreatSeverity
from utils.logger import setup_logger

logger = setup_logger("usb_monitor")

IS_WINDOWS = sys.platform == "win32"

# ── ANSI colours ──────────────────────────────────────────────────────
R   = "\033[91m"
Y   = "\033[93m"
C   = "\033[96m"
G   = "\033[92m"
W   = "\033[97m"
DIM = "\033[2m"
B   = "\033[94m"
RST = "\033[0m"

# ══════════════════════════════════════════════════════════════════════
# Config
# ══════════════════════════════════════════════════════════════════════

# Extensions that are NEVER suspicious — skip silently
SAFE_EXTENSIONS = {
    ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp",
    ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv",
    ".mp3", ".wav", ".flac", ".aac", ".ogg",
    ".txt", ".md", ".csv", ".json", ".xml", ".html", ".htm",
    ".zip", ".rar", ".7z", ".tar", ".gz",   # archives — noted but not flagged
    ".iso",                                  # disk images — noted only
    ".lnk",                                  # shortcuts — flagged separately
}

# Extensions that are suspicious and need deeper inspection
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta",
    ".scr", ".pif", ".com", ".jar", ".dll", ".msi",
    ".wsf", ".reg", ".cpl", ".inf", ".sys", ".drv",
}

# Malicious script patterns
MALICIOUS_PATTERNS = [
    re.compile(r"powershell.*-enc",               re.I),
    re.compile(r"cmd.*\/c.*certutil.*-decode",    re.I),
    re.compile(r"mshta.*http",                    re.I),
    re.compile(r"wscript.*\.vbs",                 re.I),
    re.compile(r"regsvr32.*scrobj",               re.I),
    re.compile(r"rundll32.*javascript",           re.I),
    re.compile(r"IEX\s*\(.*DownloadString",       re.I),
    re.compile(r"Net\.WebClient.*Download",       re.I),
    re.compile(r"bash.*-i.*>&.*/dev/tcp",         re.I),
    re.compile(r"nc\s+.*-e\s+/bin",              re.I),
    re.compile(r"curl.*\|.*bash",                 re.I),
    re.compile(r"wget.*\|\s*(ba)?sh",             re.I),
    re.compile(r"Add-MpPreference.*Exclusion",    re.I),   # AV bypass
    re.compile(r"vssadmin.*delete.*shadows",      re.I),   # ransomware
    re.compile(r"Set-MpPreference.*Disable",      re.I),   # disable defender
]

# Known malicious hashes (SHA256)
MALICIOUS_HASHES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # EICAR
    "44d88612fea8a8f36de82e1278abb02f",
}

# Ransomware extensions on USB
RANSOMWARE_EXTENSIONS = {
    ".encrypted", ".locked", ".crypt", ".wnry", ".wncry",
    ".cerber", ".locky", ".zepto", ".thor",
}

# Max files to deep-scan (avoid hanging on huge drives)
MAX_SCAN_FILES   = 2000
MAX_FILE_SIZE_MB = 50    # skip files larger than this for content scan
ENTROPY_THRESHOLD = 7.2


# ══════════════════════════════════════════════════════════════════════
# State
# ══════════════════════════════════════════════════════════════════════

# Already-seen drives: {mountpoint → device_id}
_known_drives: dict[str, str] = {}

# Scan results cache: {mountpoint → scan_result_dict}
_scan_cache: dict[str, dict] = {}


# ══════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════

def _file_entropy(path: str, max_bytes: int = 65536) -> float:
    """Calculate Shannon entropy of file. >7.2 = likely packed/encrypted."""
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


def _sha256(path: str) -> str:
    """Calculate SHA256 hash of a file."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _get_removable_drives() -> list[dict]:
    """
    Return list of currently connected removable/USB drives.
    Each entry: {mountpoint, device, fstype, label, total_gb, opts}
    """
    drives = []
    if not _PSUTIL:
        return drives
    try:
        for part in psutil.disk_partitions(all=False):
            opts = part.opts.lower() if part.opts else ""
            # Windows: removable drives have 'removable' in opts or drive type
            # Linux: usb drives typically mounted under /media or /run/media
            is_removable = False

            if IS_WINDOWS:
                # psutil on Windows marks removable as 'removable' in opts
                if "removable" in opts:
                    is_removable = True
                # Also catch USB drives that appear as fixed but have USB in device
                elif "usb" in part.device.lower():
                    is_removable = True
            else:
                # Linux: mounted under /media, /mnt, /run/media
                mp = part.mountpoint.lower()
                if any(mp.startswith(p) for p in ["/media", "/mnt", "/run/media"]):
                    is_removable = True

            if not is_removable:
                continue

            # Try to get disk usage
            try:
                usage     = psutil.disk_usage(part.mountpoint)
                total_gb  = round(usage.total / 1024 / 1024 / 1024, 2)
            except Exception:
                total_gb  = 0

            # Try to get volume label (Windows only)
            label = ""
            if IS_WINDOWS:
                try:
                    import ctypes
                    buf = ctypes.create_unicode_buffer(256)
                    ctypes.windll.kernel32.GetVolumeInformationW(
                        part.mountpoint, buf, 256,
                        None, None, None, None, 0
                    )
                    label = buf.value or ""
                except Exception:
                    pass

            drives.append({
                "mountpoint": part.mountpoint,
                "device":     part.device,
                "fstype":     part.fstype,
                "label":      label or "Unknown",
                "total_gb":   total_gb,
                "opts":       opts,
            })
    except Exception as e:
        logger.debug(f"Drive enumeration error: {e}")
    return drives


# ══════════════════════════════════════════════════════════════════════
# USB Scanner
# ══════════════════════════════════════════════════════════════════════

class USBScanResult:
    """Holds the result of scanning a USB drive."""

    def __init__(self, drive: dict):
        self.drive          = drive
        self.total_files    = 0
        self.scanned_files  = 0
        self.risk_level     = "CLEAN"   # CLEAN | WARN | DANGER
        self.findings: list[dict] = []  # list of {file, reason, severity}
        self.has_autorun    = False
        self.exec_count     = 0         # number of executables
        self.malware_count  = 0
        self.suspicious_count = 0
        self.scan_duration  = 0.0

    def add_finding(self, filepath: str, reason: str, severity: str) -> None:
        self.findings.append({
            "file":     filepath,
            "reason":   reason,
            "severity": severity,
        })
        if severity == "DANGER":
            self.malware_count   += 1
            self.risk_level       = "DANGER"
        elif severity == "WARN" and self.risk_level == "CLEAN":
            self.suspicious_count += 1
            self.risk_level        = "WARN"


async def scan_usb_drive(drive: dict) -> USBScanResult:
    """
    Deep scan a USB drive for malicious content.
    Returns USBScanResult with risk level and all findings.
    """
    mp     = drive["mountpoint"]
    result = USBScanResult(drive)
    t0     = time.time()

    logger.info(f"🔍 USB scan started: {mp} ({drive['label']}, {drive['total_gb']}GB)")

    try:
        # Walk the drive
        files_to_check = []
        for root, dirs, files in os.walk(mp):
            # Skip system folders
            dirs[:] = [d for d in dirs if d.lower() not in {
                "system volume information", "$recycle.bin", "recycler",
                ".spotlight-v100", ".trashes", ".fseventsd",
            }]
            for fname in files:
                result.total_files += 1
                fpath = os.path.join(root, fname)
                files_to_check.append(fpath)
                if result.total_files >= MAX_SCAN_FILES:
                    break
            if result.total_files >= MAX_SCAN_FILES:
                break

        # ── Check autorun.inf ──────────────────────────────────────────
        autorun_path = os.path.join(mp, "autorun.inf")
        if os.path.exists(autorun_path):
            result.has_autorun = True
            result.add_finding(
                autorun_path,
                "autorun.inf present — classic USB malware spreading mechanism",
                "DANGER",
            )

        # ── Scan each file ─────────────────────────────────────────────
        for fpath in files_to_check:
            try:
                ext  = Path(fpath).suffix.lower()
                name = Path(fpath).name.lower()

                # Skip safe extensions unless autorun/suspicious name
                if ext in SAFE_EXTENSIONS and "autorun" not in name:
                    continue

                try:
                    stat = os.stat(fpath)
                    size_mb = stat.st_size / 1024 / 1024
                except OSError:
                    continue

                result.scanned_files += 1

                # ── Known malware hash check ───────────────────────────
                if size_mb < 50:
                    fhash = _sha256(fpath)
                    if fhash and fhash in MALICIOUS_HASHES:
                        result.add_finding(
                            fpath,
                            f"Known malware hash: {fhash[:16]}...",
                            "DANGER",
                        )
                        continue

                # ── Ransomware extension check ─────────────────────────
                if ext in RANSOMWARE_EXTENSIONS:
                    result.add_finding(
                        fpath,
                        f"Ransomware encrypted file extension: {ext}",
                        "DANGER",
                    )
                    continue

                # ── Suspicious executable ──────────────────────────────
                if ext in SUSPICIOUS_EXTENSIONS:
                    result.exec_count += 1

                    # High entropy = packed/obfuscated = likely malware
                    if size_mb < MAX_FILE_SIZE_MB:
                        entropy = _file_entropy(fpath)
                        if entropy > ENTROPY_THRESHOLD:
                            result.add_finding(
                                fpath,
                                f"High-entropy executable (entropy={entropy:.2f}) — packed/obfuscated",
                                "DANGER",
                            )
                            continue

                    # Executable in root of drive = suspicious
                    parent = str(Path(fpath).parent)
                    if parent.rstrip("/\\") == mp.rstrip("/\\"):
                        result.add_finding(
                            fpath,
                            f"Executable in USB root: {name}",
                            "WARN",
                        )
                        continue

                # ── .lnk shortcut pointing to suspicious target ────────
                if ext == ".lnk" and size_mb < 1:
                    result.add_finding(
                        fpath,
                        "Shortcut (.lnk) file — may point to malicious target",
                        "WARN",
                    )
                    continue

                # ── Script content scan ────────────────────────────────
                script_exts = {".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".wsf"}
                if ext in script_exts and size_mb < MAX_FILE_SIZE_MB:
                    try:
                        with open(fpath, "r", errors="ignore") as f:
                            content = f.read(50000)
                        for pattern in MALICIOUS_PATTERNS:
                            if pattern.search(content):
                                result.add_finding(
                                    fpath,
                                    f"Malicious script pattern: {pattern.pattern[:60]}",
                                    "DANGER",
                                )
                                break
                    except Exception:
                        pass

            except Exception:
                continue

            # Yield control periodically so event loop doesn't block
            if result.scanned_files % 100 == 0:
                await asyncio.sleep(0)

    except Exception as e:
        logger.error(f"USB scan error on {mp}: {e}")

    result.scan_duration = round(time.time() - t0, 2)
    return result


# ══════════════════════════════════════════════════════════════════════
# Terminal output
# ══════════════════════════════════════════════════════════════════════

def _print_usb_connected(drive: dict) -> None:
    """Print USB connected notification."""
    now = datetime.now().strftime("%H:%M:%S")
    print(
        f"{DIM}[AISS USB ]{RST} {W}{now}{RST} | {C}🔌 USB CONNECTED{RST} "
        f"| {W}{drive['label']}{RST} "
        f"({drive['total_gb']}GB, {drive['fstype']}) "
        f"→ {drive['mountpoint']}  — scanning...",
        flush=True,
    )


def _print_scan_result(result: USBScanResult) -> None:
    """Print scan result to terminal."""
    now   = datetime.now().strftime("%H:%M:%S")
    drive = result.drive
    mp    = drive["mountpoint"]

    if result.risk_level == "CLEAN":
        print(
            f"{DIM}[AISS USB ]{RST} {W}{now}{RST} | {G}✅ CLEAN   {RST} "
            f"| {drive['label']} ({drive['total_gb']}GB) "
            f"— {result.total_files} files checked, "
            f"{result.exec_count} executables "
            f"({result.scan_duration}s)",
            flush=True,
        )
        return

    if result.risk_level == "WARN":
        print(
            f"{DIM}[AISS USB ]{RST} {W}{now}{RST} | {Y}⚠  WARNING {RST} "
            f"| {drive['label']} ({drive['total_gb']}GB) "
            f"— {result.suspicious_count} suspicious item(s) found",
            flush=True,
        )
        for f in result.findings[:5]:
            fname = Path(f["file"]).name
            print(
                f"{DIM}[AISS USB ]{RST}   {Y}↳ WARN{RST}  "
                f"{fname:<30} {DIM}{f['reason'][:70]}{RST}",
                flush=True,
            )
        return

    # DANGER
    print(
        f"{DIM}[AISS USB ]{RST} {W}{now}{RST} | {R}🔴 DANGER  {RST} "
        f"| {drive['label']} ({drive['total_gb']}GB) "
        f"— {result.malware_count} MALICIOUS file(s) detected!",
        flush=True,
    )
    for f in result.findings[:10]:
        sev   = f["severity"]
        color = R if sev == "DANGER" else Y
        fname = Path(f["file"]).name
        print(
            f"{DIM}[AISS USB ]{RST}   {color}↳ {sev:<6}{RST} "
            f"{fname:<30} {f['reason'][:70]}",
            flush=True,
        )
    if len(result.findings) > 10:
        print(
            f"{DIM}[AISS USB ]{RST}   {R}↳ ... and {len(result.findings)-10} more findings{RST}",
            flush=True,
        )


# ══════════════════════════════════════════════════════════════════════
# Background loop
# ══════════════════════════════════════════════════════════════════════

async def usb_monitor_loop(engine) -> None:
    """
    Background asyncio task.
    Polls every 3 seconds for new removable drives.
    On new drive: scan it, assess risk, alert if needed.
    """
    if not _PSUTIL:
        logger.warning("psutil not available — USB monitor disabled")
        return

    logger.info("🔌 USB monitor started (polling every 3s)")

    # Capture drives already present at startup (don't alert for these)
    for drive in _get_removable_drives():
        _known_drives[drive["mountpoint"]] = drive["device"]

    while True:
        try:
            await asyncio.sleep(3)
            current = _get_removable_drives()
            current_mps = {d["mountpoint"] for d in current}

            # ── Detect newly connected drives ──────────────────────────
            for drive in current:
                mp = drive["mountpoint"]
                if mp in _known_drives:
                    continue

                # New drive!
                _known_drives[mp] = drive["device"]
                _print_usb_connected(drive)

                # Show checking message
                now_str = datetime.now().strftime("%H:%M:%S")
                print(
                    f"{DIM}[AISS USB ]{RST} {W}{now_str}{RST} | "
                    f"{Y}🔍 CHECKING FOR THREATS...{RST} "
                    f"| Scanning {drive['label']} ({drive['total_gb']}GB)",
                    flush=True,
                )

                # Scan it
                result = await scan_usb_drive(drive)
                _scan_cache[mp] = {
                    "drive":           drive,
                    "risk_level":      result.risk_level,
                    "total_files":     result.total_files,
                    "scanned_files":   result.scanned_files,
                    "exec_count":      result.exec_count,
                    "malware_count":   result.malware_count,
                    "suspicious_count": result.suspicious_count,
                    "findings":        result.findings,
                    "scan_duration":   result.scan_duration,
                    "scanned_at":      datetime.utcnow().isoformat(),
                }

                # Print result
                _print_scan_result(result)

                # ── Register threat if DANGER ──────────────────────────
                if result.risk_level == "DANGER":
                    threat = Threat(
                        type        = ThreatType.INTRUSION,
                        description = (
                            f"MALICIOUS USB DETECTED: {drive['label']} "
                            f"({drive['total_gb']}GB) at {mp} — "
                            f"{result.malware_count} malicious file(s)"
                        ),
                        severity    = ThreatSeverity.CRITICAL,
                        source      = mp,
                        module      = "USBMonitor",
                        metadata    = {
                            "mountpoint":   mp,
                            "label":        drive["label"],
                            "total_gb":     drive["total_gb"],
                            "fstype":       drive["fstype"],
                            "malware_count": result.malware_count,
                            "findings":     result.findings[:20],
                            "has_autorun":  result.has_autorun,
                        },
                    )
                    await engine.register_threat(threat)

                # ── Register threat if WARN ────────────────────────────
                elif result.risk_level == "WARN":
                    threat = Threat(
                        type        = ThreatType.SUSPICIOUS_FILE,
                        description = (
                            f"SUSPICIOUS USB: {drive['label']} "
                            f"({drive['total_gb']}GB) at {mp} — "
                            f"{result.suspicious_count} suspicious item(s)"
                        ),
                        severity    = ThreatSeverity.HIGH,
                        source      = mp,
                        module      = "USBMonitor",
                        metadata    = {
                            "mountpoint":      mp,
                            "label":           drive["label"],
                            "total_gb":        drive["total_gb"],
                            "suspicious_count": result.suspicious_count,
                            "findings":        result.findings[:10],
                        },
                    )
                    await engine.register_threat(threat)

            # ── Detect removed drives ──────────────────────────────────
            for mp in list(_known_drives.keys()):
                if mp not in current_mps:
                    now = datetime.now().strftime("%H:%M:%S")
                    print(
                        f"{DIM}[AISS USB ]{RST} {W}{now}{RST} | "
                        f"{DIM}🔌 USB REMOVED{RST} | {mp}",
                        flush=True,
                    )
                    del _known_drives[mp]
                    _scan_cache.pop(mp, None)

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.debug(f"USB monitor loop error: {e}")


# ══════════════════════════════════════════════════════════════════════
# API helpers
# ══════════════════════════════════════════════════════════════════════

def get_usb_status() -> dict:
    """Return current USB scan status for API endpoint."""
    return {
        "connected_drives": len(_known_drives),
        "scan_cache":       dict(_scan_cache),
        "known_mounts":     list(_known_drives.keys()),
    }
