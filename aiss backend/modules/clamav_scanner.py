"""AISS - ClamAV Integration

Detects whether ClamAV is installed and provides async wrappers to scan files
and folders. Never fabricates detections; reports "not_installed" when ClamAV
is unavailable.
"""

from __future__ import annotations

import asyncio
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from utils.logger import setup_logger

logger = setup_logger("clamav_scanner")

IS_WINDOWS = platform.system() == "Windows"


@dataclass
class ClamAVResult:
    installed: bool
    infected: bool
    detections: list[dict]
    clean_count: int
    error_count: int
    scanned_count: int
    errors: list[str]
    signature_version: Optional[str] = None
    engine_version: Optional[str] = None


def _find_clamav_binary(name: str) -> Optional[str]:
    """Locate a ClamAV binary in PATH or common install locations."""
    path = shutil.which(name)
    if path:
        return path
    candidates: list[str] = []
    if IS_WINDOWS:
        candidates = [
            r"C:\Program Files\ClamAV\clamscan.exe",
            r"C:\Program Files (x86)\ClamAV\clamscan.exe",
        ]
    else:
        candidates = [
            "/usr/bin/clamscan",
            "/usr/local/bin/clamscan",
            "/opt/clamav/bin/clamscan",
        ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def _detect_clamav_sync() -> dict:
    """Detect ClamAV installation and version information."""
    binary = _find_clamav_binary("clamscan")
    if not binary:
        return {"installed": False, "reason": "clamscan not found in PATH or common locations"}

    try:
        result = subprocess.run(
            [binary, "--version"], capture_output=True, text=True, timeout=10
        )
        parts = result.stdout.strip().split()
        engine = parts[0] if parts else None
        signature = None
        for i, p in enumerate(parts):
            if "/" in p:
                signature = p
                break
        return {
            "installed": True,
            "binary": binary,
            "engine_version": engine,
            "signature_version": signature,
        }
    except Exception as e:
        return {"installed": False, "reason": f"Failed to query clamscan: {e}"}


async def detect_clamav() -> dict:
    """Async detection of ClamAV installation."""
    return await asyncio.to_thread(_detect_clamav_sync)


def _scan_path_sync(path: str, binary: str) -> ClamAVResult:
    """Synchronously scan a file or directory with clamscan."""
    result = ClamAVResult(
        installed=True,
        infected=False,
        detections=[],
        clean_count=0,
        error_count=0,
        scanned_count=0,
        errors=[],
    )

    if not os.path.exists(path):
        result.errors.append(f"Path does not exist: {path}")
        return result

    cmd = [binary, "--infected", "--no-summary", "--stdout", path]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        # clamscan exit codes: 0 = clean, 1 = virus found, 2 = error
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if ":" in line:
                file_part, virus_part = line.rsplit(":", 1)
                result.detections.append({
                    "path": file_part.strip(),
                    "malware_name": virus_part.strip(),
                    "engine": "clamav",
                })
            else:
                result.errors.append(line)

        if proc.returncode == 1:
            result.infected = True
        elif proc.returncode == 2:
            # Some errors may be present; record stderr if no detections
            if not result.detections and proc.stderr:
                result.errors.append(proc.stderr.strip()[:500])

    except subprocess.TimeoutExpired:
        result.errors.append("ClamAV scan timed out after 300s")
    except Exception as e:
        result.errors.append(f"ClamAV scan failed: {e}")

    result.scanned_count = len(result.detections) + result.clean_count
    return result


async def scan_path(path: str, binary: Optional[str] = None) -> ClamAVResult:
    """Async scan a single file or directory with ClamAV."""
    if binary is None:
        info = await detect_clamav()
        if not info["installed"]:
            return ClamAVResult(
                installed=False,
                infected=False,
                detections=[],
                clean_count=0,
                error_count=0,
                scanned_count=0,
                errors=[info.get("reason", "ClamAV not installed")],
            )
        binary = info["binary"]

    return await asyncio.to_thread(_scan_path_sync, path, binary)


def _scan_paths_sync(paths: list[str], binary: str) -> ClamAVResult:
    """Scan multiple paths and aggregate results."""
    aggregate = ClamAVResult(
        installed=True,
        infected=False,
        detections=[],
        clean_count=0,
        error_count=0,
        scanned_count=0,
        errors=[],
    )
    for p in paths:
        r = _scan_path_sync(p, binary)
        if r.infected:
            aggregate.infected = True
        aggregate.detections.extend(r.detections)
        aggregate.clean_count += r.clean_count
        aggregate.error_count += r.error_count
        aggregate.scanned_count += r.scanned_count
        aggregate.errors.extend(r.errors)
    return aggregate


async def scan_paths(paths: list[str]) -> ClamAVResult:
    """Async scan a list of files/directories with ClamAV."""
    info = await detect_clamav()
    if not info["installed"]:
        return ClamAVResult(
            installed=False,
            infected=False,
            detections=[],
            clean_count=0,
            error_count=0,
            scanned_count=0,
            errors=[info.get("reason", "ClamAV not installed")],
        )
    return await asyncio.to_thread(_scan_paths_sync, paths, info["binary"])
