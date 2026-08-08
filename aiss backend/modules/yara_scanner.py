"""AISS - YARA Scanner Module
Real YARA rule compilation and matching against files and process memory.
Replaces the inline Python dict "YARA-style" engine in malware_scanner.py.
"""

import os
import glob
from pathlib import Path
from utils.logger import setup_logger

logger = setup_logger("yara_scanner")

# Rules directory
RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")

# Compiled YARA rules (loaded once at import time)
_compiled_rules = None


def _load_rules():
    """Compile all .yar files in the rules/ directory into a single ruleset."""
    global _compiled_rules
    try:
        import yara
    except ImportError:
        logger.warning("yara-python not installed — YARA scanning disabled")
        return None

    yar_files = glob.glob(os.path.join(RULES_DIR, "*.yar"))
    if not yar_files:
        logger.warning(f"No .yar files found in {RULES_DIR}")
        return None

    try:
        # Compile all rule files into one namespace
        filepaths = {Path(f).stem: f for f in yar_files}
        rules = yara.compile(filepaths=filepaths)
        logger.info(f"✅ YARA: compiled {len(yar_files)} rule file(s) from {RULES_DIR}")
        return rules
    except Exception as e:
        logger.error(f"YARA rule compilation failed: {e}")
        return None


def get_rules():
    """Return compiled YARA rules, loading on first call."""
    global _compiled_rules
    if _compiled_rules is None:
        _compiled_rules = _load_rules()
    return _compiled_rules


def reload_rules():
    """Force reload of YARA rules from disk (useful after adding new rules)."""
    global _compiled_rules
    _compiled_rules = None
    return get_rules() is not None


def scan_file(filepath: str) -> list[dict]:
    """
    Scan a file with compiled YARA rules.
    Returns list of match dicts: {rule, severity, description, strings}
    """
    rules = get_rules()
    if not rules:
        return []

    try:
        matches = rules.match(filepath, timeout=10)
        results = []
        for m in matches:
            severity = m.meta.get("severity", "HIGH")
            results.append({
                "rule":        m.rule,
                "namespace":   m.namespace,
                "severity":    severity,
                "description": m.meta.get("description", f"YARA rule matched: {m.rule}"),
                "strings":     [(str(s.identifier), str(s.instances[0].matched_data[:64]
                                  if s.instances else b""))
                                for s in m.strings[:5]],
            })
        return results
    except Exception as e:
        logger.debug(f"YARA file scan error ({filepath}): {e}")
        return []


def scan_data(data: bytes, context: str = "") -> list[dict]:
    """
    Scan raw bytes with compiled YARA rules (for process memory regions).
    Returns list of match dicts.
    """
    rules = get_rules()
    if not rules or not data:
        return []

    try:
        matches = rules.match(data=data, timeout=5)
        results = []
        for m in matches:
            severity = m.meta.get("severity", "HIGH")
            results.append({
                "rule":        m.rule,
                "namespace":   m.namespace,
                "severity":    severity,
                "description": m.meta.get("description", f"YARA rule matched: {m.rule}"),
                "context":     context,
            })
        return results
    except Exception as e:
        logger.debug(f"YARA data scan error: {e}")
        return []


def scan_process_memory(pid: int) -> list[dict]:
    """
    Scan memory-mapped files of a process with real YARA rules.
    Throttled — check _yara_last_scanned before calling.
    """
    rules = get_rules()
    if not rules:
        return []

    results = []
    try:
        import psutil
        proc = psutil.Process(pid)
        try:
            maps = proc.memory_maps(grouped=False)
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            return []

        scanned_paths: set[str] = set()
        for mmap in maps:
            path = getattr(mmap, "path", "") or ""
            if not path or path in scanned_paths or not os.path.isfile(path):
                continue
            scanned_paths.add(path)
            try:
                with open(path, "rb") as f:
                    data = f.read(131072)  # 128KB
                matches = scan_data(data, context=f"PID:{pid} map:{path}")
                results.extend(matches)
            except Exception:
                continue

    except Exception as e:
        logger.debug(f"YARA process memory scan error (PID {pid}): {e}")

    return results
