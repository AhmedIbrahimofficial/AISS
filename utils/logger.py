"""AISS - Logger Utility"""
import logging
import os
import sys

# Force UTF-8 on Windows so emoji in log messages don't crash the stream handler
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass  # reconfigure not available in all environments

# Resolve logs/ relative to the project root (one level up from utils/)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(_PROJECT_ROOT, "logs")
os.makedirs(LOG_DIR, exist_ok=True)


def setup_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(f"cybersecurity.{name}")
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        fmt = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")

        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(fmt)
        logger.addHandler(ch)

        fh = logging.FileHandler(os.path.join(LOG_DIR, "cybersecurity.log"), encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger
