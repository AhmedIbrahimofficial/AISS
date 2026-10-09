"""AISS - Logger Utility
Dual-mode logging: structlog structured JSON for prod + human-readable for dev.

Set LOG_FORMAT=json in .env for JSON output.
Default is human-readable (colored in terminals).
"""

import logging
import os
import sys

# Force UTF-8 on Windows so emoji in log messages don't crash the stream handler
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(_PROJECT_ROOT, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FORMAT = os.environ.get("LOG_FORMAT", "text").lower()   # "json" or "text"
LOG_LEVEL  = os.environ.get("LOG_LEVEL",  "DEBUG").upper()

# ── Structlog configuration ───────────────────────────────────────────
_structlog_configured = False


def _configure_structlog():
    global _structlog_configured
    if _structlog_configured:
        return

    try:
        import structlog

        shared_processors = [
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
        ]

        if LOG_FORMAT == "json":
            processors = shared_processors + [
                structlog.processors.format_exc_info,
                structlog.processors.JSONRenderer(),
            ]
        else:
            processors = shared_processors + [
                structlog.dev.ConsoleRenderer(colors=sys.stdout.isatty()),
            ]

        structlog.configure(
            processors=processors,
            wrapper_class=structlog.make_filtering_bound_logger(
                getattr(logging, LOG_LEVEL, logging.DEBUG)
            ),
            context_class=dict,
            logger_factory=structlog.PrintLoggerFactory(),
            cache_logger_on_first_use=True,
        )
        _structlog_configured = True

    except ImportError:
        pass   # structlog not available — fall back to stdlib


def setup_logger(name: str) -> logging.Logger:
    """
    Returns a stdlib Logger named cybersecurity.{name}.
    Also configures structlog on first call.

    Modules can use structlog.get_logger() directly for structured context fields.
    """
    _configure_structlog()

    logger = logging.getLogger(f"cybersecurity.{name}")
    if not logger.handlers:
        logger.setLevel(getattr(logging, LOG_LEVEL, logging.DEBUG))

        if LOG_FORMAT == "json":
            import json as _json

            class _JsonFormatter(logging.Formatter):
                def format(self, record):
                    return _json.dumps({
                        "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
                        "level":     record.levelname,
                        "logger":    record.name,
                        "event":     record.getMessage(),
                        "module":    record.module,
                    })

            fmt = _JsonFormatter()
        else:
            fmt = logging.Formatter(
                "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
            )

        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(fmt)
        logger.addHandler(ch)

        fh = logging.FileHandler(
            os.path.join(LOG_DIR, "cybersecurity.log"), encoding="utf-8"
        )
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger


def get_structlog(name: str):
    """
    Return a structlog bound logger for structured context logging.
    Falls back to a stdlib logger wrapper if structlog is unavailable.
    """
    _configure_structlog()
    try:
        import structlog
        return structlog.get_logger(name)
    except ImportError:
        return setup_logger(name)
