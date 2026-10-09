"""AISS — Celery Application (optional)
Background task queue using Redis as broker and result backend.
If Redis/Celery is not installed, a lightweight stub is returned so the
rest of the application can import this module without crashing.
"""

import os
from utils.logger import setup_logger

logger = setup_logger("celery_app")

BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
RESULT_URL  = os.environ.get("CELERY_RESULT_URL",  "redis://localhost:6379/1")

try:
    from celery import Celery as _Celery

    celery_app = _Celery(
        "aiss",
        broker=BROKER_URL,
        backend=RESULT_URL,
    )
    celery_app.conf.update(
        task_serializer            = "json",
        result_serializer          = "json",
        accept_content             = ["json"],
        timezone                   = "UTC",
        enable_utc                 = True,
        task_track_started         = True,
        task_acks_late             = True,
        worker_prefetch_multiplier = 1,
        task_routes                = {
            "aiss.tasks.scan_file_task":     {"queue": "scan"},
            "aiss.tasks.ai_analyze_task":    {"queue": "ai"},
            "aiss.tasks.enrich_threat_task": {"queue": "intel"},
        },
    )
    logger.info("Celery app initialized (broker: redis)")

except ImportError:
    # Celery not installed — create a harmless stub so imports never fail
    class _CeleryStub:
        """Stub that silently ignores all Celery operations."""
        def task(self, *args, **kwargs):
            def decorator(fn):
                return fn
            return decorator
        def __getattr__(self, name):
            return lambda *a, **kw: None

    celery_app = _CeleryStub()  # type: ignore
    logger.warning("celery not installed — background task queue disabled (non-fatal)")
