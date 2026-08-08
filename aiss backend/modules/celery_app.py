"""AISS - Celery Application
Background task queue using Redis as broker and result backend.

Redis must be running: redis-cli ping → PONG
Configure via .env:
  CELERY_BROKER_URL   = redis://localhost:6379/0  (default)
  CELERY_RESULT_URL   = redis://localhost:6379/1  (default)

If Redis is unavailable, the app still starts — Celery tasks simply won't
be processable until a worker connects.
"""

import os
from celery import Celery

BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
RESULT_URL  = os.environ.get("CELERY_RESULT_URL",  "redis://localhost:6379/1")

celery_app = Celery(
    "aiss",
    broker=BROKER_URL,
    backend=RESULT_URL,
)

celery_app.conf.update(
    task_serializer          = "json",
    result_serializer        = "json",
    accept_content           = ["json"],
    timezone                 = "UTC",
    enable_utc               = True,
    task_track_started       = True,
    task_acks_late           = True,
    worker_prefetch_multiplier = 1,
    task_routes              = {
        "aiss.tasks.scan_file_task":     {"queue": "scan"},
        "aiss.tasks.ai_analyze_task":    {"queue": "ai"},
        "aiss.tasks.enrich_threat_task": {"queue": "intel"},
    },
)
