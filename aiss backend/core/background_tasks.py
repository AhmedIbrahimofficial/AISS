"""AISS - Async Background Task Runner

Lightweight replacement for Celery+Redis when Redis is unavailable.
Uses asyncio tasks with a simple in-memory store for results.

Usage:
    from core.background_tasks import background_runner

    # Submit a task
    task_id = await background_runner.submit(my_async_fn, arg1, arg2)

    # Check result
    result = background_runner.get_result(task_id)
"""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Optional

from utils.logger import setup_logger

logger = setup_logger("background_tasks")


class TaskState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class TaskResult:
    id: str
    state: TaskState = TaskState.PENDING
    result: Any = None
    error: Optional[str] = None
    submitted_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "state": self.state.value,
            "result": self.result,
            "error": self.error,
            "submitted_at": self.submitted_at,
            "completed_at": self.completed_at,
        }


class BackgroundTaskRunner:
    """Asyncio-based background task runner.

    Drop-in replacement for Celery when Redis is unavailable.
    Results stored in-memory (up to 1000 tasks, FIFO eviction).
    """

    MAX_STORED = 1000

    def __init__(self) -> None:
        self._tasks: dict[str, TaskResult] = {}
        self._running: dict[str, asyncio.Task] = {}

    async def submit(
        self,
        fn: Callable[..., Coroutine],
        *args: Any,
        task_name: str = "",
        **kwargs: Any,
    ) -> str:
        """Submit an async coroutine as a background task. Returns task_id."""
        task_id = f"bg_{secrets.token_hex(8)}"
        tr = TaskResult(id=task_id)
        self._tasks[task_id] = tr

        async def _wrapper() -> None:
            tr.state = TaskState.RUNNING
            try:
                tr.result = await fn(*args, **kwargs)
                tr.state = TaskState.COMPLETED
            except Exception as exc:
                tr.state = TaskState.FAILED
                tr.error = str(exc)
                logger.warning("Background task %s (%s) failed: %s", task_id, task_name, exc)
            finally:
                tr.completed_at = time.time()
                self._running.pop(task_id, None)
                self._evict_old()

        bg_task = asyncio.create_task(_wrapper(), name=f"bg_{task_name or task_id}")
        self._running[task_id] = bg_task
        return task_id

    def get_result(self, task_id: str) -> Optional[dict]:
        """Get the result of a background task. Returns None if not found."""
        tr = self._tasks.get(task_id)
        if tr is None:
            return None
        return tr.to_dict()

    def is_running(self, task_id: str) -> bool:
        tr = self._tasks.get(task_id)
        return tr is not None and tr.state == TaskState.RUNNING

    def cancel(self, task_id: str) -> bool:
        """Cancel a running background task."""
        task = self._running.get(task_id)
        if task and not task.done():
            task.cancel()
            tr = self._tasks.get(task_id)
            if tr:
                tr.state = TaskState.FAILED
                tr.error = "Cancelled"
            return True
        return False

    def _evict_old(self) -> None:
        """Remove oldest completed tasks when store exceeds MAX_STORED."""
        if len(self._tasks) <= self.MAX_STORED:
            return
        # Sort by submitted_at and remove oldest
        sorted_ids = sorted(
            self._tasks.keys(),
            key=lambda k: self._tasks[k].submitted_at,
        )
        for tid in sorted_ids[: len(sorted_ids) // 2]:
            if tid not in self._running:
                del self._tasks[tid]

    @property
    def active_count(self) -> int:
        return len(self._running)

    @property
    def total_stored(self) -> int:
        return len(self._tasks)


# Module-level singleton
background_runner = BackgroundTaskRunner()
