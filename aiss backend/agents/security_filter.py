"""
Agentic AI Orchestrator — SecurityFilter

Handles:
  - Prompt injection detection (before LLM sees user input)
  - Tool argument injection detection (shell/SQL/XSS patterns)
  - Per-user rate limiting (60 req/min sliding window)

Requirements: 1.6, 13.1, 13.3, 13.6
"""
from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from typing import Any

# ---------------------------------------------------------------------------
# Prompt injection patterns (case-insensitive)
# ---------------------------------------------------------------------------

INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(previous|prior|all)\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+", re.IGNORECASE),
    re.compile(r"disregard\s+(your|all)\s+", re.IGNORECASE),
    re.compile(r"forget\s+(your|all)\s+", re.IGNORECASE),
    re.compile(r"new\s+system\s+prompt", re.IGNORECASE),
    re.compile(r"pretend\s+you\s+are", re.IGNORECASE),
    re.compile(r"act\s+as\s+if\s+you\s+have\s+no\s+", re.IGNORECASE),
    re.compile(r"override\s+(safety|security|policy|rules)", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"DAN\s+mode", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Argument injection patterns
# ---------------------------------------------------------------------------

ARG_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"[;&|`$]"),                                    # shell metacharacters
    re.compile(r"(?:UNION|SELECT|DROP|INSERT)\s", re.IGNORECASE),  # SQL injection
    re.compile(r"\.\.\/"),                                     # path traversal
    re.compile(r"<script", re.IGNORECASE),                     # XSS
]


class SecurityFilter:
    """
    Stateful (per-instance) rate limiter + stateless injection detectors.
    One instance should be shared across the application lifetime.
    """

    def __init__(self) -> None:
        # user_id -> deque of request timestamps (float, epoch seconds)
        self._rate_buckets: dict[str, deque[float]] = defaultdict(deque)

    # ------------------------------------------------------------------
    # Prompt injection detection
    # ------------------------------------------------------------------

    def detect_injection(self, message: str) -> bool:
        """
        Return True if `message` contains any prompt injection pattern.
        Called BEFORE the message is forwarded to the LLM.
        """
        for pattern in INJECTION_PATTERNS:
            if pattern.search(message):
                return True
        return False

    # ------------------------------------------------------------------
    # Tool argument injection detection
    # ------------------------------------------------------------------

    def sanitize_args(self, args: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        """
        Scan every string value in `args` (recursively) for injection patterns.
        Returns (original_args, injection_detected).
        Does NOT modify args.
        """
        injection_detected = self._scan_value(args)
        return args, injection_detected

    def _scan_value(self, value: Any) -> bool:
        """Recursively scan a value for injection patterns. Returns True if found."""
        if isinstance(value, str):
            for pattern in ARG_INJECTION_PATTERNS:
                if pattern.search(value):
                    return True
            return False
        if isinstance(value, dict):
            return any(self._scan_value(v) for v in value.values())
        if isinstance(value, list):
            return any(self._scan_value(item) for item in value)
        return False

    # ------------------------------------------------------------------
    # Rate limiting (in-process sliding window)
    # ------------------------------------------------------------------

    async def check_rate_limit(
        self,
        user_id: str,
        limit: int = 60,
        window_seconds: int = 60,
    ) -> bool:
        """
        Sliding-window rate limiter.
        Returns True if the request is allowed, False if rate-limited.
        Window: `window_seconds` seconds, max `limit` requests per user.
        """
        now = time.monotonic()
        bucket = self._rate_buckets[user_id]

        # Evict timestamps outside the window
        cutoff = now - window_seconds
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

        if len(bucket) >= limit:
            return False  # rate limited

        bucket.append(now)
        return True
