"""AISS - Custom Prometheus Metrics
Defines and exposes AISS-specific metrics using prometheus_client directly.

Metrics exposed:
  aiss_threats_total{severity, type}      — counter, incremented on each new threat
  aiss_threats_active                     — gauge, current active threat count
  aiss_threats_resolved_total             — counter, total resolved
  aiss_scan_duration_seconds{module}      — histogram, time each module scan takes
  aiss_llm_requests_total{provider}       — counter, LLM API calls made
  aiss_llm_tokens_total{provider, direction} — counter, tokens consumed
  aiss_anomaly_score                      — histogram, online ML anomaly scores
  aiss_blocked_ips_total                  — gauge, currently blocked IPs

All metrics are registered once at import time. Importing this module
twice is safe — the _CREATED guard prevents duplicate registration.

Integrated into main.py lifespan and ThreatEngine.register_threat().
Exposed via Prometheus FastAPI Instrumentator on /metrics.
"""
import os
from utils.logger import setup_logger

logger = setup_logger("metrics")

# ── Lazy flag — only register once ───────────────────────────────────
_CREATED = False

# Public handles — None until init() is called
threats_total        = None
threats_active       = None
threats_resolved     = None
scan_duration        = None
llm_requests         = None
llm_tokens           = None
anomaly_score_hist   = None
blocked_ips          = None


def init() -> bool:
    """
    Register all custom AISS Prometheus metrics.
    Safe to call multiple times — idempotent.
    Returns True if prometheus_client is available.
    """
    global _CREATED
    global threats_total, threats_active, threats_resolved
    global scan_duration, llm_requests, llm_tokens
    global anomaly_score_hist, blocked_ips

    if _CREATED:
        return True

    try:
        from prometheus_client import (
            Counter, Gauge, Histogram, REGISTRY
        )

        def _safe(name, desc, labels=None, cls=None, buckets=None):
            """Register metric, skipping if already registered (e.g. hot-reload)."""
            try:
                kwargs = {"name": name, "documentation": desc}
                if labels:
                    kwargs["labelnames"] = labels
                if buckets is not None:
                    kwargs["buckets"] = buckets
                return cls(**kwargs)
            except Exception as e:
                # Already registered — retrieve existing collector
                try:
                    return REGISTRY._names_to_collectors.get(name)
                except Exception:
                    return None

        threats_total = _safe(
            "aiss_threats_total",
            "Total threats detected by AISS",
            labels=["severity", "type"],
            cls=Counter,
        )
        threats_active = _safe(
            "aiss_threats_active",
            "Currently active (unresolved) threats",
            cls=Gauge,
        )
        threats_resolved = _safe(
            "aiss_threats_resolved_total",
            "Total threats resolved",
            cls=Counter,
        )
        scan_duration = _safe(
            "aiss_scan_duration_seconds",
            "Time taken by each detection module scan",
            labels=["module"],
            cls=Histogram,
            buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0],
        )
        llm_requests = _safe(
            "aiss_llm_requests_total",
            "Total LLM API requests made",
            labels=["provider"],
            cls=Counter,
        )
        llm_tokens = _safe(
            "aiss_llm_tokens_total",
            "Total LLM tokens consumed",
            labels=["provider", "direction"],
            cls=Counter,
        )
        anomaly_score_hist = _safe(
            "aiss_anomaly_score",
            "Distribution of online ML anomaly scores (0-1)",
            cls=Histogram,
            buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
        )
        blocked_ips = _safe(
            "aiss_blocked_ips_total",
            "Number of IPs currently blocked by the response engine",
            cls=Gauge,
        )

        _CREATED = True
        logger.info("✅ Prometheus custom metrics registered (aiss_threats_*, aiss_llm_*, ...)")
        return True

    except ImportError:
        logger.debug("prometheus_client not installed — custom metrics disabled")
        return False
    except Exception as e:
        logger.warning(f"Prometheus metrics init failed: {e}")
        return False


# ── Convenience helpers (no-op when metrics unavailable) ─────────────

def inc_threat(severity: str, threat_type: str) -> None:
    """Increment threat counter. Called from ThreatEngine.register_threat()."""
    try:
        if threats_total:
            threats_total.labels(
                severity=str(severity).lower(),
                type=str(threat_type).lower(),
            ).inc()
    except Exception:
        pass


def set_active_count(n: int) -> None:
    """Set the active threats gauge. Called from ThreatEngine."""
    try:
        if threats_active:
            threats_active.set(n)
    except Exception:
        pass


def inc_resolved() -> None:
    """Increment resolved counter."""
    try:
        if threats_resolved:
            threats_resolved.inc()
    except Exception:
        pass


def observe_scan(module: str, duration_secs: float) -> None:
    """Record a module scan duration. Use as: observe_scan('malware_scanner', elapsed)."""
    try:
        if scan_duration:
            scan_duration.labels(module=module).observe(duration_secs)
    except Exception:
        pass


def inc_llm_request(provider: str) -> None:
    try:
        if llm_requests:
            llm_requests.labels(provider=provider).inc()
    except Exception:
        pass


def inc_llm_tokens(provider: str, input_n: int, output_n: int) -> None:
    try:
        if llm_tokens:
            llm_tokens.labels(provider=provider, direction="input").inc(input_n)
            llm_tokens.labels(provider=provider, direction="output").inc(output_n)
    except Exception:
        pass


def observe_anomaly_score(score: float) -> None:
    try:
        if anomaly_score_hist:
            anomaly_score_hist.observe(min(1.0, max(0.0, score)))
    except Exception:
        pass


def set_blocked_ips(n: int) -> None:
    try:
        if blocked_ips:
            blocked_ips.set(n)
    except Exception:
        pass
