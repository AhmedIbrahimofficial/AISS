"""AISS - Celery Tasks
Background tasks for CPU-intensive and IO-bound operations that should not
block FastAPI request threads.

Start worker with:
  celery -A tasks worker --loglevel=info -Q scan,ai,intel,celery

Tasks:
  scan_file_task       — YARA scan a single file
  ai_analyze_task      — Claude threat analysis
  enrich_threat_task   — VT + Shodan IP enrichment
"""

import asyncio
import json
import os
from celery import Task
from modules.celery_app import celery_app
from utils.logger import setup_logger

logger = setup_logger("celery_tasks")


def _run_async(coro):
    """Run an async coroutine from a synchronous Celery task."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


# ── 1. YARA file scan ──────────────────────────────────────────────────

@celery_app.task(
    bind=True,
    name="aiss.tasks.scan_file_task",
    queue="scan",
    max_retries=2,
    default_retry_delay=5,
)
def scan_file_task(self, filepath: str) -> dict:
    """
    Perform a full YARA scan on a file.
    Returns list of match dicts.
    """
    try:
        from modules.yara_scanner import scan_file
        matches = scan_file(filepath)
        logger.info(f"YARA scan completed: {filepath} — {len(matches)} match(es)")
        return {
            "status":    "completed",
            "filepath":  filepath,
            "matches":   matches,
            "match_count": len(matches),
        }
    except Exception as exc:
        logger.error(f"YARA scan failed for {filepath}: {exc}")
        raise self.retry(exc=exc)


# ── 2. AI threat analysis ──────────────────────────────────────────────

@celery_app.task(
    bind=True,
    name="aiss.tasks.ai_analyze_task",
    queue="ai",
    max_retries=3,
    default_retry_delay=10,
    soft_time_limit=120,
)
def ai_analyze_task(self, threat_dict: dict, api_key: str = "") -> dict:
    """
    Run Claude AI analysis on a threat dict.
    Returns analysis result dict.
    """
    try:
        from modules.ai_analyst import AIAnalyst
        from models.threat import Threat, ThreatType, ThreatSeverity

        # Reconstruct Threat object from dict
        threat = Threat(
            id          = threat_dict.get("id", ""),
            type        = ThreatType(threat_dict.get("type", "Unknown Threat")),
            description = threat_dict.get("description", ""),
            severity    = ThreatSeverity(threat_dict.get("severity", "medium")),
            source      = threat_dict.get("source", ""),
            module      = threat_dict.get("module", ""),
            metadata    = threat_dict.get("metadata", {}),
        )

        # api_key param kept for backward compat but ignored — OpenRouter is used
        analyst = AIAnalyst()
        result = _run_async(analyst.analyze_threat(threat))
        logger.info(f"AI analysis completed for threat {threat.id[:8]}")
        return {"status": "completed", "threat_id": threat.id, "analysis": result}

    except Exception as exc:
        logger.error(f"AI analysis task failed: {exc}")
        raise self.retry(exc=exc)


# ── 3. Threat IP enrichment ────────────────────────────────────────────

@celery_app.task(
    bind=True,
    name="aiss.tasks.enrich_threat_task",
    queue="intel",
    max_retries=2,
    default_retry_delay=30,
)
def enrich_threat_task(self, ip: str) -> dict:
    """
    Enrich an IP with VirusTotal + Shodan + GeoIP2 data.
    Returns combined enrichment dict.
    """
    try:
        from modules.threat_intel import enrich_ip
        from modules.geo_lookup import lookup_ip

        intel = _run_async(enrich_ip(ip))
        geo   = lookup_ip(ip)

        result = {
            "status": "completed",
            "ip":     ip,
            "intel":  intel,
            "geo":    geo,
        }
        logger.info(f"Enrichment completed for {ip}")
        return result

    except Exception as exc:
        logger.error(f"Enrichment task failed for {ip}: {exc}")
        raise self.retry(exc=exc)


# ── 4. Network topology scan ──────────────────────────────────────────

@celery_app.task(
    bind=True,
    name="aiss.tasks.topology_scan_task",
    queue="scan",
    max_retries=1,
    default_retry_delay=60,
    soft_time_limit=300,
)
def topology_scan_task(self) -> dict:
    """
    Periodic network topology scan — discovers hosts on all registered segments.
    Scheduled automatically via APScheduler every 30 minutes.
    """
    try:
        from modules.network_topology import topology_manager
        results = _run_async(topology_manager.scan_all_segments())
        total   = sum(v.get("hosts_up", 0) for v in results.values()
                      if isinstance(v, dict))
        logger.info(f"Topology scan completed — {total} host(s) found")
        return {"status": "completed", "results": results, "hosts_up": total}
    except Exception as exc:
        logger.error(f"Topology scan failed: {exc}")
        raise self.retry(exc=exc)


# ── 5. Agent health check ─────────────────────────────────────────────

@celery_app.task(
    bind=True,
    name="aiss.tasks.agent_health_task",
    queue="intel",
    max_retries=0,
)
def agent_health_task(self) -> dict:
    """
    Check health of all connected remote agents.
    Marks agents as idle if no heartbeat in 60s.
    """
    try:
        import time
        from modules.remote_agent import _agent_registry
        now = time.time()
        stale = []
        for aid, agent in _agent_registry.items():
            try:
                from datetime import datetime
                last = datetime.fromisoformat(agent.last_seen.replace("Z", "+00:00"))
                age  = now - last.timestamp()
                if age > 60 and agent.status == "connected":
                    agent.status = "idle"
                    stale.append(aid[:8])
            except Exception:
                pass
        logger.debug(f"Agent health check: {len(stale)} marked idle")
        return {"status": "completed", "stale_agents": stale}
    except Exception as exc:
        logger.warning(f"Agent health check failed: {exc}")
        return {"status": "error", "error": str(exc)}


# ── 6. Document analysis (background) ────────────────────────────────

@celery_app.task(
    bind=True,
    name="aiss.tasks.analyze_document_task",
    queue="scan",
    max_retries=1,
    default_retry_delay=10,
    soft_time_limit=120,
)
def analyze_document_task(self, filepath: str) -> dict:
    """
    Deep document analysis in background (PDF/Office/PE/images).
    Used when file is too large for synchronous request handling.
    """
    try:
        from modules.document_analyzer import document_analyzer
        result = _run_async(document_analyzer.analyze(filepath))
        logger.info(f"Document analysis done: {filepath} — {len(result.get('threats', []))} threat(s)")
        return {"status": "completed", "filepath": filepath, **result}
    except Exception as exc:
        logger.error(f"Document analysis failed for {filepath}: {exc}")
        raise self.retry(exc=exc)


# ── 7. LLM batch analysis ─────────────────────────────────────────────

@celery_app.task(
    bind=True,
    name="aiss.tasks.llm_batch_task",
    queue="ai",
    max_retries=2,
    default_retry_delay=15,
    soft_time_limit=300,
)
def llm_batch_task(self, prompts: list, system: str = "") -> dict:
    """
    Process a batch of LLM prompts using the LLM router.
    Returns list of responses.
    """
    try:
        from modules.llm_router import llm_router
        results = []
        for prompt in prompts:
            resp = _run_async(llm_router.complete(
                prompt,
                system=system or "You are an AI security analyst.",
                max_tokens=800,
            ))
            results.append(resp)
        logger.info(f"LLM batch completed: {len(results)} prompts")
        return {"status": "completed", "results": results, "count": len(results)}
    except Exception as exc:
        logger.error(f"LLM batch task failed: {exc}")
        raise self.retry(exc=exc)
