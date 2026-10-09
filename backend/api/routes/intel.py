"""AISS - Threat Intelligence API Routes
Exposes VT, Shodan, GeoIP, STIX/TAXII, and YARA endpoints.
"""
from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel
from core.dependencies import get_engine, get_engine_authenticated
from core.threat_engine import ThreatEngine

router = APIRouter()


# ── IP Enrichment ─────────────────────────────────────────────────────

@router.get("/enrich/ip/{ip}")
async def enrich_ip(ip: str):
    """Enrich an IP address with VT + Shodan + GeoIP data."""
    from modules.threat_intel import enrich_ip as _enrich
    from modules.geo_lookup import lookup_ip
    intel = await _enrich(ip)
    geo   = lookup_ip(ip)
    return {"ip": ip, "intel": intel, "geo": geo}


@router.get("/enrich/hash/{file_hash}")
async def check_hash(file_hash: str):
    """Check a file hash against VirusTotal."""
    from modules.threat_intel import vt_check_hash
    return await vt_check_hash(file_hash)


# ── Cache stats ───────────────────────────────────────────────────────

@router.get("/intel/stats")
async def intel_stats():
    """Return threat intel cache statistics."""
    from modules.threat_intel import get_cache_stats
    return get_cache_stats()


# ── GeoIP ─────────────────────────────────────────────────────────────

@router.get("/geo/{ip}")
async def geo_lookup(ip: str):
    """Look up geographic location of an IP."""
    from modules.geo_lookup import lookup_ip, is_available
    if not is_available():
        raise HTTPException(
            status_code=503,
            detail="GeoIP2 database not loaded. Download GeoLite2-City.mmdb and set GEOIP_DB_PATH."
        )
    geo = lookup_ip(ip)
    if not geo:
        return {"ip": ip, "geo": None, "message": "No geo data (private or unknown IP)"}
    return {"ip": ip, "geo": geo}


# ── STIX / TAXII ──────────────────────────────────────────────────────

@router.post("/taxii/ingest")
async def taxii_ingest(engine: ThreatEngine = Depends(get_engine_authenticated)):
    """Manually trigger TAXII feed ingestion."""
    from modules.threat_intel_feeds import ingest_from_taxii, get_cache_stats
    count = await ingest_from_taxii()
    return {"ingested": count, **get_cache_stats()}


@router.get("/taxii/stats")
async def taxii_stats():
    """Return TAXII cache statistics."""
    from modules.threat_intel_feeds import get_cache_stats
    return get_cache_stats()


@router.get("/taxii/indicators")
async def taxii_indicators(limit: int = Query(100, le=1000)):
    """Return cached STIX indicators."""
    from modules.threat_intel_feeds import get_all_indicators
    indicators = get_all_indicators()
    return {"count": len(indicators), "indicators": indicators[:limit]}


# ── YARA ──────────────────────────────────────────────────────────────

@router.post("/yara/reload")
async def reload_yara(engine: ThreatEngine = Depends(get_engine_authenticated)):
    """Reload YARA rules from disk."""
    from modules.yara_scanner import reload_rules
    ok = reload_rules()
    return {"reloaded": ok}


@router.post("/sigma/reload")
async def reload_sigma(engine: ThreatEngine = Depends(get_engine_authenticated)):
    """Reload Sigma rules from disk."""
    from modules.sigma_loader import reload_rules
    count = reload_rules()
    return {"rules_loaded": count}


# ── Celery task status ────────────────────────────────────────────────

@router.get("/task/{task_id}")
async def get_task_status(task_id: str):
    """Get Celery background task status and result."""
    try:
        from modules.celery_app import celery_app
        result = celery_app.AsyncResult(task_id)
        resp = {"task_id": task_id, "status": result.status}
        if result.ready():
            resp["result"] = result.get(timeout=1)
        return resp
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Task queue unavailable: {e}")


# ── Evidence encryption status ────────────────────────────────────────

@router.get("/evidence/crypto")
async def evidence_crypto_status():
    """Return evidence encryption status."""
    from modules.evidence_crypto import get_key_status
    return get_key_status()


# ── Semantic Threat Search ────────────────────────────────────────────

class SemanticSearchRequest(BaseModel):
    query: str
    n: int = 5
    severity_filter: str | None = None


@router.post("/semantic/search")
async def semantic_search(req: SemanticSearchRequest):
    """
    Semantic similarity search over stored threats.
    Example: query='ransomware C2 traffic from external IP'
    Returns threats ranked by semantic similarity score.
    """
    from modules.semantic_threat_store import semantic_store
    if not semantic_store.is_available():
        raise HTTPException(status_code=503,
            detail="Semantic store unavailable (chromadb or sentence-transformers not installed)")
    results = await semantic_store.search(req.query, n=req.n,
                                          severity_filter=req.severity_filter)
    return {"query": req.query, "results": results, "count": len(results)}


@router.get("/semantic/count")
async def semantic_count():
    """Return total threats indexed in the vector store."""
    from modules.semantic_threat_store import semantic_store
    return {"count": await semantic_store.count(), "available": semantic_store.is_available()}


# ── IOC Extraction ────────────────────────────────────────────────────

class IOCRequest(BaseModel):
    text: str


@router.post("/ioc/extract")
async def extract_iocs(req: IOCRequest):
    """
    Extract IOCs (IPs, domains, hashes, CVEs, MITRE techniques)
    from arbitrary text — alert descriptions, log snippets, emails.
    """
    from modules.ioc_extractor import ioc_extractor
    result = ioc_extractor.extract(req.text)
    return {"iocs": result}


# ── Phishing URL Analysis ─────────────────────────────────────────────

class PhishingRequest(BaseModel):
    url: str


@router.post("/phishing/analyze")
async def analyze_phishing(req: PhishingRequest):
    """
    Multi-layer phishing analysis: dataset thresholds + heuristics +
    optional Playwright screenshot.
    """
    from modules.phishing_analyzer import phishing_analyzer
    return await phishing_analyzer.analyze_url(req.url)


# ── LLM Threat Analysis (via LLM Router) ─────────────────────────────

class LLMAnalysisRequest(BaseModel):
    threat_id: str | None = None
    text: str


@router.post("/llm/analyze")
async def llm_analyze(req: LLMAnalysisRequest,
                      engine: ThreatEngine = Depends(get_engine_authenticated)):
    """
    AI threat analysis via OpenRouter (OPENROUTER_API_KEY required).
    """
    from modules.llm_router import llm_router
    if not llm_router.is_available():
        raise HTTPException(
            status_code=503,
            detail=(
                "AI service is temporarily unavailable. "
                "Contact your AISS administrator."
            ),
        )

    system = (
        "You are AISS's AI Security Analyst. Respond ONLY with valid JSON with keys: "
        "threat_assessment, risk_level, attack_vector, immediate_actions, "
        "mitre_tactics, indicators_of_compromise, recommended_response."
    )
    result = await llm_router.complete_json(req.text, system=system)
    return {"analysis": result, "provider": "openrouter"}


# ── Online Anomaly Scoring ────────────────────────────────────────────

class AnomalyRequest(BaseModel):
    event: dict


@router.post("/anomaly/score")
async def anomaly_score(req: AnomalyRequest):
    """
    Score a network event for anomalousness using the online ML model.
    Provide keys like: duration, src_bytes, dst_bytes, src_port, dst_port.
    """
    from modules.online_anomaly_detector import online_detector
    score, is_anomaly = online_detector.learn_and_score(req.event)
    return {
        "score":      round(score, 4),
        "is_anomaly": is_anomaly,
        "threshold":  online_detector.ANOMALY_THRESHOLD if hasattr(online_detector, 'ANOMALY_THRESHOLD') else 0.7,
        "stats":      online_detector.get_stats(),
    }
