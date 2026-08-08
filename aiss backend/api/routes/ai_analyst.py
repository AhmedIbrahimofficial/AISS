"""AISS - AI Analyst API Routes
Supports both Anthropic Claude and OpenAI via unified AIAnalyst provider.
"""
import os
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import Response
from pydantic import BaseModel
from core.dependencies import get_engine_authenticated
from core.threat_engine import ThreatEngine

router = APIRouter()


class AnalysisRequest(BaseModel):
    threat_id:  str
    api_key:    str  = ""
    provider:   str  = "auto"   # "auto" | "claude" | "openai"
    async_mode: bool = False    # True → return Celery task ID immediately


class ReportRequest(BaseModel):
    api_key:  str = ""
    provider: str = "auto"
    format:   str = "json"      # "json" | "pdf"


def _resolve_key(request_key: str) -> str:
    """Pick the best available API key."""
    k = request_key or os.environ.get("ANTHROPIC_API_KEY", "") or os.environ.get("OPENAI_API_KEY", "")
    if not k:
        raise HTTPException(
            status_code=400,
            detail="No AI API key configured. Set ANTHROPIC_API_KEY or OPENAI_API_KEY in .env"
        )
    return k


@router.post("/analyze")
async def analyze_threat(
    request: AnalysisRequest,
    engine:  ThreatEngine = Depends(get_engine_authenticated),
):
    threat  = engine.active_threats.get(request.threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    api_key = _resolve_key(request.api_key)

    # ── Async Celery mode ─────────────────────────────────────────────
    if request.async_mode:
        try:
            from tasks import ai_analyze_task
            task = ai_analyze_task.delay(threat.to_dict(), api_key)
            return {"mode": "async", "task_id": task.id,
                    "status": "queued", "poll_url": f"/api/ai/task/{task.id}"}
        except Exception:
            pass  # Celery not running — fall through to sync

    # ── Sync mode ─────────────────────────────────────────────────────
    from modules.ai_analyst import AIAnalyst
    analyst  = AIAnalyst(api_key=api_key, provider=request.provider)
    analysis = await analyst.analyze_threat(threat)

    threat.ai_analysis        = analysis.get("threat_assessment", "")
    threat.recommended_action = analysis.get("recommended_response", "")

    return {
        "threat_id":   request.threat_id,
        "threat_type": str(threat.type),
        "provider":    analyst.provider,
        "analysis":    analysis,
    }


@router.get("/task/{task_id}")
async def get_task_status(task_id: str):
    """Poll Celery task status."""
    try:
        from modules.celery_app import celery_app
        result = celery_app.AsyncResult(task_id)
        resp = {"task_id": task_id, "status": result.status}
        if result.ready():
            resp["result"] = result.get(timeout=1)
        return resp
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Task queue unavailable: {e}")


@router.post("/report")
async def generate_report(
    request: ReportRequest,
    engine:  ThreatEngine = Depends(get_engine_authenticated),
):
    api_key = _resolve_key(request.api_key)
    threats = engine.get_all_threats()
    if not threats:
        return {"report": "No threats recorded yet."}

    from modules.ai_analyst import AIAnalyst
    analyst = AIAnalyst(api_key=api_key, provider=request.provider)

    if request.format == "pdf":
        pdf_bytes = await analyst.generate_pdf_report(threats)
        media = "application/pdf" if pdf_bytes[:4] == b"%PDF" else "text/html"
        return Response(
            content=pdf_bytes,
            media_type=media,
            headers={"Content-Disposition": "attachment; filename=aiss_report.pdf"},
        )

    report = await analyst.generate_report(threats)
    return {"report": report, "threat_count": len(threats), "provider": analyst.provider}
