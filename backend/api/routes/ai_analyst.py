"""AISS — AI Analyst API Routes (OpenRouter)

All AI analysis goes through OpenRouter via the shared llm_router.
Set OPENROUTER_API_KEY in .env — no other AI key required.
"""
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import Response
from pydantic import BaseModel

from core.dependencies import get_engine_authenticated
from core.threat_engine import ThreatEngine
from modules.llm_router import llm_router

router = APIRouter()


class AnalysisRequest(BaseModel):
    threat_id:  str
    # Kept for backward compat — ignored
    api_key:    str  = ""
    provider:   str  = "auto"
    async_mode: bool = False


class ReportRequest(BaseModel):
    # Kept for backward compat — ignored
    api_key:  str = ""
    provider: str = "auto"
    format:   str = "json"   # "json" | "pdf"


def _check_llm_available() -> None:
    if not llm_router.is_available():
        raise HTTPException(
            status_code=503,
            detail=(
                "AI service is temporarily unavailable. "
                "Contact your AISS administrator."
            ),
        )


@router.post("/analyze")
async def analyze_threat(
    request: AnalysisRequest,
    engine:  ThreatEngine = Depends(get_engine_authenticated),
):
    _check_llm_available()

    threat = engine.active_threats.get(request.threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found in active threat store")

    # Async Celery mode — try first, fall through to sync if Redis not running
    if request.async_mode:
        try:
            from tasks import ai_analyze_task
            task = ai_analyze_task.delay(threat.to_dict(), "")
            return {
                "mode": "async",
                "task_id": task.id,
                "status": "queued",
                "poll_url": f"/api/ai/task/{task.id}",
            }
        except Exception:
            pass  # Celery/Redis not running — fall through to sync

    from modules.ai_analyst import AIAnalyst
    analyst  = AIAnalyst()
    analysis = await analyst.analyze_threat(threat)

    threat.ai_analysis        = analysis.get("threat_assessment", "")
    threat.recommended_action = analysis.get("recommended_response", "")

    return {
        "threat_id":   request.threat_id,
        "threat_type": str(threat.type),
        "provider":    "openrouter",
        "analysis":    analysis,
    }


@router.get("/task/{task_id}")
async def get_task_status(task_id: str):
    """Poll Celery task status."""
    try:
        from modules.celery_app import celery_app
        result = celery_app.AsyncResult(task_id)
        resp: dict = {"task_id": task_id, "status": result.status}
        if result.ready():
            resp["result"] = result.get(timeout=1)
        return resp
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Task queue unavailable: {exc}")


@router.post("/report")
async def generate_report(
    request: ReportRequest,
    engine:  ThreatEngine = Depends(get_engine_authenticated),
):
    _check_llm_available()

    threats = engine.get_all_threats()
    if not threats:
        return {"report": "No threats recorded yet.", "threat_count": 0}

    from modules.ai_analyst import AIAnalyst
    analyst = AIAnalyst()

    if request.format == "pdf":
        pdf_bytes = await analyst.generate_pdf_report(threats)
        media = "application/pdf" if pdf_bytes[:4] == b"%PDF" else "text/html"
        return Response(
            content=pdf_bytes,
            media_type=media,
            headers={"Content-Disposition": "attachment; filename=aiss_report.pdf"},
        )

    report = await analyst.generate_report(threats)
    return {
        "report":       report,
        "threat_count": len(threats),
        "provider":     "openrouter",
    }
