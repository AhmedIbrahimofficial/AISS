"""AISS - AI Analyst API Routes"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from core.dependencies import get_engine_authenticated
from core.threat_engine import ThreatEngine

router = APIRouter()


class AnalysisRequest(BaseModel):
    threat_id: str
    api_key: str = ""


class ReportRequest(BaseModel):
    api_key: str = ""


@router.post("/analyze")
async def analyze_threat(
    request: AnalysisRequest,
    engine: ThreatEngine = Depends(get_engine_authenticated),
):
    threat = engine.active_threats.get(request.threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    import os
    api_key = request.api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise HTTPException(
            status_code=400,
            detail="Anthropic API key required. Pass api_key or set ANTHROPIC_API_KEY env var."
        )

    from modules.ai_analyst import AIAnalyst
    analyst = AIAnalyst(api_key=api_key)
    analysis = await analyst.analyze_threat(threat)

    threat.ai_analysis = analysis.get("threat_assessment", "")
    threat.recommended_action = analysis.get("recommended_response", "")

    from core import database
    await database.save_threat(threat.to_dict())

    return {"threat_id": request.threat_id, "threat_type": threat.type, "analysis": analysis}


@router.post("/report")
async def generate_report(
    request: ReportRequest,
    engine: ThreatEngine = Depends(get_engine_authenticated),
):
    import os
    api_key = request.api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise HTTPException(
            status_code=400,
            detail="Anthropic API key required. Pass api_key or set ANTHROPIC_API_KEY env var."
        )

    threats = engine.get_all_threats()
    if not threats:
        return {"report": "No threats recorded yet."}

    from modules.ai_analyst import AIAnalyst
    analyst = AIAnalyst(api_key=api_key)
    report = await analyst.generate_report(threats)

    return {"report": report, "threat_count": len(threats)}
