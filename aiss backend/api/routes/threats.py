"""AISS - Threats API Routes"""
from fastapi import APIRouter, HTTPException, Depends
from core.dependencies import get_engine, get_engine_authenticated
from core.threat_engine import ThreatEngine

router = APIRouter()


@router.get("/")
async def get_all_threats(engine: ThreatEngine = Depends(get_engine)):
    return {"threats": engine.get_all_threats()}


@router.get("/active")
async def get_active_threats(engine: ThreatEngine = Depends(get_engine)):
    return {"threats": engine.get_active_threats()}


@router.get("/stats")
async def get_threat_stats(engine: ThreatEngine = Depends(get_engine)):
    return engine.get_stats()


@router.post("/{threat_id}/resolve")
async def resolve_threat(
    threat_id: str,
    note: str = "Manually resolved",
    engine: ThreatEngine = Depends(get_engine),
):
    success = await engine.resolve_threat(threat_id, note)
    if not success:
        raise HTTPException(status_code=404, detail="Threat not found")
    return {"status": "resolved", "threat_id": threat_id, "message": "✅ Threat successfully neutralized!"}


@router.delete("/clear")
async def clear_all_threats(engine: ThreatEngine = Depends(get_engine_authenticated)):
    engine.active_threats.clear()
    from core.database import AsyncSessionLocal
    from sqlalchemy import text
    async with AsyncSessionLocal() as db:
        await db.execute(text("DELETE FROM threats"))
        await db.commit()
    return {"status": "cleared"}


# ── Report Export Endpoints ───────────────────────────────────────────

from fastapi.responses import Response


@router.get("/export/excel")
async def export_threats_excel(engine: ThreatEngine = Depends(get_engine)):
    """
    Export all threats to an Excel workbook (.xlsx).
    Includes severity-colour-coded rows, summary sheet, and pie chart.
    """
    from modules.report_exporter import report_exporter
    threats = engine.get_all_threats()
    xlsx_bytes = await report_exporter.export_excel(threats)
    if not xlsx_bytes:
        raise HTTPException(status_code=503,
            detail="Excel export unavailable (openpyxl/xlsxwriter not installed)")
    return Response(
        content=xlsx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=aiss_threats.xlsx"},
    )


@router.get("/export/chart.png")
async def export_threats_chart(engine: ThreatEngine = Depends(get_engine)):
    """Export severity distribution + hourly timeline chart as PNG."""
    from modules.report_exporter import report_exporter
    threats = engine.get_all_threats()
    png_bytes = await report_exporter.export_chart_png(threats)
    if not png_bytes:
        raise HTTPException(status_code=503,
            detail="Chart export unavailable (matplotlib not installed)")
    return Response(
        content=png_bytes,
        media_type="image/png",
        headers={"Content-Disposition": "attachment; filename=aiss_chart.png"},
    )


@router.get("/export/dashboard.html")
async def export_threats_plotly(engine: ThreatEngine = Depends(get_engine)):
    """Export interactive Plotly threat dashboard as standalone HTML."""
    from modules.report_exporter import report_exporter
    threats = engine.get_all_threats()
    html = await report_exporter.export_plotly_html(threats)
    if not html:
        raise HTTPException(status_code=503,
            detail="Interactive dashboard unavailable (plotly not installed)")
    return Response(content=html, media_type="text/html")


@router.get("/export/status")
async def export_status():
    """Return which export formats are available."""
    from modules.report_exporter import report_exporter
    return report_exporter.is_available()
