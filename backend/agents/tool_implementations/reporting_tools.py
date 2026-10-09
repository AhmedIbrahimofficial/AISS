"""
REPORTING tool handlers — delegate to ReportGenerator.
"""
from __future__ import annotations
from datetime import datetime, timedelta
from typing import Any

_NA = "No real data available for {tool}"


async def generate_security_report(user_id: str = "", **kwargs: Any) -> dict:
    """Triggers report generation and returns report metadata."""
    try:
        from core.database import AsyncSessionLocal
        from agents.report_generator import ReportGenerator
        period_end = datetime.utcnow()
        period_start = period_end - timedelta(days=7)
        generator = ReportGenerator()
        async with AsyncSessionLocal() as db:
            # Minimal user object for report scoping
            class _FakeUser:
                id = user_id or "system"
            report = await generator.generate(_FakeUser(), period_start, period_end, db)
            return {"status": "ok", "report_id": report.id, "report_status": report.status}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="generate_security_report")}


async def generate_pdf_report(report_id: str, **_: Any) -> dict:
    """Returns the file path of an existing PDF report."""
    try:
        from core.database import AsyncSessionLocal
        from agents.models import Report
        from sqlalchemy import select
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Report).where(Report.id == report_id))
            report = result.scalar_one_or_none()
            if not report:
                return {"status": "error", "message": f"Report {report_id} not found"}
            return {"status": "ok", "report_id": report.id,
                    "file_path": report.file_path, "status": report.status}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="generate_pdf_report")}


async def export_audit_log(**kwargs: Any) -> dict:
    """Exports audit log entries as structured data."""
    from agents.tool_implementations.security_tools import query_audit_logs
    return await query_audit_logs(**kwargs)


async def export_findings(**kwargs: Any) -> dict:
    """Exports security findings from DB."""
    try:
        from core.database import AsyncSessionLocal
        from agents.models import SecurityFinding
        from sqlalchemy import select, desc
        limit = kwargs.get("limit", 100)
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(SecurityFinding).order_by(desc(SecurityFinding.created_at)).limit(limit)
            )
            findings = []
            for f in result.scalars().all():
                findings.append({
                    "id": f.id, "finding_type": f.finding_type, "severity": f.severity,
                    "title": f.title, "affected_resource": f.affected_resource,
                    "mitre_technique": f.mitre_technique,
                    "created_at": f.created_at.isoformat(),
                })
        return {"status": "ok", "count": len(findings), "findings": findings}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="export_findings")}
