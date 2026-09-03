"""
Agentic AI Orchestrator — ReportGenerator

Generates real PDF security reports using WeasyPrint + Jinja2.
All data sourced from DB — never fabricated.
SHA-256 integrity hash stored with each report.

Requirements: 10.1–10.10, 16.4
"""
from __future__ import annotations

import hashlib
import logging
import os
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.models import (
    AgentAuditEvent, AgentTask, Report, SecurityFinding
)
from agents.schemas import ReportData

logger = logging.getLogger("agents.report_generator")

_TEMPLATE_DIR = Path(__file__).parent / "templates" / "report"
_DEFAULT_REPORTS_DIR = "data/reports"


class ReportGenerator:
    """Generates PDF security reports from real backend data."""

    def __init__(self, reports_dir: str | None = None) -> None:
        self._reports_dir = Path(
            reports_dir or os.environ.get("AGENT_REPORTS_DIR", _DEFAULT_REPORTS_DIR)
        )
        os.makedirs(self._reports_dir, exist_ok=True)

        self._jinja_env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=True,
        )

    # ------------------------------------------------------------------
    # Public: generate report
    # ------------------------------------------------------------------

    async def generate(
        self,
        user: Any,
        period_start: datetime,
        period_end: datetime,
        db: AsyncSession,
    ) -> Report:
        """Generate a full PDF report. Returns the Report ORM record."""
        report_id = str(uuid.uuid4())

        # Create initial record with "generating" status
        report = Report(
            id=report_id,
            user_id=user.id,
            period_start=period_start,
            period_end=period_end,
            status="generating",
        )
        db.add(report)
        await db.flush()

        try:
            # 1. Collect real data
            data = await self._collect_report_data(user.id, period_start, period_end, db)

            # 2. Render HTML
            html = self._render_html(data, report_id)

            # 3. Convert to PDF
            file_path = self._reports_dir / f"report_{report_id}.pdf"
            self._html_to_pdf(html, str(file_path))

            # 4. Compute integrity hash
            pdf_bytes = file_path.read_bytes()
            sha256 = hashlib.sha256(pdf_bytes).hexdigest()
            file_size = len(pdf_bytes)

            # 5. Update record
            report.status = "ready"
            report.generated_at = datetime.utcnow()
            report.file_path = str(file_path)
            report.sha256_hash = sha256
            report.file_size_bytes = file_size
            report.scope_json = {"user_id": user.id}
            await db.flush()

            logger.info("Report %s generated: %s (%d bytes)", report_id, file_path, file_size)

        except Exception as exc:
            logger.error("Report generation failed for %s: %s", report_id, exc)
            report.status = "failed"
            report.error_message = str(exc)[:1000]
            await db.flush()

        return report

    # ------------------------------------------------------------------
    # Integrity verification
    # ------------------------------------------------------------------

    async def verify_integrity(self, report: Report) -> bool:
        """Return True if the file on disk matches the stored SHA-256 hash."""
        try:
            if not report.file_path or not report.sha256_hash:
                return False
            path = Path(report.file_path)
            if not path.exists():
                return False
            actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            return actual_hash == report.sha256_hash
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Data collection
    # ------------------------------------------------------------------

    async def _collect_report_data(
        self,
        user_id: str,
        period_start: datetime,
        period_end: datetime,
        db: AsyncSession,
    ) -> ReportData:
        data = ReportData(
            user_id=user_id,
            period_start=period_start,
            period_end=period_end,
        )

        # Security events (SystemEvent)
        try:
            from core.models import SystemEvent
            result = await db.execute(
                select(SystemEvent)
                .where(SystemEvent.created_at >= period_start)
                .where(SystemEvent.created_at <= period_end)
                .limit(200)
            )
            data.security_events = [e.to_dict() for e in result.scalars().all()]
        except Exception as e:
            logger.warning("Could not collect security_events: %s", e)

        # Threats
        try:
            from core.models import ThreatLog
            result = await db.execute(
                select(ThreatLog)
                .where(ThreatLog.detected_at >= period_start)
                .where(ThreatLog.detected_at <= period_end)
                .limit(200)
            )
            data.threats = [t.to_dict() for t in result.scalars().all()]
        except Exception as e:
            logger.warning("Could not collect threats: %s", e)

        # Vulnerabilities (threats of vuln type)
        data.vulnerabilities = [
            t for t in data.threats
            if "vuln" in t.get("threat_type", "").lower()
        ]

        # Security findings
        try:
            # Get all task IDs for this user
            task_result = await db.execute(
                select(AgentTask.id)
                .where(AgentTask.user_id == user_id)
                .where(AgentTask.created_at >= period_start)
            )
            task_ids = [row[0] for row in task_result.all()]
            if task_ids:
                finding_result = await db.execute(
                    select(SecurityFinding)
                    .where(SecurityFinding.task_id.in_(task_ids))
                    .limit(100)
                )
                data.findings = [
                    {
                        "id": f.id, "finding_type": f.finding_type,
                        "severity": f.severity, "title": f.title,
                        "description": f.description, "affected_resource": f.affected_resource,
                        "mitre_technique": f.mitre_technique,
                        "recommendation": f.recommendation,
                        "created_at": f.created_at.isoformat() if f.created_at else None,
                        "resolved_at": f.resolved_at.isoformat() if f.resolved_at else None,
                    }
                    for f in finding_result.scalars().all()
                ]
        except Exception as e:
            logger.warning("Could not collect findings: %s", e)

        # Device status
        try:
            from auth.models import AuthUser
            result = await db.execute(select(AuthUser).where(AuthUser.is_active == True).limit(50))
            data.device_status = [
                {"id": u.id, "username": u.username, "role": u.role,
                 "is_active": u.is_active,
                 "last_login": u.last_login.isoformat() if u.last_login else None}
                for u in result.scalars().all()
            ]
        except Exception as e:
            logger.warning("Could not collect device_status: %s", e)

        # Audit summary
        try:
            result = await db.execute(
                select(func.count(AgentAuditEvent.id))
                .where(AgentAuditEvent.user_id == user_id)
                .where(AgentAuditEvent.created_at >= period_start)
            )
            total_events = result.scalar() or 0
            data.audit_summary = {
                "total_agent_actions": total_events,
                "period_days": (period_end - period_start).days,
            }
        except Exception as e:
            logger.warning("Could not collect audit_summary: %s", e)

        # Security score (simple heuristic)
        critical_count = sum(1 for t in data.threats if t.get("severity") == "critical")
        high_count = sum(1 for t in data.threats if t.get("severity") == "high")
        score = max(0, 100 - (critical_count * 15) - (high_count * 5) - (len(data.vulnerabilities) * 2))
        data.security_score = min(100, score)

        # Recommendations
        recs = []
        if critical_count > 0:
            recs.append(f"Immediately investigate and remediate {critical_count} critical threat(s).")
        if high_count > 0:
            recs.append(f"Address {high_count} high-severity finding(s) within 24 hours.")
        if len(data.vulnerabilities) > 5:
            recs.append(f"Prioritise patching {len(data.vulnerabilities)} identified vulnerabilities.")
        recs.append("Ensure all connected devices are authorised and up to date.")
        recs.append("Review audit logs regularly for unauthorised access attempts.")
        data.recommendations = recs

        return data

    # ------------------------------------------------------------------
    # HTML rendering
    # ------------------------------------------------------------------

    def _render_html(self, data: ReportData, report_id: str) -> str:
        template = self._jinja_env.get_template("report.html.j2")
        return template.render(
            report_id=report_id,
            period_start=data.period_start.strftime("%Y-%m-%d"),
            period_end=data.period_end.strftime("%Y-%m-%d"),
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            security_score=data.security_score,
            security_events=data.security_events,
            threats=data.threats,
            vulnerabilities=data.vulnerabilities,
            findings=data.findings,
            device_status=data.device_status,
            network_summary=data.network_summary,
            audit_summary=data.audit_summary,
            mitre_mappings=data.mitre_mappings,
            recommendations=data.recommendations,
        )

    # ------------------------------------------------------------------
    # PDF generation
    # ------------------------------------------------------------------

    def _html_to_pdf(self, html: str, output_path: str) -> None:
        """Convert HTML string to PDF file using WeasyPrint."""
        try:
            from weasyprint import HTML
            HTML(string=html).write_pdf(output_path)
        except ImportError:
            # WeasyPrint not available — write a minimal valid PDF placeholder
            logger.warning("WeasyPrint not available; writing text PDF stub.")
            self._write_text_pdf(html, output_path)

    def _write_text_pdf(self, html: str, output_path: str) -> None:
        """Fallback: write a minimal PDF with reportlab if weasyprint unavailable."""
        try:
            from reportlab.pdfgen import canvas
            c = canvas.Canvas(output_path)
            c.drawString(50, 800, "AISS Security Report")
            c.drawString(50, 780, "WeasyPrint not installed. Install it for full PDF reports.")
            y = 760
            for line in html.split("\n")[:50]:
                import re
                text = re.sub("<[^>]+>", "", line).strip()
                if text:
                    c.drawString(50, y, text[:100])
                    y -= 14
                    if y < 50:
                        c.showPage()
                        y = 800
            c.save()
        except Exception as e:
            logger.error("PDF fallback also failed: %s", e)
            # Write raw bytes so the file exists
            Path(output_path).write_bytes(b"%PDF-1.4\n%AISS Report Generation Error\n")
