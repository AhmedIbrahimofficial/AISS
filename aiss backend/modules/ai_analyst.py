"""AISS — AI Analyst Module (OpenRouter)

All LLM calls go through OpenRouter via the shared llm_router singleton.
Set OPENROUTER_API_KEY in .env — no other AI keys required.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from models.threat import Threat
from modules.llm_router import llm_router
from utils.logger import setup_logger

logger = setup_logger("ai_analyst")

SYSTEM_PROMPT = """You are AISS's AI Security Analyst — an elite cybersecurity expert.
When given a threat report, respond ONLY with a valid JSON object (no markdown, no extra text):
{
  "threat_assessment": "...",
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "attack_vector": "...",
  "potential_impact": "...",
  "immediate_actions": ["..."],
  "recommended_response": "...",
  "mitre_tactics": ["..."],
  "indicators_of_compromise": ["..."],
  "resolution_message": "..."
}"""


def _parse_json(text: str) -> dict:
    """Parse JSON from LLM output, stripping markdown fences if present."""
    text = re.sub(r"```(?:json)?", "", text).strip().strip("`").strip()
    try:
        return json.loads(text)
    except Exception:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except Exception:
                pass
    return {"threat_assessment": text}


class AIAnalyst:
    """
    Threat analysis via OpenRouter (all models via llm_router).
    The `api_key` and `provider` params are accepted for backward
    compatibility but ignored — OpenRouter is always used.
    """

    def __init__(self, api_key: str = "", provider: str = "auto") -> None:
        # Kept for backward compatibility with existing callers
        self._provider = "openrouter"

    @property
    def provider(self) -> str:
        return self._provider

    async def _complete(
        self,
        user_prompt: str,
        system: str = SYSTEM_PROMPT,
        max_tokens: int = 1000,
    ) -> str:
        return await llm_router.complete(
            user_prompt, system=system, max_tokens=max_tokens
        )

    async def analyze_threat(self, threat: Threat) -> dict:
        prompt = (
            f"Analyze this cybersecurity threat detected by AISS:\n"
            f"Type: {threat.type} | Severity: {threat.severity} | Source: {threat.source}\n"
            f"Module: {threat.module} | Detected: {threat.detected_at}\n"
            f"Description: {threat.description}\n"
            f"Metadata: {json.dumps(threat.metadata or {}, indent=2)}"
        )
        try:
            text   = await self._complete(prompt, max_tokens=1200)
            result = _parse_json(text)
            logger.info("Threat analysis complete: %s", threat.id[:8])
            return result
        except Exception as exc:
            logger.error("Threat analysis failed %s: %s", threat.id[:8], exc)
            return {
                "threat_assessment": f"Automated detection: {threat.type} from {threat.source}",
                "risk_level":        str(threat.severity).upper(),
                "recommended_response": "Isolate source, review logs, apply patches.",
                "resolution_message": f"✅ {threat.type} flagged for review",
            }

    async def analyze_threats_batch(
        self,
        threats: list[Any],
        *,
        delay_between: float = 1.5,
    ) -> list[dict]:
        import asyncio
        results = []
        for i, t in enumerate(threats):
            if i > 0:
                await asyncio.sleep(delay_between)
            results.append(await self.analyze_threat(t))
        return results

    async def generate_report(self, threats: list[Any]) -> str:
        threat_list = [
            t.to_dict() if hasattr(t, "to_dict") else dict(t)
            for t in threats[:40]
        ]
        prompt = (
            f"Write a professional executive security incident report covering "
            f"{len(threats)} detected threats.\n"
            f"Threat data:\n{json.dumps(threat_list, indent=2)}\n\n"
            f"Include: Executive summary, timeline, key findings, "
            f"impact assessment, actions taken, and security recommendations."
        )
        try:
            return await self._complete(
                prompt,
                system=(
                    "You are a professional cybersecurity report writer. "
                    "Be concise, accurate, and use clear section headings. "
                    "Do NOT fabricate data beyond what is provided."
                ),
                max_tokens=2000,
            )
        except Exception as exc:
            logger.error("Report generation failed: %s", exc)
            return f"Report generation failed: {exc}"

    async def generate_pdf_report(self, threats: list[Any]) -> bytes:
        """Generate a PDF report. Falls back from weasyprint → reportlab → HTML bytes."""
        from datetime import datetime
        report_text = await self.generate_report(threats)
        now_str     = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        threat_dicts = [
            t.to_dict() if hasattr(t, "to_dict") else dict(t)
            for t in threats
        ]
        critical = sum(1 for t in threat_dicts if str(t.get("severity", "")).lower() == "critical")
        high     = sum(1 for t in threat_dicts if str(t.get("severity", "")).lower() == "high")

        try:
            import weasyprint
            html = _build_report_html(report_text, threat_dicts, now_str, critical, high)
            pdf  = weasyprint.HTML(string=html).write_pdf()
            logger.info("PDF via weasyprint: %d bytes", len(pdf))
            return pdf
        except Exception as e:
            logger.warning("weasyprint unavailable (%s) — trying reportlab", type(e).__name__)

        return _build_report_reportlab(report_text, threat_dicts, now_str, critical, high)


# ── Report HTML builder ───────────────────────────────────────────────────

def _build_report_html(
    body: str,
    threats: list[dict],
    now_str: str,
    critical: int,
    high: int,
) -> str:
    rows = "".join(
        f"<tr><td>{t.get('id', '')[:8]}</td><td>{t.get('type', '')}</td>"
        f"<td>{str(t.get('severity', '')).upper()}</td>"
        f"<td>{str(t.get('source', ''))[:30]}</td><td>{t.get('status', '')}</td></tr>"
        for t in threats[:50]
    )
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<style>
body{{font-family:Arial,sans-serif;margin:40px;color:#1a1a2e;line-height:1.6}}
.hdr{{background:#16213e;color:white;padding:25px;border-radius:8px;margin-bottom:25px}}
.hdr h1{{margin:0;font-size:22px}}.hdr p{{margin:4px 0 0;opacity:.8;font-size:13px}}
.body{{white-space:pre-wrap;font-size:14px}}
table{{width:100%;border-collapse:collapse;margin-top:16px}}
th{{background:#16213e;color:white;padding:8px;text-align:left;font-size:12px}}
td{{padding:6px 8px;border-bottom:1px solid #e5e7eb;font-size:11px}}
</style></head><body>
<div class="hdr">
  <h1>&#128737; AISS Security Incident Report</h1>
  <p>{now_str} &nbsp;|&nbsp; Threats: {len(threats)} &nbsp;|&nbsp;
     Critical: {critical} &nbsp;|&nbsp; High: {high}</p>
</div>
<h2>Executive Summary</h2>
<div class="body">{body}</div>
<h2>Threat Details</h2>
<table>
  <tr><th>ID</th><th>Type</th><th>Severity</th><th>Source</th><th>Status</th></tr>
  {rows}
</table>
<p style="text-align:center;color:#9ca3af;font-size:11px;margin-top:30px">
AISS AI Security Intelligence System &mdash; Confidential</p>
</body></html>"""


# ── Report reportlab builder ──────────────────────────────────────────────

def _build_report_reportlab(
    body: str,
    threats: list[dict],
    now_str: str,
    critical: int,
    high: int,
) -> bytes:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        )
        import io

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf, pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=2*cm, bottomMargin=2*cm,
        )
        s     = getSampleStyleSheet()
        story = []

        story.append(Paragraph("AISS — Security Incident Report", s["Title"]))
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph(
            f"Generated: {now_str} | Threats: {len(threats)} | "
            f"Critical: {critical} | High: {high}",
            s["Normal"],
        ))
        story.append(Spacer(1, 0.4*cm))
        story.append(Paragraph("Executive Summary", s["Heading2"]))

        for para in body.split("\n\n"):
            if para.strip():
                safe = (
                    para.replace("&", "&amp;")
                        .replace("<", "&lt;")
                        .replace("\n", "<br/>")
                )
                story.append(Paragraph(safe, s["Normal"]))
                story.append(Spacer(1, 0.15*cm))

        story.append(Spacer(1, 0.4*cm))
        story.append(Paragraph("Threat Details", s["Heading2"]))

        rows = [["ID", "Type", "Severity", "Source", "Status"]] + [
            [
                str(t.get("id", ""))[:8],
                str(t.get("type", ""))[:24],
                str(t.get("severity", "")).upper(),
                str(t.get("source", ""))[:24],
                str(t.get("status", "")),
            ]
            for t in threats[:50]
        ]
        tbl = Table(rows, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0),  colors.HexColor("#16213e")),
            ("TEXTCOLOR",    (0, 0), (-1, 0),  colors.white),
            ("FONTSIZE",     (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
            ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
            ("PADDING",      (0, 0), (-1, -1), 4),
        ]))
        story.append(tbl)
        doc.build(story)
        pdf = buf.getvalue()
        logger.info("PDF via reportlab: %d bytes", len(pdf))
        return pdf

    except Exception as exc:
        logger.error("reportlab failed: %s — returning HTML bytes", exc)
        return _build_report_html(body, threats, now_str, critical, high).encode("utf-8")
