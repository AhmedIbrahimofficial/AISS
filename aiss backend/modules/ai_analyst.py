"""AISS - AI Analyst Module
Supports both Anthropic (Claude) and OpenAI (GPT) providers.
Provider is auto-detected from the API key, or set explicitly.

Rate limiting:
  - tenacity @retry with exponential backoff on HTTP 429
  - Random 1-3s jitter before every Claude request
"""

import asyncio, json, os, random, re, httpx, logging
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception, before_sleep_log
from models.threat import Threat
from utils.logger import setup_logger

logger = setup_logger("ai_analyst")

CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
CLAUDE_MODEL   = "claude-sonnet-4-20250514"
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
OPENAI_MODEL   = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

SYSTEM_PROMPT = """You are AISS's AI Security Analyst — an elite cybersecurity expert.
When given a threat report, respond ONLY with a JSON object (no markdown) with this structure:
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


def _is_rate_limit(exc):
    return isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 429

def _parse_json(text):
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


async def _call_openai(api_key, messages, max_tokens=1000, model=None):
    """Call OpenAI chat completions and return text."""
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.post(
            OPENAI_API_URL,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": model or OPENAI_MODEL, "max_tokens": max_tokens, "messages": messages},
        )
        if r.status_code == 429:
            r.raise_for_status()
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


class AIAnalyst:
    """
    AI Analyst supporting Anthropic Claude and OpenAI GPT.

    Provider auto-detection:
      - api_key starts with "sk-ant-"  → Claude
      - api_key starts with "sk-"      → OpenAI
      - provider="openai" / "claude"   → explicit override
      - Falls back to env vars: ANTHROPIC_API_KEY / OPENAI_API_KEY
    """

    def __init__(self, api_key: str = "", provider: str = "auto"):
        self.api_key   = api_key or ""
        self._provider = self._detect(provider, api_key)

    def _detect(self, provider, key):
        if provider in ("claude", "openai"):
            return provider
        if key.startswith("sk-ant-") or os.environ.get("ANTHROPIC_API_KEY", "").startswith("sk-ant-"):
            return "claude"
        if key.startswith("sk-") or os.environ.get("OPENAI_API_KEY"):
            return "openai"
        return "claude"

    @property
    def provider(self):
        return self._provider

    @retry(
        retry=retry_if_exception(_is_rate_limit),
        wait=wait_exponential(multiplier=1, min=1, max=30),
        stop=stop_after_attempt(4),
        before_sleep=before_sleep_log(logging.getLogger("cybersecurity.ai_analyst"), logging.WARNING),
        reraise=True,
    )
    async def _post_claude(self, payload):
        await asyncio.sleep(random.uniform(1.0, 3.0))
        async with httpx.AsyncClient(timeout=60) as client:
            r = await client.post(
                CLAUDE_API_URL,
                headers={"Content-Type": "application/json",
                         "x-api-key": self.api_key,
                         "anthropic-version": "2023-06-01"},
                json=payload,
            )
            if r.status_code == 429:
                r.raise_for_status()
            r.raise_for_status()
            return r.json()

    async def _complete(self, user_prompt, system=SYSTEM_PROMPT, max_tokens=1000):
        """Call configured provider and return text response."""
        if self._provider == "openai":
            key = self.api_key or os.environ.get("OPENAI_API_KEY", "")
            if not key:
                raise ValueError("OPENAI_API_KEY not configured")
            return await _call_openai(
                key,
                [{"role": "system", "content": system},
                 {"role": "user",   "content": user_prompt}],
                max_tokens=max_tokens,
            )
        else:
            key = self.api_key or os.environ.get("ANTHROPIC_API_KEY", "")
            if not key:
                raise ValueError("ANTHROPIC_API_KEY not configured")
            self.api_key = key
            data = await self._post_claude({
                "model": CLAUDE_MODEL, "max_tokens": max_tokens,
                "system": system,
                "messages": [{"role": "user", "content": user_prompt}],
            })
            return data["content"][0]["text"]

    async def analyze_threat(self, threat: Threat) -> dict:
        prompt = f"""Analyze this cybersecurity threat detected by AISS:
Type: {threat.type} | Severity: {threat.severity} | Source: {threat.source}
Module: {threat.module} | Detected: {threat.detected_at}
Description: {threat.description}
Metadata: {json.dumps(threat.metadata, indent=2)}"""
        try:
            text = await self._complete(prompt, max_tokens=1000)
            result = _parse_json(text)
            logger.info(f"Analysis complete [{self._provider}]: {threat.id[:8]}")
            return result
        except Exception as e:
            logger.error(f"Analysis failed [{self._provider}] {threat.id[:8]}: {e}")
            return {
                "threat_assessment": f"Automated: {threat.type} from {threat.source}",
                "risk_level": str(threat.severity).upper(),
                "recommended_response": "Isolate source, investigate logs, apply patches",
                "resolution_message": f"✅ {threat.type} neutralized",
            }

    async def analyze_threats_batch(self, threats, *, delay_between=2.0):
        results = []
        for i, t in enumerate(threats):
            if i > 0:
                await asyncio.sleep(delay_between)
            results.append(await self.analyze_threat(t))
        return results

    async def generate_report(self, threats: list) -> str:
        prompt = f"""Write a concise executive security incident report for these {len(threats)} threats:
{json.dumps(threats[:30], indent=2)}
Include: Executive summary, timeline, impact, actions taken, recommendations."""
        try:
            return await self._complete(prompt,
                system="You are a professional security report writer. Be concise and structured.",
                max_tokens=1500)
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return f"Report generation failed: {e}"

    async def generate_pdf_report(self, threats: list) -> bytes:
        """Generate PDF report — tries weasyprint, falls back to reportlab."""
        from datetime import datetime
        report_text = await self.generate_report(threats)
        now_str  = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        critical = sum(1 for t in threats if str(t.get("severity","")).lower() == "critical")
        high     = sum(1 for t in threats if str(t.get("severity","")).lower() == "high")

        try:
            import weasyprint
            html = _build_report_html(report_text, threats, now_str, critical, high)
            pdf = weasyprint.HTML(string=html).write_pdf()
            logger.info(f"PDF via weasyprint: {len(pdf)} bytes")
            return pdf
        except Exception as we:
            logger.warning(f"weasyprint unavailable ({type(we).__name__}) — using reportlab")

        return _build_report_reportlab(report_text, threats, now_str, critical, high)


# ── Report rendering helpers ──────────────────────────────────────────

def _build_report_html(body, threats, now_str, critical, high):
    rows = "".join(
        f"<tr><td>{t.get('id','')[:8]}</td><td>{t.get('type','')}</td>"
        f"<td>{str(t.get('severity','')).upper()}</td>"
        f"<td>{t.get('source','')[:30]}</td><td>{t.get('status','')}</td></tr>"
        for t in threats[:50]
    )
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<style>body{{font-family:Arial;margin:40px;color:#1a1a2e}}
.hdr{{background:#16213e;color:white;padding:25px;border-radius:8px;margin-bottom:25px}}
.hdr h1{{margin:0;font-size:22px}}.hdr p{{margin:4px 0 0;opacity:.8;font-size:13px}}
.body{{white-space:pre-wrap;line-height:1.6;font-size:14px}}
table{{width:100%;border-collapse:collapse;margin-top:16px}}
th{{background:#16213e;color:white;padding:8px;text-align:left;font-size:12px}}
td{{padding:6px 8px;border-bottom:1px solid #e5e7eb;font-size:11px}}
</style></head><body>
<div class="hdr"><h1>&#128737; AISS Security Incident Report</h1>
<p>{now_str} | Threats: {len(threats)} | Critical: {critical} | High: {high}</p></div>
<h2>Executive Summary</h2><div class="body">{body}</div>
<h2>Threat Details</h2>
<table><tr><th>ID</th><th>Type</th><th>Severity</th><th>Source</th><th>Status</th></tr>
{rows}</table>
<p style="text-align:center;color:#9ca3af;font-size:11px;margin-top:30px">
AISS AI Security Intelligence System — Confidential</p>
</body></html>"""


def _build_report_reportlab(body, threats, now_str, critical, high):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        import io

        buf  = io.BytesIO()
        doc  = SimpleDocTemplate(buf, pagesize=A4,
                                 leftMargin=2*cm, rightMargin=2*cm,
                                 topMargin=2*cm,  bottomMargin=2*cm)
        s    = getSampleStyleSheet()
        story = []

        story.append(Paragraph("AISS — Security Incident Report",
            ParagraphStyle("T", parent=s["Title"],
                           textColor=colors.HexColor("#16213e"), fontSize=18)))
        story.append(Spacer(1, .3*cm))
        story.append(Paragraph(
            f"Generated: {now_str} | Threats: {len(threats)} | Critical: {critical} | High: {high}",
            s["Normal"]))
        story.append(Spacer(1, .4*cm))
        story.append(Paragraph("Executive Summary", s["Heading2"]))
        for para in body.split("\n\n"):
            if para.strip():
                safe = para.replace("&","&amp;").replace("<","&lt;").replace("\n","<br/>")
                story.append(Paragraph(safe, s["Normal"]))
                story.append(Spacer(1, .15*cm))

        story.append(Spacer(1, .4*cm))
        story.append(Paragraph("Threat Details", s["Heading2"]))
        rows = [["ID","Type","Severity","Source","Status"]] + [
            [t.get("id","")[:8], str(t.get("type",""))[:24],
             str(t.get("severity","")).upper(), str(t.get("source",""))[:24],
             str(t.get("status",""))]
            for t in threats[:50]
        ]
        tbl = Table(rows, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#16213e")),
            ("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("FONTSIZE",(0,0),(-1,-1),8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f8f9fa")]),
            ("GRID",(0,0),(-1,-1),.5,colors.HexColor("#e5e7eb")),
            ("PADDING",(0,0),(-1,-1),4),
        ]))
        story.append(tbl)
        doc.build(story)
        pdf = buf.getvalue()
        logger.info(f"PDF via reportlab: {len(pdf)} bytes")
        return pdf
    except Exception as e:
        logger.error(f"reportlab failed: {e} — returning HTML bytes")
        return _build_report_html(body, threats, now_str, critical, high).encode("utf-8")
