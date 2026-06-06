"""
Cybersecurity - AI Analyst Module
Uses Claude API to deeply analyze threats and generate expert response recommendations.

Rate limit handling:
  - Random 1–3s delay before every request (avoid triggering limits)
  - Exponential backoff on HTTP 429: retries at 1s, 2s, 4s (max 3 retries)
"""

import asyncio
import json
import random
import re
import httpx

from models.threat import Threat
from utils.logger import setup_logger

logger = setup_logger("ai_analyst")

CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
CLAUDE_MODEL   = "claude-sonnet-4-20250514"

# Rate-limit config
_MIN_DELAY_S   = 1.0   # minimum pre-request delay (seconds)
_MAX_DELAY_S   = 3.0   # maximum pre-request delay (seconds)
_MAX_RETRIES   = 3     # retries on 429
_BACKOFF_BASE  = 1.0   # first retry wait (seconds); doubles each retry

SYSTEM_PROMPT = """You are Cybersecurity's AI Security Analyst — an elite cybersecurity expert with deep knowledge of:
- Malware analysis (viruses, trojans, worms, ransomware, spyware, rootkits, botnets, cryptominers)
- Network security (intrusion detection, DDoS, MITM, ARP spoofing, DNS attacks)
- Threat intelligence and incident response
- MITRE ATT&CK framework
- Digital forensics

When given a threat report, you MUST respond with a JSON object (no markdown, no preamble) with this exact structure:
{
  "threat_assessment": "Detailed analysis of what this threat is and how it works",
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "attack_vector": "How the attacker gained/is gaining access",
  "potential_impact": "What damage this could cause if not stopped",
  "immediate_actions": ["action1", "action2", "action3"],
  "recommended_response": "Step-by-step response plan",
  "mitre_tactics": ["tactic1", "tactic2"],
  "indicators_of_compromise": ["ioc1", "ioc2"],
  "resolution_message": "Short success message to show when threat is resolved"
}"""


# ── Internal helpers ──────────────────────────────────────────────────

async def _pre_request_delay() -> None:
    """Wait a random 1–3 seconds before sending a request."""
    delay = random.uniform(_MIN_DELAY_S, _MAX_DELAY_S)
    logger.debug(f"AI rate-limit delay: {delay:.2f}s")
    await asyncio.sleep(delay)


async def _post_with_backoff(
    client: httpx.AsyncClient,
    url: str,
    headers: dict,
    payload: dict,
) -> httpx.Response:
    """
    POST with exponential backoff on HTTP 429.

    Retry schedule (seconds): 1 → 2 → 4
    Raises httpx.HTTPStatusError if still failing after max retries.
    """
    wait = _BACKOFF_BASE

    for attempt in range(_MAX_RETRIES + 1):
        await _pre_request_delay()

        response = await client.post(url, headers=headers, json=payload)

        if response.status_code == 429:
            if attempt == _MAX_RETRIES:
                logger.error(
                    f"Claude API rate limit hit — gave up after {_MAX_RETRIES} retries"
                )
                response.raise_for_status()

            # Honour Retry-After header if present, else use backoff
            retry_after = response.headers.get("retry-after")
            sleep_time  = float(retry_after) if retry_after else wait

            logger.warning(
                f"Claude API 429 — retry {attempt + 1}/{_MAX_RETRIES} "
                f"in {sleep_time:.1f}s"
            )
            await asyncio.sleep(sleep_time)
            wait *= 2  # double for next retry
            continue

        # Any other 4xx/5xx → raise immediately (no point retrying)
        response.raise_for_status()
        return response

    # Should never reach here
    raise RuntimeError("Unexpected exit from retry loop")


def _parse_claude_json(text: str) -> dict:
    """Try to parse Claude's response as JSON, fallback to regex extraction."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            return json.loads(match.group())
        return {"threat_assessment": text}


# ── Public API ────────────────────────────────────────────────────────

class AIAnalyst:
    def __init__(self, api_key: str = ""):
        self.api_key = api_key

    def _headers(self) -> dict:
        return {
            "Content-Type":      "application/json",
            "x-api-key":         self.api_key,
            "anthropic-version": "2023-06-01",
        }

    async def analyze_threat(self, threat: Threat) -> dict:
        """
        Send a single threat to Claude for deep analysis.
        Applies 1–3s pre-request delay + exponential backoff on 429.
        """
        prompt = f"""Analyze this cybersecurity threat detected by Cybersecurity Platform:

THREAT REPORT:
- Type: {threat.type}
- Severity: {threat.severity}
- Description: {threat.description}
- Source: {threat.source}
- Detection Module: {threat.module}
- Metadata: {json.dumps(threat.metadata, indent=2)}
- Detected At: {threat.detected_at}

Provide a comprehensive security analysis and response plan."""

        payload = {
            "model":      CLAUDE_MODEL,
            "max_tokens": 1000,
            "system":     SYSTEM_PROMPT,
            "messages":   [{"role": "user", "content": prompt}],
        }

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                response = await _post_with_backoff(
                    client, CLAUDE_API_URL, self._headers(), payload
                )
            data     = response.json()
            text     = data["content"][0]["text"]
            analysis = _parse_claude_json(text)
            logger.info(f"AI analysis complete for threat: {threat.id}")
            return analysis

        except Exception as e:
            logger.error(f"AI analysis failed for {threat.id}: {e}")
            return {
                "threat_assessment":  f"Automated analysis: {threat.type} detected from {threat.source}",
                "risk_level":         threat.severity.upper(),
                "recommended_response": "Isolate source, investigate logs, apply patches",
                "resolution_message": f"✅ {threat.type} threat has been neutralized",
            }

    async def analyze_threats_batch(
        self, threats: list[Threat], *, delay_between: float = 2.0
    ) -> list[dict]:
        """
        Analyze multiple threats sequentially.
        Adds `delay_between` seconds between each call on top of the
        per-request random delay — avoids burst rate limiting.
        """
        results = []
        for i, threat in enumerate(threats):
            if i > 0:
                logger.debug(f"Batch delay {delay_between}s before threat {i + 1}/{len(threats)}")
                await asyncio.sleep(delay_between)
            result = await self.analyze_threat(threat)
            results.append(result)
        return results

    async def generate_report(self, threats: list[dict]) -> str:
        """
        Generate an executive security incident report for a list of threats.
        Applies the same delay + backoff as analyze_threat.
        """
        prompt = f"""Generate a concise executive security incident report for these threats:

{json.dumps(threats, indent=2)}

Include: Executive summary, threat timeline, impact assessment, actions taken, and recommendations."""

        payload = {
            "model":    CLAUDE_MODEL,
            "max_tokens": 1500,
            "messages": [{"role": "user", "content": prompt}],
        }

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                response = await _post_with_backoff(
                    client, CLAUDE_API_URL, self._headers(), payload
                )
            data = response.json()
            return data["content"][0]["text"]

        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return f"Report generation failed: {e}"
