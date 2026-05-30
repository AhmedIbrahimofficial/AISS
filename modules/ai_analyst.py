"""
Cybersecurity - AI Analyst Module
Uses Claude API to deeply analyze threats and generate expert response recommendations
"""

import json
import httpx
from models.threat import Threat
from utils.logger import setup_logger

logger = setup_logger("ai_analyst")

CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
CLAUDE_MODEL = "claude-sonnet-4-20250514"

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


class AIAnalyst:
    def __init__(self, api_key: str = ""):
        self.api_key = api_key

    async def analyze_threat(self, threat: Threat) -> dict:
        """Send threat to Claude API for deep analysis"""
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

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    CLAUDE_API_URL,
                    headers={
                        "Content-Type": "application/json",
                        "anthropic-version": "2023-06-01"
                    },
                    json={
                        "model": CLAUDE_MODEL,
                        "max_tokens": 1000,
                        "system": SYSTEM_PROMPT,
                        "messages": [{"role": "user", "content": prompt}]
                    }
                )
                data = response.json()
                text = data["content"][0]["text"]

                # Parse JSON response
                try:
                    analysis = json.loads(text)
                except json.JSONDecodeError:
                    # Fallback: extract JSON from text
                    import re
                    match = re.search(r"\{.*\}", text, re.DOTALL)
                    analysis = json.loads(match.group()) if match else {"threat_assessment": text}

                return analysis

        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return {
                "threat_assessment": f"Automated analysis: {threat.type} detected from {threat.source}",
                "risk_level": threat.severity.upper(),
                "recommended_response": "Isolate source, investigate logs, apply patches",
                "resolution_message": f"✅ {threat.type} threat has been neutralized"
            }

    async def generate_report(self, threats: list[dict]) -> str:
        """Generate a comprehensive security incident report"""
        prompt = f"""Generate a concise executive security incident report for these threats:

{json.dumps(threats, indent=2)}

Include: Executive summary, threat timeline, impact assessment, actions taken, and recommendations."""

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    CLAUDE_API_URL,
                    headers={
                        "Content-Type": "application/json",
                        "anthropic-version": "2023-06-01"
                    },
                    json={
                        "model": CLAUDE_MODEL,
                        "max_tokens": 1000,
                        "messages": [{"role": "user", "content": prompt}]
                    }
                )
                data = response.json()
                return data["content"][0]["text"]
        except Exception as e:
            return f"Report generation failed: {e}"
