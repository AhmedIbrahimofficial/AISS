"""
CyberSentinel - Secure AI Firewall
Detects and blocks AI-targeted attacks before they reach the model.

Attack types detected:
  1. Prompt Injection     — "ignore previous instructions", "you are now..."
  2. Jailbreak Attempts   — "DAN mode", "developer mode", "pretend you have no rules"
  3. Data Extraction      — attempts to leak training data, system prompts, credentials
  4. Model Abuse          — NSFW, illegal content, mass automated requests
"""

import re
import time
from collections import defaultdict
from datetime import datetime
from utils.logger import setup_logger

logger = setup_logger("ai_firewall")

# ── Pattern sets ──────────────────────────────────────────────────────

PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)", re.I),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|above)", re.I),
    re.compile(r"forget\s+(everything|all|your\s+instructions)", re.I),
    re.compile(r"you\s+are\s+now\s+(a|an)\s+\w+", re.I),
    re.compile(r"new\s+instructions?\s*:", re.I),
    re.compile(r"system\s*prompt\s*:", re.I),
    re.compile(r"###\s*(instruction|system|prompt)", re.I),
    re.compile(r"\[INST\]|\[SYS\]|<\|system\|>|<\|user\|>", re.I),
    re.compile(r"override\s+(safety|filter|restriction|guideline)", re.I),
]

JAILBREAK_PATTERNS = [
    re.compile(r"\bDAN\b.*mode", re.I),
    re.compile(r"developer\s+mode", re.I),
    re.compile(r"jailbreak", re.I),
    re.compile(r"pretend\s+(you\s+)?(have\s+)?no\s+(rules?|restriction|filter|limit)", re.I),
    re.compile(r"act\s+as\s+(if\s+you\s+(are|were)\s+)?(a\s+)?(unrestricted|evil|hacker|unfiltered)", re.I),
    re.compile(r"(evil|unethical|uncensored|unrestricted)\s+(ai|model|assistant|version)", re.I),
    re.compile(r"do\s+anything\s+now", re.I),
    re.compile(r"without\s+(any\s+)?(restrictions?|filters?|limitations?|guidelines?)", re.I),
    re.compile(r"your\s+true\s+self", re.I),
    re.compile(r"(unlock|bypass|disable)\s+(safety|filter|content\s+policy)", re.I),
]

DATA_EXTRACTION_PATTERNS = [
    re.compile(r"(print|show|reveal|output|display|repeat|tell\s+me)\s+(your\s+)?(system\s+prompt|instructions?|training\s+data|initial\s+prompt)", re.I),
    re.compile(r"(show|give|tell)\s+me\s+(your\s+)?(system|prompt|instructions?)", re.I),
    re.compile(r"what\s+(are|were)\s+your\s+(instructions?|initial\s+prompt|system\s+message)", re.I),
    re.compile(r"leak\s+(your\s+)?(prompt|data|credentials?|password|key)", re.I),
    re.compile(r"extract\s+(training\s+data|private\s+data|credentials?)", re.I),
    re.compile(r"(api\s+key|secret\s+key|password|token)\s*(=|:|\?)", re.I),
    re.compile(r"base64\s+(decode|encode)\s+.{20,}", re.I),
    re.compile(r"<\?php|<script>|javascript:", re.I),
]

MODEL_ABUSE_PATTERNS = [
    re.compile(r"(generate|write|create)\s+(malware|virus|ransomware|exploit|payload)", re.I),
    re.compile(r"(how\s+to\s+)?(hack|crack|brute.?force)\s+\w+", re.I),
    re.compile(r"(synthesize|make|create|produce)\s+(drugs?|poison|explosive|bomb)", re.I),
    re.compile(r"(child|minor|underage).{0,20}(sexual|nude|explicit|porn)", re.I),
    re.compile(r"step.by.step\s+(instructions?\s+)?(to\s+)?(kill|murder|attack|bomb)", re.I),
]

# ── Rate limiting ─────────────────────────────────────────────────────
_request_counts: dict[str, list] = defaultdict(list)
RATE_LIMIT_WINDOW = 60   # seconds
RATE_LIMIT_MAX    = 30   # requests per window per source


# ── Main firewall function ────────────────────────────────────────────

class FirewallResult:
    def __init__(self, blocked: bool, attack_type: str, reason: str, risk: str):
        self.blocked     = blocked
        self.attack_type = attack_type
        self.reason      = reason
        self.risk        = risk          # LOW / MEDIUM / HIGH / CRITICAL
        self.timestamp   = datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        return {
            "blocked":     self.blocked,
            "attack_type": self.attack_type,
            "reason":      self.reason,
            "risk":        self.risk,
            "timestamp":   self.timestamp,
        }


def inspect(text: str, source_ip: str = "unknown") -> FirewallResult:
    """
    Inspect a prompt/message for AI attacks.
    Returns FirewallResult — check .blocked before sending to AI.
    """
    if not text or not isinstance(text, str):
        return FirewallResult(False, "", "", "LOW")

    # ── Rate limiting ─────────────────────────────────────────────────
    now = time.time()
    _request_counts[source_ip] = [
        t for t in _request_counts[source_ip]
        if now - t < RATE_LIMIT_WINDOW
    ]
    _request_counts[source_ip].append(now)

    if len(_request_counts[source_ip]) > RATE_LIMIT_MAX:
        logger.warning(f"AI Firewall: Rate limit exceeded from {source_ip}")
        return FirewallResult(
            blocked     = True,
            attack_type = "Model Abuse",
            reason      = f"Rate limit exceeded: {len(_request_counts[source_ip])} requests in {RATE_LIMIT_WINDOW}s",
            risk        = "HIGH",
        )

    # ── Pattern checks ────────────────────────────────────────────────
    checks = [
        (PROMPT_INJECTION_PATTERNS, "Prompt Injection",  "CRITICAL"),
        (JAILBREAK_PATTERNS,        "Jailbreak Attempt", "CRITICAL"),
        (DATA_EXTRACTION_PATTERNS,  "Data Extraction",   "HIGH"),
        (MODEL_ABUSE_PATTERNS,      "Model Abuse",       "CRITICAL"),
    ]

    for patterns, attack_type, risk in checks:
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                snippet = match.group(0)[:60]
                logger.warning(
                    f"AI Firewall BLOCKED [{attack_type}] from {source_ip} "
                    f"— matched: '{snippet}'"
                )
                return FirewallResult(
                    blocked     = True,
                    attack_type = attack_type,
                    reason      = f"Pattern matched: '{snippet}'",
                    risk        = risk,
                )

    # ── Length abuse ──────────────────────────────────────────────────
    if len(text) > 10000:
        return FirewallResult(
            blocked     = True,
            attack_type = "Model Abuse",
            reason      = f"Input too long: {len(text)} characters (max 10000)",
            risk        = "MEDIUM",
        )

    return FirewallResult(False, "", "Clean", "LOW")


def get_stats() -> dict:
    """Return current rate-limit stats per IP."""
    now = time.time()
    return {
        ip: len([t for t in times if now - t < RATE_LIMIT_WINDOW])
        for ip, times in _request_counts.items()
    }
