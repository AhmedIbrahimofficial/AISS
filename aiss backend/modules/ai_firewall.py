"""
AISS - AI Firewall (UPGRADED)
──────────────────────────────
Advanced features:
  - Risk scoring system (0-100): CRITICAL=40pts, HIGH=25pts, MEDIUM=15pts
    score>70 = block, 40-70 = warn+log, <40 = allow
  - Token anomaly detection: long repeated tokens = token flooding
  - Encoding detection: base64, hex, URL-encoded attacks
  - Multi-language injection patterns
  - Context poisoning detection: gradual manipulation patterns
  - Character frequency statistical analysis for obfuscation
  - Progressive blocking: 1st offense=warn, 2nd=5min block, 3rd=permanent
  - Per-endpoint rate limiting
  - Attack history per IP (last 10 attempts)
  - Whitelist for known safe patterns
"""

import re
import time
import base64
import hashlib
import math
import collections
from datetime import datetime, timedelta
from typing import Optional
from utils.logger import setup_logger

logger = setup_logger("ai_firewall")

# ══════════════════════════════════════════════════════════════════════
# Pattern definitions with risk weights
# ══════════════════════════════════════════════════════════════════════

# Each entry: (compiled_pattern, attack_type, risk_label, points)
FIREWALL_RULES: list[tuple] = []


def _rule(pattern: str, attack_type: str, risk: str, points: int, flags=re.I):
    FIREWALL_RULES.append((re.compile(pattern, flags), attack_type, risk, points))


# ── Prompt Injection (CRITICAL = 40pts each) ─────────────────────────
_rule(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)",
      "Prompt Injection", "CRITICAL", 40)
_rule(r"disregard\s+(all\s+)?(previous|prior|above)",
      "Prompt Injection", "CRITICAL", 40)
_rule(r"forget\s+(everything|all|your\s+instructions)",
      "Prompt Injection", "CRITICAL", 40)
_rule(r"you\s+are\s+now\s+(a|an)\s+\w+",
      "Prompt Injection", "CRITICAL", 40)
_rule(r"new\s+instructions?\s*:",
      "Prompt Injection", "CRITICAL", 40)
_rule(r"system\s*prompt\s*:",
      "Prompt Injection", "CRITICAL", 40)
_rule(r"###\s*(instruction|system|prompt)",
      "Prompt Injection", "CRITICAL", 40)
_rule(r"\[INST\]|\[SYS\]|<\|system\|>|<\|user\|>",
      "Prompt Injection", "CRITICAL", 40)
_rule(r"override\s+(safety|filter|restriction|guideline)",
      "Prompt Injection", "CRITICAL", 40)
# Multi-language injections
_rule(r"ignorez\s+les\s+instructions|ignorar\s+instrucciones|указания\s+игнорировать",
      "Prompt Injection (Multi-lang)", "CRITICAL", 40)

# ── Jailbreak (CRITICAL = 40pts) ─────────────────────────────────────
_rule(r"\bDAN\b.*mode",                         "Jailbreak", "CRITICAL", 40)
_rule(r"developer\s+mode",                      "Jailbreak", "CRITICAL", 40)
_rule(r"jailbreak",                             "Jailbreak", "CRITICAL", 40)
_rule(r"pretend\s+(you\s+)?(have\s+)?no\s+(rules?|restriction|filter|limit)",
      "Jailbreak", "CRITICAL", 40)
_rule(r"act\s+as\s+(if\s+you\s+(are|were)\s+)?(a\s+)?(unrestricted|evil|hacker|unfiltered)",
      "Jailbreak", "CRITICAL", 40)
_rule(r"(evil|unethical|uncensored|unrestricted)\s+(ai|model|assistant|version)",
      "Jailbreak", "CRITICAL", 40)
_rule(r"do\s+anything\s+now",                  "Jailbreak", "CRITICAL", 40)
_rule(r"(unlock|bypass|disable)\s+(safety|filter|content\s+policy)",
      "Jailbreak", "CRITICAL", 40)
_rule(r"your\s+true\s+self",                   "Jailbreak", "CRITICAL", 40)

# ── Data Extraction (HIGH = 25pts) ────────────────────────────────────
_rule(r"(print|show|reveal|output|display|repeat|tell\s+me)\s+(your\s+)?(system\s+prompt|instructions?|training\s+data|initial\s+prompt)",
      "Data Extraction", "HIGH", 25)
_rule(r"what\s+(are|were)\s+your\s+(instructions?|initial\s+prompt|system\s+message)",
      "Data Extraction", "HIGH", 25)
_rule(r"leak\s+(your\s+)?(prompt|data|credentials?|password|key)",
      "Data Extraction", "HIGH", 25)
_rule(r"extract\s+(training\s+data|private\s+data|credentials?)",
      "Data Extraction", "HIGH", 25)
_rule(r"(api\s+key|secret\s+key|password|token)\s*(=|:|\?)",
      "Data Extraction", "HIGH", 25)

# ── Context Poisoning (HIGH = 25pts) ─────────────────────────────────
_rule(r"(previous|last|earlier)\s+(response|answer|output)\s+(was|said|told)",
      "Context Poisoning", "HIGH", 25)
_rule(r"you\s+(previously|already|before)\s+(told|said|confirmed|agreed)",
      "Context Poisoning", "HIGH", 25)
_rule(r"based\s+on\s+(your|our)\s+(previous|earlier|past)\s+(conversation|context)",
      "Context Poisoning", "HIGH", 25)

# ── Model Abuse (CRITICAL = 40pts) ───────────────────────────────────
_rule(r"(generate|write|create)\s+(malware|virus|ransomware|exploit|payload)",
      "Model Abuse", "CRITICAL", 40)
_rule(r"(how\s+to\s+)?(hack|crack|brute.?force)\s+\w+",
      "Model Abuse", "CRITICAL", 40)
_rule(r"step.by.step\s+(instructions?\s+)?(to\s+)?(kill|murder|attack|bomb)",
      "Model Abuse", "CRITICAL", 40)

# ── Encoding Attacks (MEDIUM = 15pts, will elevate if decoded content is bad) ──
_rule(r"[A-Za-z0-9+/]{40,}={0,2}",             "Encoding Attack (base64)", "MEDIUM", 15)
_rule(r"(%[0-9A-Fa-f]{2}){10,}",               "Encoding Attack (URL)", "MEDIUM", 15)
_rule(r"(\\x[0-9A-Fa-f]{2}){10,}",             "Encoding Attack (hex)", "MEDIUM", 15)
_rule(r"&#[0-9]{2,4};",                         "HTML Injection", "MEDIUM", 15)

# ── Token Flooding (MEDIUM = 15pts) ──────────────────────────────────
_rule(r"(.)\1{50,}",                            "Token Flooding", "MEDIUM", 15)
_rule(r"(\b\w+\b)(\s+\1){20,}",                "Token Flooding", "MEDIUM", 15)


# ── Whitelist — never block these ─────────────────────────────────────
WHITELIST_PATTERNS = [
    re.compile(r"^(hello|hi|hey|please|thank|help|what|how|can you|could you)", re.I),
]

# ══════════════════════════════════════════════════════════════════════
# Rate limiting & blocking state
# ══════════════════════════════════════════════════════════════════════

RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX    = 30

# {ip → [timestamps]}
_request_counts: dict[str, list] = collections.defaultdict(list)

# {(ip, endpoint) → [timestamps]} — per-endpoint rate limiting
_endpoint_counts: dict[tuple, list] = collections.defaultdict(list)

# Attack history per IP: {ip → deque of (timestamp, attack_type, score)}
_attack_history: dict[str, collections.deque] = {}

# Progressive blocking:
# {ip → {"offense_count": int, "blocked_until": float, "permanent": bool}}
_block_registry: dict[str, dict] = {}

# ══════════════════════════════════════════════════════════════════════
# Result class
# ══════════════════════════════════════════════════════════════════════

class FirewallResult:
    """Result of a firewall inspection."""

    def __init__(
        self,
        blocked: bool,
        attack_type: str,
        reason: str,
        risk: str,
        score: int = 0,
        action: str = "allow",
    ):
        self.blocked     = blocked
        self.attack_type = attack_type
        self.reason      = reason
        self.risk        = risk
        self.score       = score
        self.action      = action   # allow | warn | block
        self.timestamp   = datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        return {
            "blocked":     self.blocked,
            "attack_type": self.attack_type,
            "reason":      self.reason,
            "risk":        self.risk,
            "score":       self.score,
            "action":      self.action,
            "timestamp":   self.timestamp,
        }


# ══════════════════════════════════════════════════════════════════════
# Statistical analysis helpers
# ══════════════════════════════════════════════════════════════════════

def _char_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of character distribution.
    Very high entropy (>4.5) in short text = possible encoding/obfuscation.
    """
    if not text:
        return 0.0
    freq  = collections.Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _detect_encoded_injection(text: str) -> tuple[bool, str]:
    """
    Try to decode base64/URL chunks and check decoded content for patterns.
    Returns (is_malicious, decoded_snippet).
    """
    # Base64 chunks
    b64_chunks = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", text)
    for chunk in b64_chunks[:5]:
        try:
            decoded = base64.b64decode(chunk + "==").decode("utf-8", errors="ignore")
            if any(kw in decoded.lower() for kw in [
                "ignore", "system prompt", "jailbreak", "dan mode",
                "forget instructions", "you are now",
            ]):
                return True, decoded[:60]
        except Exception:
            pass
    return False, ""


# ══════════════════════════════════════════════════════════════════════
# Progressive blocking
# ══════════════════════════════════════════════════════════════════════

def _progressive_block(ip: str, attack_type: str, score: int) -> tuple[bool, str]:
    """
    Apply progressive blocking:
      1st offense → warn (no block)
      2nd offense → 5-minute block
      3rd+ offense → permanent block
    Returns (is_blocked, reason).
    """
    now    = time.time()
    record = _block_registry.setdefault(ip, {
        "offense_count": 0,
        "blocked_until": 0.0,
        "permanent":     False,
    })

    # Already permanently blocked
    if record["permanent"]:
        return True, f"Permanently blocked (repeat offender, {record['offense_count']} offenses)"

    # Currently in temporary block window
    if now < record["blocked_until"]:
        remaining = int(record["blocked_until"] - now)
        return True, f"Temporarily blocked for {remaining}s more"

    # New offense
    record["offense_count"] += 1
    count = record["offense_count"]

    if count == 1:
        logger.info(f"AI Firewall WARN [{ip}]: 1st offense ({attack_type})")
        return False, f"1st offense — warning issued"

    if count == 2:
        record["blocked_until"] = now + 300  # 5 min
        logger.warning(f"AI Firewall BLOCK [{ip}]: 2nd offense — 5min block")
        return True, f"2nd offense — blocked for 5 minutes"

    # 3rd+
    record["permanent"] = True
    logger.warning(f"AI Firewall PERMANENT BLOCK [{ip}]: {count} offenses")
    return True, f"Permanent block ({count} offenses)"


def _record_attack(ip: str, attack_type: str, score: int) -> None:
    """Record an attack attempt in the per-IP history."""
    if ip not in _attack_history:
        _attack_history[ip] = collections.deque(maxlen=10)
    _attack_history[ip].append({
        "timestamp":   datetime.utcnow().isoformat(),
        "attack_type": attack_type,
        "score":       score,
    })


# ══════════════════════════════════════════════════════════════════════
# Main inspection function
# ══════════════════════════════════════════════════════════════════════

def inspect(
    text: str,
    source_ip: str = "unknown",
    endpoint: str = "default",
) -> FirewallResult:
    """
    Inspect a prompt/message for AI attacks using risk scoring.

    Scoring:
      CRITICAL match = +40pts
      HIGH match     = +25pts
      MEDIUM match   = +15pts
      score > 70     = block
      score 40–70    = warn + log
      score < 40     = allow

    Progressive blocking applies to repeat offenders.
    """
    if not text or not isinstance(text, str):
        return FirewallResult(False, "", "Clean", "LOW", 0, "allow")

    # ── Whitelist check ───────────────────────────────────────────────
    stripped = text.strip()
    if len(stripped) < 100:
        for wp in WHITELIST_PATTERNS:
            if wp.match(stripped):
                return FirewallResult(False, "", "Whitelisted", "LOW", 0, "allow")

    # ── Global rate limiting ──────────────────────────────────────────
    now = time.time()
    _request_counts[source_ip] = [
        t for t in _request_counts[source_ip]
        if now - t < RATE_LIMIT_WINDOW
    ]
    _request_counts[source_ip].append(now)
    if len(_request_counts[source_ip]) > RATE_LIMIT_MAX:
        return FirewallResult(
            True, "Rate Limit", f"{len(_request_counts[source_ip])} req/{RATE_LIMIT_WINDOW}s",
            "HIGH", 30, "block",
        )

    # ── Per-endpoint rate limiting ────────────────────────────────────
    ep_key = (source_ip, endpoint)
    _endpoint_counts[ep_key] = [
        t for t in _endpoint_counts[ep_key] if now - t < RATE_LIMIT_WINDOW
    ]
    _endpoint_counts[ep_key].append(now)
    if len(_endpoint_counts[ep_key]) > RATE_LIMIT_MAX // 2:
        return FirewallResult(
            True, "Endpoint Rate Limit",
            f"Too many requests to {endpoint}",
            "MEDIUM", 25, "block",
        )

    # ── Statistical entropy check ─────────────────────────────────────
    score       = 0
    matched     = []
    top_type    = ""
    top_risk    = "LOW"

    if len(text) > 20:
        entropy = _char_entropy(text)
        # Very short text with high entropy = obfuscated payload
        if entropy > 5.0 and len(text) < 200:
            score += 20
            matched.append("High-entropy short text (obfuscation)")

    # ── Encoded injection check ───────────────────────────────────────
    encoded_bad, decoded_snippet = _detect_encoded_injection(text)
    if encoded_bad:
        score += 35
        matched.append(f"Base64-encoded injection: '{decoded_snippet}'")
        top_type = "Encoding Attack"
        top_risk = "CRITICAL"

    # ── Pattern matching ──────────────────────────────────────────────
    for pattern, attack_type, risk, points in FIREWALL_RULES:
        m = pattern.search(text)
        if m:
            score    += points
            snippet   = m.group(0)[:60]
            matched.append(f"[{attack_type}] '{snippet}'")
            if points > 15:   # Only track significant matches for primary type
                if not top_type or points > _risk_points(top_risk):
                    top_type = attack_type
                    top_risk = risk

    # ── Length abuse ──────────────────────────────────────────────────
    if len(text) > 10000:
        score += 20
        matched.append(f"Input too long: {len(text)} chars")

    # ── Determine action ──────────────────────────────────────────────
    if score == 0 and not matched:
        return FirewallResult(False, "", "Clean", "LOW", 0, "allow")

    reason = "; ".join(matched[:3])   # top 3 reasons

    if score < 40:
        # Low risk — allow but log
        logger.debug(f"AI Firewall LOW [{source_ip}] score={score}: {reason[:80]}")
        return FirewallResult(False, top_type or "Low Risk", reason, "LOW", score, "allow")

    # Score >= 40 — apply progressive blocking
    _record_attack(source_ip, top_type, score)
    is_blocked, block_reason = _progressive_block(source_ip, top_type, score)

    if not is_blocked and score < 70:
        # 40-70 = warn
        logger.warning(
            f"AI Firewall WARN [{source_ip}] score={score} [{top_type}]: {reason[:80]}"
        )
        return FirewallResult(
            False, top_type, f"[WARN] {reason}", top_risk, score, "warn"
        )

    # Block
    final_reason = f"{reason} | {block_reason}" if block_reason else reason
    logger.warning(
        f"AI Firewall BLOCKED [{source_ip}] score={score} [{top_type}]: {final_reason[:120]}"
    )
    return FirewallResult(True, top_type, final_reason, top_risk, score, "block")


def _risk_points(risk: str) -> int:
    return {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 15, "LOW": 5}.get(risk, 5)


# ══════════════════════════════════════════════════════════════════════
# Stats & management
# ══════════════════════════════════════════════════════════════════════

def get_stats() -> dict:
    """Return current rate-limit stats and block registry."""
    now = time.time()
    return {
        "rate_limits": {
            ip: len([t for t in times if now - t < RATE_LIMIT_WINDOW])
            for ip, times in _request_counts.items()
        },
        "blocked_ips": {
            ip: {
                "offense_count": rec["offense_count"],
                "permanent":     rec["permanent"],
                "blocked_until": datetime.fromtimestamp(rec["blocked_until"]).isoformat()
                                 if rec["blocked_until"] > now else "expired",
            }
            for ip, rec in _block_registry.items()
            if rec["permanent"] or rec["blocked_until"] > now
        },
    }


def get_attack_history(ip: str) -> list[dict]:
    """Return the last 10 attack attempts from a given IP."""
    history = _attack_history.get(ip)
    return list(history) if history else []


def unblock_ip(ip: str) -> bool:
    """Manually unblock an IP."""
    if ip in _block_registry:
        _block_registry[ip] = {"offense_count": 0, "blocked_until": 0.0, "permanent": False}
        logger.info(f"IP {ip} manually unblocked")
        return True
    return False
