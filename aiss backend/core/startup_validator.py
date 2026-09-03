"""AISS - Startup Validation System
Runs at launch before anything else:
  1. Environment variable validation (required vs optional)
  2. Dependency verification (redis, DB reachability)
  3. File system checks (writable dirs, rules present)
  4. License validation
  5. Security config (auto-generates missing keys)

Returns a StartupReport with pass/warn/fail counts.
Blocks startup on any FAIL in production.
"""

import asyncio
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from utils.logger import setup_logger

logger = setup_logger("startup_validator")

CheckResult = Literal["PASS", "WARN", "FAIL"]


@dataclass
class Check:
    name:    str
    result:  CheckResult
    message: str


@dataclass
class StartupReport:
    checks: list[Check] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.result == "PASS")

    @property
    def warnings(self) -> int:
        return sum(1 for c in self.checks if c.result == "WARN")

    @property
    def failures(self) -> int:
        return sum(1 for c in self.checks if c.result == "FAIL")

    def add(self, name: str, result: CheckResult, msg: str) -> None:
        self.checks.append(Check(name, result, msg))

    def print_summary(self) -> None:
        logger.info(f"{'─'*60}")
        logger.info("AISS STARTUP VALIDATION REPORT")
        logger.info(f"{'─'*60}")
        for c in self.checks:
            icon = {"PASS": "✅", "WARN": "⚠ ", "FAIL": "🚫"}[c.result]
            logger.info(f"  {icon} [{c.result:4}] {c.name}: {c.message}")
        logger.info(f"{'─'*60}")
        logger.info(
            f"  Result: {self.passed} passed, {self.warnings} warnings, "
            f"{self.failures} failures"
        )
        logger.info(f"{'─'*60}")


async def run_startup_checks() -> StartupReport:
    """Execute all startup checks and return the report."""
    report = StartupReport()
    env    = os.environ.get("ENVIRONMENT", "development").lower()
    is_prod = env == "production"

    # ── 1. Security config & key generation ──────────────────────────
    try:
        from core.security_config import security_config
        await security_config.validate()
        report.add("SecurityConfig", "PASS", "All secret keys resolved")
    except SystemExit:
        raise   # let critical failures propagate
    except Exception as e:
        report.add("SecurityConfig", "FAIL", str(e))

    # ── 2. License validation ─────────────────────────────────────────
    try:
        from core.licensing import license_manager
        info = await license_manager.validate()
        result = "PASS" if license_manager.is_valid() else "WARN"
        report.add("License", result,
                   f"{info.license_type.value} [{info.status.value}] {info.message[:60]}")
    except Exception as e:
        report.add("License", "WARN", f"License check failed: {e}")

    # ── 3-4. Run DB + Redis checks concurrently (slow I/O) ──────────────
    async def _check_db():
        try:
            from core.database import engine
            from sqlalchemy import text
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            return ("Database", "PASS", f"Connected: {_mask_url(os.environ.get('DATABASE_URL',''))}")
        except Exception as e:
            level = "FAIL" if is_prod else "WARN"
            return ("Database", level, f"Connection failed: {e}")

    async def _check_redis():
        try:
            import redis.asyncio as aioredis
            url    = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
            client = aioredis.from_url(url, socket_connect_timeout=2, socket_timeout=2)
            await asyncio.wait_for(client.ping(), timeout=2)
            await client.aclose()
            return ("Redis", "PASS", f"Connected: {_mask_url(url)}")
        except Exception as e:
            return ("Redis", "WARN", f"Redis unavailable (using asyncio task runner instead): {e}")

    async def _check_bom():
        bom_files = []
        for py_file in Path(".").rglob("*.py"):
            parts = py_file.parts
            if any(skip in parts for skip in (".venv", "venv", "node_modules", "build", "dist", "__pycache__")):
                continue
            try:
                raw = py_file.read_bytes()[:3]
                if raw.startswith(b"\xef\xbb\xbf"):
                    bom_files.append(str(py_file))
            except Exception:
                pass
        if bom_files:
            return ("SourceBOM", "FAIL" if is_prod else "WARN",
                       f"BOM character found in {len(bom_files)} file(s): {', '.join(bom_files[:5])}")
        return ("SourceBOM", "PASS", "No BOM characters in source files")

    db_res, redis_res, bom_res = await asyncio.gather(_check_db(), _check_redis(), _check_bom())
    report.add(*db_res)
    report.add(*redis_res)

    # ── 5. Required directories ───────────────────────────────────────
    required_dirs = ["logs", "logs/evidence", "data", "rules", "static"]
    for d in required_dirs:
        p = Path(d)
        try:
            p.mkdir(parents=True, exist_ok=True)
            # Test write permission
            test = p / ".write_test"
            test.touch()
            test.unlink()
            report.add(f"Dir:{d}", "PASS", "exists and writable")
        except Exception as e:
            report.add(f"Dir:{d}", "FAIL" if is_prod else "WARN", str(e))

    # ── 6. YARA rules ─────────────────────────────────────────────────
    yar_files = list(Path("rules").glob("*.yar"))
    if yar_files:
        report.add("YARAFiles", "PASS", f"{len(yar_files)} rule file(s) found")
    else:
        report.add("YARAFiles", "WARN", "No .yar files in rules/ — YARA scanning disabled")

    # ── 7. GeoIP database ─────────────────────────────────────────────
    geoip_path = os.environ.get("GEOIP_DB_PATH", "data/GeoLite2-City.mmdb")
    if Path(geoip_path).exists():
        report.add("GeoIPDB", "PASS", f"Found: {geoip_path}")
    else:
        report.add("GeoIPDB", "WARN",
                   "GeoLite2-City.mmdb missing — geo enrichment disabled. "
                   "Download from maxmind.com and set GEOIP_DB_PATH")

    # ── 8. Evidence encryption ────────────────────────────────────────
    enc_key = os.environ.get("EVIDENCE_ENCRYPTION_KEY", "")
    if enc_key:
        try:
            from cryptography.fernet import Fernet
            Fernet(enc_key.encode() if isinstance(enc_key, str) else enc_key)
            report.add("EvidenceKey", "PASS", "Valid Fernet key")
        except Exception as e:
            report.add("EvidenceKey", "FAIL" if is_prod else "WARN",
                       f"Invalid EVIDENCE_ENCRYPTION_KEY: {e}")
    else:
        report.add("EvidenceKey", "WARN",
                   "EVIDENCE_ENCRYPTION_KEY not set — auto-generated (not persistent)")

    # ── 9. LLM provider — OpenRouter is primary ──────────────────────
    llm_keys = [
        os.environ.get("OPENROUTER_API_KEY", ""),   # PRIMARY — required
        os.environ.get("ANTHROPIC_API_KEY", ""),    # legacy fallback
        os.environ.get("OPENAI_API_KEY", ""),
        os.environ.get("GROQ_API_KEY", ""),
        os.environ.get("GOOGLE_API_KEY", ""),
        os.environ.get("LLAMA_MODEL_PATH", ""),
    ]
    if os.environ.get("OPENROUTER_API_KEY", "").strip():
        report.add("LLMProvider", "PASS", "OpenRouter API key configured — all AI features active")
    elif any(k.strip() for k in llm_keys[1:]):
        report.add("LLMProvider", "WARN",
                   "No OPENROUTER_API_KEY — legacy provider detected but AI agent will not work. "
                   "Add OPENROUTER_API_KEY to .env: https://openrouter.ai/keys")
    else:
        report.add("LLMProvider", "WARN",
                   "No LLM keys set — AI features disabled. "
                   "Add OPENROUTER_API_KEY to .env: https://openrouter.ai/keys")

    # ── 10. SECRET_KEY security ───────────────────────────────────────
    sk = os.environ.get("SECRET_KEY", "")
    if len(sk) >= 64:
        report.add("SecretKey", "PASS", "Meets minimum length (≥64 chars)")
    elif sk:
        level = "FAIL" if is_prod else "WARN"
        report.add("SecretKey", level, f"Secret key too short ({len(sk)} chars, need ≥64)")
    else:
        report.add("SecretKey", "WARN", "SECRET_KEY not set — auto-generated")

    # ── 11. Source file encoding (BOM prevention) — result from parallel check ──
    report.add(*bom_res)

    # ── Print and check for fatal failures ───────────────────────────
    report.print_summary()

    if is_prod and report.failures > 0:
        logger.error(
            f"🚫 {report.failures} startup check(s) FAILED in production. "
            "Cannot start. Fix errors above and restart."
        )
        sys.exit(1)

    return report


def _mask_url(url: str) -> str:
    """Mask password in database/redis URL for logging."""
    import re
    return re.sub(r"(:)[^:@]+(@)", r"\1***\2", url)
