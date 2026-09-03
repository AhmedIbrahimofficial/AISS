"""AISS - Security Configuration & Secret Management
Centralises all security-sensitive config with:
  - Auto-generation of missing keys on first startup
  - Startup validation that blocks launch if required keys are absent
  - Persistent key storage in data/secrets.json (gitignored)
  - Clear logging of which keys are generated vs loaded

Usage:
    from core.security_config import security_config
    await security_config.validate()    # call in lifespan startup
    key = security_config.secret_key    # access resolved values
"""

import json
import os
import secrets
import sys
from pathlib import Path
from typing import Optional

from utils.logger import setup_logger

logger = setup_logger("security_config")

_SECRETS_FILE = Path("data/secrets.json")
_SECRETS_FILE.parent.mkdir(exist_ok=True)


def _generate_secret_key() -> str:
    return secrets.token_hex(64)


def _generate_fernet_key() -> str:
    from cryptography.fernet import Fernet
    return Fernet.generate_key().decode()


class SecurityConfig:
    """
    Resolves all security-critical config values.

    Priority: .env variable → data/secrets.json → auto-generate
    Auto-generated keys are saved to data/secrets.json so they
    survive restarts in dev. In production always set explicit .env values.
    """

    def __init__(self):
        self._secrets: dict = self._load_secrets_file()
        self._resolved: dict = {}

    # ── Persistent secrets file (dev convenience) ─────────────────────

    def _load_secrets_file(self) -> dict:
        if _SECRETS_FILE.exists():
            try:
                return json.loads(_SECRETS_FILE.read_text())
            except Exception:
                pass
        return {}

    def _save_secrets_file(self) -> None:
        try:
            _SECRETS_FILE.write_text(json.dumps(self._secrets, indent=2))
            # Restrict permissions on Unix
            try:
                _SECRETS_FILE.chmod(0o600)
            except Exception:
                pass
        except Exception as e:
            logger.warning(f"Could not save secrets file: {e}")

    def _resolve(self, env_key: str, generator=None, required=False) -> Optional[str]:
        """
        Resolve a secret value.
        1. Check env var
        2. Check secrets.json
        3. Auto-generate if generator provided
        4. Error if required and still missing
        """
        val = os.environ.get(env_key, "").strip()
        if val:
            return val

        val = self._secrets.get(env_key, "")
        if val:
            os.environ[env_key] = val   # inject back so other modules see it
            return val

        if generator:
            val = generator()
            self._secrets[env_key] = val
            os.environ[env_key] = val
            self._save_secrets_file()
            logger.warning(
                f"⚠  Auto-generated {env_key} — add to .env for production: "
                f"{env_key}={val[:20]}..."
            )
            return val

        if required:
            return None
        return ""

    # ── Public properties ─────────────────────────────────────────────

    @property
    def secret_key(self) -> str:
        return self._resolved.get("SECRET_KEY", "")

    @property
    def evidence_encryption_key(self) -> str:
        return self._resolved.get("EVIDENCE_ENCRYPTION_KEY", "")

    @property
    def internal_service_token(self) -> str:
        return self._resolved.get("INTERNAL_SERVICE_TOKEN", "")

    # ── Startup validation ────────────────────────────────────────────

    async def validate(self) -> None:
        """
        Called at app startup.
        - Resolves all keys (generating where needed)
        - Validates required keys are present
        - Warns about insecure defaults
        - Blocks startup in production if critical keys are missing
        """
        env = os.environ.get("ENVIRONMENT", "development").lower()
        is_production = env == "production"

        errors = []
        warnings = []

        # ── Critical keys — auto-generate if missing ──────────────────
        self._resolved["SECRET_KEY"] = self._resolve(
            "SECRET_KEY", generator=_generate_secret_key
        )
        self._resolved["EVIDENCE_ENCRYPTION_KEY"] = self._resolve(
            "EVIDENCE_ENCRYPTION_KEY", generator=_generate_fernet_key
        )
        self._resolved["INTERNAL_SERVICE_TOKEN"] = self._resolve(
            "INTERNAL_SERVICE_TOKEN", generator=lambda: secrets.token_hex(32)
        )

        # ── Validate SECRET_KEY is not an insecure default ────────────
        bad_keys = {
            "change-this-in-production",
            "change-this-in-production-please",
            "change-this-to-a-random-secret-key",
            "dev-change-this-in-production",
            "secret",
            "your-secret-key",
        }
        sk = self._resolved["SECRET_KEY"].lower()
        if any(bad in sk for bad in bad_keys):
            msg = "SECRET_KEY is set to an insecure default value"
            if is_production:
                errors.append(msg)
            else:
                warnings.append(msg)

        # ── Production-required checks ────────────────────────────────
        if is_production:
            required_for_prod = [
                ("DATABASE_URL", "Database must be configured for production"),
                ("ALLOWED_ORIGINS", "CORS origins must be explicitly set for production"),
            ]
            for key, msg in required_for_prod:
                if not os.environ.get(key, "").strip():
                    errors.append(f"{msg} ({key})")

            # Warn about localhost database in production
            db_url = os.environ.get("DATABASE_URL", "")
            if "sqlite" in db_url.lower():
                warnings.append(
                    "SQLite is not recommended for production. "
                    "Use MySQL or PostgreSQL (set DATABASE_URL)."
                )

        # ── Warn about missing optional services ──────────────────────
        optional_checks = [
            ("OPENROUTER_API_KEY", "AI features disabled — add OPENROUTER_API_KEY to .env (https://openrouter.ai/keys)"),
            ("VIRUSTOTAL_API_KEY",  "VirusTotal threat enrichment disabled"),
            ("SHODAN_API_KEY",      "Shodan IP enrichment disabled"),
            ("APPRISE_URLS",        "Multi-channel alerts disabled"),
            ("GEOIP_DB_PATH",       "GeoIP lookups disabled — download GeoLite2-City.mmdb from MaxMind"),
        ]
        for key, msg in optional_checks:
            if not os.environ.get(key, "").strip():
                logger.debug(f"Optional: {msg}")

        # ── Report ────────────────────────────────────────────────────
        for w in warnings:
            logger.warning(f"⚠  Security warning: {w}")

        if errors:
            for e in errors:
                logger.error(f"🚫 Security config error: {e}")
            logger.error(
                "🚫 AISS cannot start in PRODUCTION with the above errors. "
                "Fix your .env configuration and restart."
            )
            sys.exit(1)

        logger.info(
            f"✅ Security config validated "
            f"[env={env}] "
            f"[{len(warnings)} warning(s), {len(errors)} error(s)]"
        )


# Singleton
security_config = SecurityConfig()
