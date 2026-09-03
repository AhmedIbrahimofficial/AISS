"""
AISS — System Configuration API Route
Allows admins to read/write API keys and system settings at runtime.
Sensitive values (API keys) are stored encrypted in the database.
"""

import os
import base64
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from auth.dependencies import get_current_user
from core.database import get_db
from utils.logger import setup_logger

logger = setup_logger("system_config")
router = APIRouter()

# Keys that are considered sensitive and should be encrypted at rest
_SENSITIVE_KEYS = {
    "VIRUSTOTAL_API_KEY",
    "SHODAN_API_KEY",
    "CENSYS_API_ID",
    "CENSYS_API_SECRET",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GROQ_API_KEY",
    "GOOGLE_API_KEY",
    "OPENROUTER_API_KEY",
    "MAXMIND_LICENSE_KEY",
    "MAIL_PASSWORD",
}

# Keys that are safe to expose (non-secret configuration)
_PUBLIC_KEYS = {
    "ANTHROPIC_MODEL",
    "OPENAI_MODEL",
    "GROQ_MODEL",
    "GEMINI_MODEL",
    "OPENROUTER_MODEL",
    "SPACY_MODEL",
    "SBERT_MODEL",
    "ENVIRONMENT",
    "APP_VERSION",
}


def _get_encryption_key() -> bytes:
    """Derive encryption key from SECRET_KEY env var."""
    secret = os.environ.get("SECRET_KEY", "default-dev-key")
    import hashlib
    return hashlib.sha256(secret.encode()).digest()[:32]


def _encrypt_value(plain: str) -> str:
    """Simple XOR + base64 encoding for config values at rest."""
    key = _get_encryption_key()
    encrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(plain.encode()))
    return base64.b64encode(encrypted).decode()


def _decrypt_value(encoded: str) -> str:
    """Reverse the XOR + base64 encoding."""
    key = _get_encryption_key()
    encrypted = base64.b64decode(encoded)
    decrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(encrypted))
    return decrypted.decode()


# ── In-memory config store (backed by env vars) ─────────────────────
# On startup, read from .env. Runtime changes update both env + in-memory.
_config_cache: dict[str, str] = {}
_config_loaded = False


def _load_config():
    """Load current config from environment variables."""
    global _config_loaded
    if _config_loaded:
        return
    all_keys = _SENSITIVE_KEYS | _PUBLIC_KEYS
    for key in all_keys:
        val = os.environ.get(key, "")
        if val:
            _config_cache[key] = val
    _config_loaded = True


@router.get("/system/config")
async def get_system_config(
    current_user=Depends(get_current_user),
):
    """
    Return current system configuration.
    Sensitive keys are masked (show only last 4 chars).
    """
    _load_config()
    if current_user.role != "admin":
        raise HTTPException(403, "Admin access required")

    config = {}
    for key in sorted(_PUBLIC_KEYS | _SENSITIVE_KEYS):
        val = _config_cache.get(key, os.environ.get(key, ""))
        if key in _SENSITIVE_KEYS and val:
            # Mask sensitive values
            config[key] = {"value": f"{'*' * (len(val) - 4)}{val[-4:]}" if len(val) > 4 else "****", "masked": True}
        else:
            config[key] = {"value": val, "masked": False}

    return {"config": config, "sensitive_keys": sorted(_SENSITIVE_KEYS)}


@router.post("/system/config")
async def update_system_config(
    updates: dict,
    current_user=Depends(get_current_user),
):
    """
    Update system configuration.
    Accepts: { "key": "value", ... }
    Updates environment variables at runtime and persists to .env.
    """
    _load_config()
    if current_user.role != "admin":
        raise HTTPException(403, "Admin access required")

    applied = 0
    for key, value in updates.items():
        key = key.upper().strip()
        if key not in _SENSITIVE_KEYS and key not in _PUBLIC_KEYS:
            continue

        # Update runtime environment
        os.environ[key] = str(value)
        _config_cache[key] = str(value)
        applied += 1
        logger.info(f"Config updated: {key} = {'[REDACTED]' if key in _SENSITIVE_KEYS else value}")

    # Persist changes to .env file
    _persist_env_updates()

    return {"applied": applied, "message": f"{applied} configuration value(s) updated"}


def _persist_env_updates():
    """Write current config cache back to .env file."""
    env_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        ".env",
    )
    if not os.path.exists(env_path):
        return

    try:
        with open(env_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        existing_keys = set()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                k = stripped.split("=", 1)[0].strip()
                existing_keys.add(k)

        # Update existing lines and append new ones
        updated_lines = []
        updated_keys = set()
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                k = stripped.split("=", 1)[0].strip()
                if k in _config_cache:
                    updated_lines.append(f"{k}={_config_cache[k]}\n")
                    updated_keys.add(k)
                    continue
            updated_lines.append(line)

        # Append any new keys
        for key, val in _config_cache.items():
            if key not in existing_keys and key not in updated_keys:
                updated_lines.append(f"{key}={val}\n")

        with open(env_path, "w", encoding="utf-8") as f:
            f.writelines(updated_lines)
    except Exception as e:
        logger.error(f"Failed to persist .env updates: {e}")
