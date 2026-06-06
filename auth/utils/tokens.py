"""
JWT access tokens + opaque refresh token generation.

Access token  — short-lived JWT (15–30 min), signed with HS256
Refresh token — cryptographically random 64-byte hex string stored
                as Argon2id hash in the sessions table (rotation on use)
"""

import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt

from utils.logger import setup_logger

logger = setup_logger("auth.tokens")

# ── Config (from .env) ────────────────────────────────────────────────
SECRET_KEY              = os.environ.get("SECRET_KEY", "change-me-in-production")
ALGORITHM               = "HS256"
ACCESS_TOKEN_EXPIRE_MIN = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.environ.get("REFRESH_TOKEN_EXPIRE_DAYS", "30"))


# ── Access token ──────────────────────────────────────────────────────

def create_access_token(
    user_id: str,
    email: str,
    role: str,
    extra: dict | None = None,
) -> str:
    """
    Create a signed JWT access token.
    Payload: sub, email, role, iat, exp, jti
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub":   user_id,
        "email": email,
        "role":  role,
        "iat":   now,
        "exp":   now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MIN),
        "jti":   secrets.token_hex(16),   # unique token ID
        **(extra or {}),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    """
    Decode and validate a JWT.
    Raises JWTError on invalid/expired token.
    """
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


# ── Refresh token ─────────────────────────────────────────────────────

def generate_refresh_token() -> str:
    """Generate a cryptographically secure opaque refresh token (128 hex chars)."""
    return secrets.token_hex(64)


def hash_refresh_token(token: str) -> str:
    """
    SHA-256 hash of the refresh token for DB storage.
    We use SHA-256 here (not Argon2) because:
      - Refresh tokens are already high-entropy random strings
      - We need fast lookup on every /auth/refresh call
      - Argon2 is for low-entropy user passwords
    """
    return hashlib.sha256(token.encode()).hexdigest()


def refresh_token_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)


# ── Verification / OTP tokens ─────────────────────────────────────────

def generate_verification_token() -> str:
    """URL-safe 48-byte random token for email verification."""
    return secrets.token_urlsafe(48)


def generate_otp() -> str:
    """Cryptographically secure 6-digit OTP (no sequential bias)."""
    return str(secrets.randbelow(900000) + 100000)


def hash_otp(otp: str) -> str:
    """SHA-256 hash for OTP storage."""
    return hashlib.sha256(otp.encode()).hexdigest()
