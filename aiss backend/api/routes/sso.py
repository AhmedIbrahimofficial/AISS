"""
AISS — Secure SSO handoff between the website and the desktop dashboard.

Flow:
  1. Website user authenticates (password or Google OAuth).
  2. Website calls POST /api/sso/issue to get a short-lived SSO token.
     → Response: { "sso_token": "<opaque>", "expires_in": 30 }
  3. The AISS desktop launcher opens the dashboard URL with
     ?sso=<token> in the query string (or the website injects it).
  4. Dashboard calls POST /api/sso/redeem { "sso_token": "<opaque>" }
     → Response: { "access_token": "...", "refresh_token": "...", ... }
  5. Dashboard stores the tokens and is now authenticated — no
     second login required.

Security properties:
  - The SSO token is a 32-byte cryptographically random opaque value.
  - Single-use: redeemed tokens are deleted immediately.
  - Short-lived: 60-second expiry by default.
  - The actual JWT/refresh tokens are returned in the POST body,
    never in a URL or a redirect.
  - Rate-limited at issue and redeem endpoints.
  - Requires a valid AISS access token to *issue* an SSO token
    (prevents unauthenticated issuance).
"""
from __future__ import annotations

import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from auth.dependencies import get_current_user
from auth.utils.tokens import (
    create_access_token,
    generate_refresh_token,
    hash_refresh_token,
    refresh_token_expiry,
)
from auth.models import AuthSession
from core.database import get_db
from sqlalchemy.ext.asyncio import AsyncSession
from utils.logger import setup_logger

router  = APIRouter(prefix="/sso", tags=["SSO"])
limiter = Limiter(key_func=get_remote_address)
logger  = setup_logger("sso")

# In-memory token store — swap for Redis in multi-instance prod deployments
# Maps sso_token → {user_id, email, role, expires, used}
_sso_tokens: dict[str, dict] = {}

_SSO_TTL_SECONDS = int(os.environ.get("AISS_SSO_TTL", "60"))


def _clean() -> None:
    """Remove expired SSO tokens."""
    now = datetime.now(timezone.utc).timestamp()
    expired = [k for k, v in _sso_tokens.items() if v["expires"] < now]
    for k in expired:
        del _sso_tokens[k]


# ── POST /api/sso/issue ───────────────────────────────────────────────
@router.post("/issue")
@limiter.limit("10/minute")
async def issue_sso_token(
    request: Request,
    current_user: Any = Depends(get_current_user),
) -> dict:
    """
    Issue a one-time SSO handoff token for the authenticated user.
    The caller must already hold a valid AISS access token.

    Returns: { "sso_token": str, "expires_in": int }
    """
    _clean()
    token = secrets.token_urlsafe(32)
    _sso_tokens[token] = {
        "user_id": current_user.id,
        "email":   current_user.email,
        "role":    current_user.role,
        "expires": (
            datetime.now(timezone.utc) + timedelta(seconds=_SSO_TTL_SECONDS)
        ).timestamp(),
        "used": False,
        "issuer_ip": request.client.host if request.client else "unknown",
    }
    logger.info(
        f"SSO token issued for user {current_user.email} "
        f"(expires in {_SSO_TTL_SECONDS}s)"
    )
    return {"sso_token": token, "expires_in": _SSO_TTL_SECONDS}


# ── POST /api/sso/redeem ──────────────────────────────────────────────
@router.post("/redeem")
@limiter.limit("10/minute")
async def redeem_sso_token(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Redeem a one-time SSO handoff token.
    Returns full AISS JWT + refresh token — no second login required.

    Accepts: { "sso_token": str }
    Returns: { "access_token": str, "refresh_token": str, "expires_in": int, ... }
    """
    body = await request.json()
    sso_token = body.get("sso_token", "")

    if not sso_token:
        raise HTTPException(400, "Missing sso_token")

    _clean()
    record = _sso_tokens.get(sso_token)

    if not record:
        logger.warning(
            f"SSO redeem: unknown or expired token from {request.client}"
        )
        raise HTTPException(
            400, "Invalid or expired SSO token. Please authenticate on the website first."
        )

    if record.get("used"):
        # Potential replay attack
        logger.warning(
            f"SSO redeem: reuse attempt for user {record.get('email')} "
            f"from {request.client}"
        )
        _sso_tokens.pop(sso_token, None)
        raise HTTPException(400, "SSO token already used. Please authenticate again.")

    if record["expires"] < datetime.now(timezone.utc).timestamp():
        _sso_tokens.pop(sso_token, None)
        raise HTTPException(400, "SSO token expired. Please authenticate again.")

    # Mark as used and remove (single-use)
    record["used"] = True
    _sso_tokens.pop(sso_token, None)

    # Issue full AISS session
    from auth.models import AuthUser
    from sqlalchemy import select
    user = await db.scalar(
        select(AuthUser).where(AuthUser.id == record["user_id"])
    )
    if not user or not user.is_active:
        raise HTTPException(401, "User account not found or deactivated")

    raw_refresh = generate_refresh_token()
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("User-Agent", "")

    session = AuthSession(
        user_id            = user.id,
        refresh_token_hash = hash_refresh_token(raw_refresh),
        ip_address         = ip,
        user_agent         = ua,
        device_info        = "sso-desktop",
        expires_at         = refresh_token_expiry(),
    )
    db.add(session)
    await db.commit()

    access_token = create_access_token(user.id, user.email, user.role)

    logger.info(
        f"SSO token redeemed for user {user.email} from {ip}"
    )

    from auth.utils.tokens import ACCESS_TOKEN_EXPIRE_MIN
    return {
        "access_token":  access_token,
        "refresh_token": raw_refresh,
        "token_type":    "bearer",
        "expires_in":    ACCESS_TOKEN_EXPIRE_MIN * 60,
        "user": {
            "id":       user.id,
            "email":    user.email,
            "username": user.username,
            "role":     user.role,
        },
    }
