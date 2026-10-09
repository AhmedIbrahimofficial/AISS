"""
AISS — OAuth social login routes
Handles Google and GitHub OAuth2 flows end-to-end.

SECURITY FIX: Instead of putting tokens in the URL fragment
(visible in browser history, logs, referrer headers), we now:
  1. Exchange the OAuth code on the backend.
  2. Store the resulting AISS tokens server-side in a short-lived,
     one-time-use exchange record (in-memory, TTL 60s).
  3. Redirect the frontend to /oauth-callback?code=<one-time-code>
  4. Frontend calls POST /api/auth/oauth/exchange with that code
     to get the real tokens over a JSON response body.

This keeps tokens out of URLs, fragments, and server-access logs.
"""
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from core.database import get_db
from auth.models import AuthUser, AuthSession, AuthOnboarding
from auth.utils.tokens import (
    create_access_token, generate_refresh_token,
    hash_refresh_token, refresh_token_expiry,
)
from utils.oauth_helper import oauth_helper
from utils.logger import setup_logger

logger = setup_logger("oauth.routes")

router = APIRouter(prefix="/auth/oauth", tags=["OAuth"])

FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:5173")

# Environment-specific OAuth redirect URI override.
# When the backend is behind a reverse proxy, the auto-detected request.base_url
# may not match the public URL.  Set GOOGLE_OAUTH_REDIRECT_URI (or per-provider)
# in .env to force the correct callback URL.
_OAUTH_REDIRECT_OVERRIDES: dict[str, str] = {}
for _prov in ("google", "github", "microsoft"):
    _env_key = f"{_prov.upper()}_OAUTH_REDIRECT_URI"
    _val = os.environ.get(_env_key, "").strip()
    if _val:
        _OAUTH_REDIRECT_OVERRIDES[_prov] = _val

# ── CSRF state store (in-memory; swap for Redis in prod multi-instance) ──
_oauth_states: dict[str, dict] = {}

# ── One-time exchange codes (TTL 60 s; single-use) ────────────────────
# Maps exchange_code → {access_token, refresh_token, onboarding_done, expires}
_exchange_codes: dict[str, dict] = {}


def _clean_states() -> None:
    """Remove expired OAuth CSRF states."""
    now = datetime.now(timezone.utc).timestamp()
    expired = [k for k, v in _oauth_states.items() if v.get("expires", 0) < now]
    for k in expired:
        del _oauth_states[k]


def _clean_exchange_codes() -> None:
    """Remove expired one-time exchange codes."""
    now = datetime.now(timezone.utc).timestamp()
    expired = [k for k, v in _exchange_codes.items() if v.get("expires", 0) < now]
    for k in expired:
        del _exchange_codes[k]


# ── GET /auth/oauth/{provider} — redirect to OAuth provider ──────────
@router.get("/{provider}")
async def oauth_redirect(provider: str, request: Request):
    if provider not in ("google", "github"):
        raise HTTPException(400, f"Unsupported provider: {provider}")

    if not oauth_helper.is_available():
        raise HTTPException(503, "OAuth not available — authlib not installed")

    configured = oauth_helper.configured_providers()
    if provider not in configured:
        raise HTTPException(
            503,
            f"{provider.capitalize()} OAuth not configured — "
            f"set {provider.upper()}_OAUTH_CLIENT_ID and "
            f"{provider.upper()}_OAUTH_CLIENT_SECRET in .env"
        )

    state = secrets.token_urlsafe(32)
    _clean_states()
    _oauth_states[state] = {
        "provider": provider,
        "expires":  (datetime.now(timezone.utc) + timedelta(minutes=10)).timestamp(),
    }

    redirect_uri = _OAUTH_REDIRECT_OVERRIDES.get(
        provider, f"{request.base_url}api/auth/oauth/{provider}/callback"
    )
    auth_url = oauth_helper.get_auth_url(provider, redirect_uri=redirect_uri, state=state)
    if not auth_url:
        raise HTTPException(500, "Failed to generate OAuth authorization URL")

    return RedirectResponse(auth_url)


# ── GET /auth/oauth/{provider}/callback — handle OAuth callback ───────
@router.get("/{provider}/callback")
async def oauth_callback(
    provider: str,
    code: str,
    state: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    # ── 1. Validate CSRF state ─────────────────────────────────────────
    stored = _oauth_states.pop(state, None)
    if not stored or stored.get("provider") != provider:
        logger.warning(f"OAuth callback: invalid state for {provider} from {request.client}")
        raise HTTPException(400, "Invalid or expired OAuth state. Please try again.")

    if stored.get("expires", 0) < datetime.now(timezone.utc).timestamp():
        raise HTTPException(400, "OAuth state expired — please try the login again")

    # ── 2. Exchange code for provider access token ─────────────────────
    redirect_uri = _OAUTH_REDIRECT_OVERRIDES.get(
        provider, f"{request.base_url}api/auth/oauth/{provider}/callback"
    )
    token_data = await oauth_helper.exchange_code(provider, code, redirect_uri)
    if not token_data:
        raise HTTPException(502, f"Failed to exchange authorization code with {provider}")

    # ── 3. Fetch user profile ──────────────────────────────────────────
    access_token = token_data.get("access_token", "")
    profile = await oauth_helper.get_profile(provider, access_token)
    if not profile:
        raise HTTPException(502, f"Failed to fetch profile from {provider}")

    # ── 4. Normalise provider-specific fields ──────────────────────────
    if provider == "google":
        email      = profile.get("email", "").lower()
        name       = profile.get("name", email.split("@")[0])
        subject    = profile.get("sub", "")
        avatar_url = profile.get("picture", "")
        # Verify email_verified claim if present (Google OIDC)
        if profile.get("email_verified") is False:
            raise HTTPException(400, "Your Google account email is not verified. Please verify it first.")
    else:  # github
        email      = (profile.get("email") or "").lower()
        name       = profile.get("login", "") or profile.get("name", "")
        subject    = str(profile.get("id", ""))
        avatar_url = profile.get("avatar_url", "")

    if not email:
        raise HTTPException(
            400,
            f"{provider.capitalize()} account has no public email address. "
            "Please add a verified email to your account and try again."
        )

    # ── 5. Find or create AISS user ────────────────────────────────────
    user = await db.scalar(
        select(AuthUser).where(AuthUser.email == email)
    )

    if not user:
        # New user — create account from OAuth
        import re
        base_username = re.sub(r"[^a-z0-9_]", "", name.lower().replace(" ", "_"))[:30] or "user"
        username = base_username
        # Ensure unique username
        attempt = 0
        while await db.scalar(select(AuthUser).where(AuthUser.username == username)):
            attempt += 1
            username = f"{base_username}{attempt}"

        user = AuthUser(
            username        = username,
            email           = email,
            hashed_password = "",          # no password for OAuth-only users
            role            = "viewer",
            is_active       = True,
            is_verified     = True,        # email verified by OAuth provider
            oauth_provider  = provider,
            oauth_subject   = subject,
            avatar_url      = avatar_url,
        )
        db.add(user)
        await db.flush()

        # Create onboarding record
        onboarding = AuthOnboarding(user_id=user.id)
        db.add(onboarding)
        logger.info(f"New OAuth user created: {email} via {provider}")
    else:
        # Existing user — update OAuth fields + last login
        user.oauth_provider = provider
        user.oauth_subject  = subject
        user.avatar_url     = avatar_url
        user.last_login_at  = datetime.utcnow()
        user.last_login_ip  = request.client.host if request.client else ""

        # Ensure onboarding record exists
        if not user.onboarding:
            db.add(AuthOnboarding(user_id=user.id))
        logger.info(f"Existing user OAuth login: {email} via {provider}")

    # ── 6. Create AISS session ─────────────────────────────────────────
    raw_refresh = generate_refresh_token()
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("User-Agent", "")
    session = AuthSession(
        user_id            = user.id,
        refresh_token_hash = hash_refresh_token(raw_refresh),
        ip_address         = ip,
        user_agent         = ua,
        device_info        = f"oauth-{provider}",
        expires_at         = refresh_token_expiry(),
    )
    db.add(session)
    await db.commit()

    aiss_access = create_access_token(user.id, user.email, user.role)
    onboarding_done = user.onboarding.is_completed if user.onboarding else False

    # ── 7. Issue a one-time exchange code (SECURE handoff) ────────────
    # Tokens never touch the URL — the frontend exchanges this short-lived
    # opaque code for the real tokens via POST /api/auth/oauth/exchange.
    exchange_code = secrets.token_urlsafe(32)
    _clean_exchange_codes()
    _exchange_codes[exchange_code] = {
        "access_token":    aiss_access,
        "refresh_token":   raw_refresh,
        "onboarding_done": onboarding_done,
        "expires": (datetime.now(timezone.utc) + timedelta(seconds=60)).timestamp(),
        "used": False,
    }

    # Redirect frontend to callback page with only the short-lived opaque code
    # — NOT with the actual tokens, so they never appear in URLs or logs.
    redirect = f"{FRONTEND_URL}/oauth-callback?code={exchange_code}"
    return RedirectResponse(redirect, status_code=302)


# ── POST /api/auth/oauth/exchange — redeem one-time code for tokens ───
@router.post("/exchange")
async def oauth_exchange(request: Request):
    """
    Redeem the one-time exchange code issued by the OAuth callback.
    Returns access_token + refresh_token in the JSON body (never in URL).
    Single-use: the code is deleted immediately after first use.
    """
    body = await request.json()
    code = body.get("code", "")

    if not code:
        raise HTTPException(400, "Missing exchange code")

    _clean_exchange_codes()
    record = _exchange_codes.get(code)

    if not record:
        logger.warning(f"OAuth exchange: unknown or expired code from {request.client}")
        raise HTTPException(400, "Invalid or expired exchange code. Please log in again.")

    if record.get("used"):
        # Possible replay attack — log and deny
        logger.warning(f"OAuth exchange: code reuse attempt from {request.client}")
        # Delete to prevent further attempts
        _exchange_codes.pop(code, None)
        raise HTTPException(400, "Exchange code already used. Please log in again.")

    if record.get("expires", 0) < datetime.now(timezone.utc).timestamp():
        _exchange_codes.pop(code, None)
        raise HTTPException(400, "Exchange code expired. Please log in again.")

    # Mark used and remove immediately (single-use)
    record["used"] = True
    _exchange_codes.pop(code, None)

    return JSONResponse({
        "access_token":    record["access_token"],
        "refresh_token":   record["refresh_token"],
        "onboarding_done": record["onboarding_done"],
        "token_type":      "bearer",
    })


# ── GET /api/auth/oauth/providers — list configured providers ─────────
@router.get("/providers")
async def list_providers():
    """Return which OAuth providers are currently configured."""
    configured = oauth_helper.configured_providers() if oauth_helper.is_available() else []
    return {
        "providers": configured,
        "available": oauth_helper.is_available(),
    }
