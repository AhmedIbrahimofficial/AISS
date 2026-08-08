"""AISS - OAuth Helper (Authlib)
Provides OAuth2/OIDC client utilities for social login integration.

Supports: Google, GitHub, Microsoft, generic OIDC providers.
All credentials read from environment variables.

Usage:
    from utils.oauth_helper import oauth_helper
    auth_url = oauth_helper.get_auth_url("google", redirect_uri="http://localhost:3000/callback")
    token    = await oauth_helper.exchange_code("google", code, redirect_uri=...)
    profile  = await oauth_helper.get_profile("google", access_token)
"""
import os
from typing import Optional
from utils.logger import setup_logger

logger = setup_logger("oauth_helper")

# Provider config: {name → {client_id_env, client_secret_env, authorize_url, token_url, userinfo_url}}
_PROVIDERS: dict[str, dict] = {
    "google": {
        "client_id":     os.environ.get("GOOGLE_OAUTH_CLIENT_ID", ""),
        "client_secret": os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET", ""),
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url":     "https://oauth2.googleapis.com/token",
        "userinfo_url":  "https://openidconnect.googleapis.com/v1/userinfo",
        "scope":         "openid email profile",
    },
    "github": {
        "client_id":     os.environ.get("GITHUB_OAUTH_CLIENT_ID", ""),
        "client_secret": os.environ.get("GITHUB_OAUTH_CLIENT_SECRET", ""),
        "authorize_url": "https://github.com/login/oauth/authorize",
        "token_url":     "https://github.com/login/oauth/access_token",
        "userinfo_url":  "https://api.github.com/user",
        "scope":         "read:user user:email",
    },
    "microsoft": {
        "client_id":     os.environ.get("MICROSOFT_OAUTH_CLIENT_ID", ""),
        "client_secret": os.environ.get("MICROSOFT_OAUTH_CLIENT_SECRET", ""),
        "authorize_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token_url":     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "userinfo_url":  "https://graph.microsoft.com/v1.0/me",
        "scope":         "openid email profile",
    },
}


class OAuthHelper:
    """
    Authlib-based OAuth2 client. Lazy-loads Authlib on first use.
    Gracefully returns errors when credentials are not configured.
    """

    def __init__(self):
        self._authlib = None
        self._tried   = False

    def _lazy_init(self) -> bool:
        if self._tried:
            return self._authlib is not None
        self._tried = True
        try:
            from authlib.integrations.httpx_client import AsyncOAuth2Client
            self._authlib = AsyncOAuth2Client
            logger.info("✅ OAuthHelper: Authlib loaded")
            return True
        except ImportError:
            logger.debug("Authlib not installed — OAuth helper disabled")
            return False

    def get_auth_url(
        self,
        provider: str,
        redirect_uri: str,
        state: Optional[str] = None,
    ) -> Optional[str]:
        """Build the OAuth2 authorization URL for a provider."""
        if not self._lazy_init():
            return None
        cfg = _PROVIDERS.get(provider)
        if not cfg or not cfg.get("client_id"):
            logger.warning(f"OAuth provider '{provider}' not configured")
            return None
        try:
            client = self._authlib(
                client_id=cfg["client_id"],
                redirect_uri=redirect_uri,
            )
            url, _ = client.create_authorization_url(
                cfg["authorize_url"],
                scope=cfg.get("scope", "openid email profile"),
                state=state,
            )
            return url
        except Exception as e:
            logger.error(f"OAuth URL generation failed: {e}")
            return None

    async def exchange_code(
        self,
        provider: str,
        code: str,
        redirect_uri: str,
    ) -> Optional[dict]:
        """Exchange authorization code for access token."""
        if not self._lazy_init():
            return None
        cfg = _PROVIDERS.get(provider)
        if not cfg or not cfg.get("client_id"):
            return None
        try:
            async with self._authlib(
                client_id=cfg["client_id"],
                client_secret=cfg["client_secret"],
                redirect_uri=redirect_uri,
            ) as client:
                token = await client.fetch_token(
                    cfg["token_url"],
                    code=code,
                    redirect_uri=redirect_uri,
                )
            return dict(token)
        except Exception as e:
            logger.error(f"OAuth code exchange failed ({provider}): {e}")
            return None

    async def get_profile(
        self,
        provider: str,
        access_token: str,
    ) -> Optional[dict]:
        """Fetch user profile from OAuth provider."""
        if not self._lazy_init():
            return None
        cfg = _PROVIDERS.get(provider)
        if not cfg:
            return None
        try:
            import httpx
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    cfg["userinfo_url"],
                    headers={"Authorization": f"Bearer {access_token}"},
                    timeout=10,
                )
                resp.raise_for_status()
                return resp.json()
        except Exception as e:
            logger.error(f"OAuth profile fetch failed ({provider}): {e}")
            return None

    def configured_providers(self) -> list[str]:
        """Return list of providers with client_id configured."""
        return [
            name for name, cfg in _PROVIDERS.items()
            if cfg.get("client_id")
        ]

    def is_available(self) -> bool:
        return self._lazy_init()


# Singleton
oauth_helper = OAuthHelper()
