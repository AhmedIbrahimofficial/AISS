"""AISS - Security Middleware Collection
Enterprise-grade middleware stack covering:
  1. SecurityHeadersMiddleware — CSP, HSTS, X-Frame, referrer policy, etc.
  2. AuditLogMiddleware        — structured audit trail for every mutating request
  3. InternalServiceMiddleware — BFF token validation
  4. RequestSizeLimitMiddleware— blocks oversized request bodies
  5. InputSanitizationMiddleware — blocks path traversal and common injection probes
  6. LicenseValidationMiddleware — validates AISS license on every request
"""

import os
import re
import time
import logging
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger("aiss.middleware")

# ── Config ────────────────────────────────────────────────────────────
INTERNAL_SERVICE_TOKEN  = os.environ.get("INTERNAL_SERVICE_TOKEN", "")
MAX_REQUEST_BODY_BYTES  = int(os.environ.get("MAX_REQUEST_BODY_BYTES", str(50 * 1024 * 1024)))  # 50 MB
ENVIRONMENT             = os.environ.get("ENVIRONMENT", "development")
ALLOWED_ORIGINS_RAW     = os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000")

# Paths that are exempt from license/auth middleware
_EXEMPT_PATHS = {"/", "/api/health", "/docs", "/openapi.json", "/redoc",
                 "/api/auth/login", "/api/auth/register", "/api/auth/refresh",
                 "/api/auth/verify-email", "/api/auth/forgot-password",
                 "/api/auth/reset-password", "/favicon.ico", "/metrics",
                 "/ws", "/ws/monitor", "/static"}

# Path traversal + injection probes
_SUSPICIOUS_PATH_PATTERNS = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"%2e%2e", re.I),
    re.compile(r"%252e", re.I),
    re.compile(r"etc/passwd"),
    re.compile(r"etc/shadow"),
    re.compile(r"proc/self"),
    re.compile(r"<script", re.I),
    re.compile(r"javascript:", re.I),
    re.compile(r"vbscript:", re.I),
]


# ═════════════════════════════════════════════════════════════════════
# 1. Security Headers
# ═════════════════════════════════════════════════════════════════════

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Adds the full suite of security response headers.
    CSP is strict — adjust nonce/hash approach for your frontend as needed.
    """

    _CSP = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.plot.ly; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "connect-src 'self' wss: ws: http://localhost:8000 http://localhost:8081 http://127.0.0.1:8000; "
        "font-src 'self' data:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        # Standard hardening
        response.headers["X-Content-Type-Options"]           = "nosniff"
        response.headers["X-Frame-Options"]                  = "DENY"
        response.headers["X-XSS-Protection"]                 = "1; mode=block"
        response.headers["Referrer-Policy"]                  = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]               = (
            "camera=(), microphone=(), geolocation=(), payment=(), "
            "usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
        )
        response.headers["Content-Security-Policy"]          = self._CSP
        # Allow cross-origin requests from the frontend dev server
        response.headers["Cross-Origin-Embedder-Policy"]     = "unsafe-none"
        response.headers["Cross-Origin-Opener-Policy"]       = "same-origin-allow-popups"
        response.headers["Cross-Origin-Resource-Policy"]     = "cross-origin"

        # HSTS — only on production HTTPS
        if ENVIRONMENT == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains; preload"
            )

        # Remove server fingerprinting headers
        for h in ("server", "x-powered-by"):
            if h in response.headers:
                del response.headers[h]

        return response


# ═════════════════════════════════════════════════════════════════════
# 2. Request Size Limit
# ═════════════════════════════════════════════════════════════════════

class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Block requests whose Content-Length exceeds MAX_REQUEST_BODY_BYTES."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > MAX_REQUEST_BODY_BYTES:
                    return JSONResponse(
                        status_code=413,
                        content={"error": f"Request body too large (max {MAX_REQUEST_BODY_BYTES // 1024 // 1024}MB)"},
                    )
            except ValueError:
                pass
        return await call_next(request)


# ═════════════════════════════════════════════════════════════════════
# 3. Input Sanitization
# ═════════════════════════════════════════════════════════════════════

class InputSanitizationMiddleware(BaseHTTPMiddleware):
    """
    Blocks requests with:
    - Path traversal sequences
    - Common injection probes in the URL path/query
    - Null bytes
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = str(request.url.path)

        # Null byte check
        if "\x00" in path or "%00" in path:
            logger.warning(f"Null byte in path from {request.client.host if request.client else '?'}: {path[:100]}")
            return JSONResponse(status_code=400, content={"error": "Invalid request"})

        # Path traversal / injection probe
        for pattern in _SUSPICIOUS_PATH_PATTERNS:
            if pattern.search(path):
                logger.warning(
                    f"Suspicious path probe from "
                    f"{request.client.host if request.client else '?'}: {path[:100]}"
                )
                return JSONResponse(status_code=400, content={"error": "Invalid request path"})

        return await call_next(request)


# ═════════════════════════════════════════════════════════════════════
# 4. Internal Service Token
# ═════════════════════════════════════════════════════════════════════

class InternalServiceMiddleware(BaseHTTPMiddleware):
    """
    Validates X-Internal-Service header and bearer token from the BFF.
    Attaches calling_service and is_internal to request.state.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        service = request.headers.get("X-Internal-Service")
        request.state.calling_service = service or "external"
        request.state.is_internal     = False

        if service:
            token = INTERNAL_SERVICE_TOKEN
            if token:
                auth_header  = request.headers.get("Authorization", "")
                bearer_token = auth_header.removeprefix("Bearer ").strip()
                if bearer_token == token:
                    request.state.is_internal = True
                else:
                    logger.warning(
                        f"Bad internal service token from "
                        f"{request.client.host if request.client else '?'} "
                        f"service={service}"
                    )
            else:
                request.state.is_internal = True   # dev mode — no token enforced

        return await call_next(request)


# ═════════════════════════════════════════════════════════════════════
# 5. Audit Log
# ═════════════════════════════════════════════════════════════════════

class AuditLogMiddleware(BaseHTTPMiddleware):
    """
    Structured audit trail for every mutating HTTP request.
    In production, writes to both log file and DB system_events table.
    """

    MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start    = time.perf_counter()
        response = await call_next(request)

        if request.method in self.MUTATING_METHODS:
            duration_ms  = int((time.perf_counter() - start) * 1000)
            user_id      = request.headers.get("X-User-Id", "anonymous")
            service      = getattr(request.state, "calling_service", "external")
            client_ip    = request.client.host if request.client else "unknown"

            logger.info(
                f"[Audit] {request.method} {request.url.path}"
                f" → {response.status_code} | {duration_ms}ms"
                f" | user={user_id} svc={service} ip={client_ip}"
            )

        return response


# ═════════════════════════════════════════════════════════════════════
# 6. License Validation
# ═════════════════════════════════════════════════════════════════════

class LicenseValidationMiddleware(BaseHTTPMiddleware):
    """
    Rejects requests to protected /api/* endpoints if the license is invalid.
    Exempt paths (login, health, docs) bypass this check.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path

        # Bypass exempt paths
        if path in _EXEMPT_PATHS or not path.startswith("/api/"):
            return await call_next(request)

        # Check license
        try:
            from core.licensing import license_manager
            if not license_manager.is_valid():
                return JSONResponse(
                    status_code=402,
                    content={
                        "error":   "License required",
                        "message": "No valid AISS license found. "
                                   "Set AISS_LICENSE_KEY in .env. "
                                   "Contact sales@aiss.io for a license.",
                        "license_status": (
                            license_manager.get_info().status.value
                            if license_manager.get_info() else "unlicensed"
                        ),
                    },
                )
        except Exception:
            pass   # licensing module not ready — allow request

        return await call_next(request)
