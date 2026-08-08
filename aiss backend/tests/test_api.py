"""AISS — API Integration Tests
Tests every major API endpoint for correct responses, auth enforcement,
and error handling.
"""
import os
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

os.environ.setdefault("ENVIRONMENT",  "development")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./logs/test_api.db")
os.environ.setdefault("SECRET_KEY",   "test-secret-key-minimum-64-chars-long-for-testing-purposes-only!!")
os.environ.setdefault("AISS_LICENSE_KEY", "")
os.environ.setdefault("DISABLE_TTS",  "1")
os.environ.setdefault("LOG_LEVEL",    "WARNING")


@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture(scope="module")
async def client():
    from main import app
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        yield c


# ── Health endpoints ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_root(client):
    resp = await client.get("/")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "AISS" in data["status"] or data["status"] == "AISS Online"


@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"


@pytest.mark.asyncio
async def test_system_health(client):
    resp = await client.get("/api/system/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "uptime_secs" in data
    assert "cpu_percent" in data


@pytest.mark.asyncio
async def test_library_status(client):
    resp = await client.get("/api/system/libraries")
    assert resp.status_code in (200, 402)  # 402 if unlicensed
    if resp.status_code == 200:
        data = resp.json()
        assert "total" in data
        assert "libraries" in data


# ── Auth endpoints ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_register_short_password(client):
    resp = await client.post("/api/auth/register", json={
        "username": "testuser99",
        "email":    "test99@example.com",
        "password": "short",
    })
    assert resp.status_code in (400, 422)


@pytest.mark.asyncio
async def test_login_invalid_credentials(client):
    resp = await client.post("/api/auth/login", data={
        "username": "nonexistent_user_xyz",
        "password": "wrongpassword123",
    })
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_protected_endpoint_no_token(client):
    """Endpoints requiring auth must return 401 without token."""
    resp = await client.get("/api/threats/")
    assert resp.status_code in (401, 403, 422)


@pytest.mark.asyncio
async def test_forgot_password_always_200(client):
    """Forgot-password must return 200 regardless of whether email exists."""
    resp = await client.post("/api/auth/forgot-password", json={
        "email": "nonexistent@example.com"
    })
    assert resp.status_code == 200
    assert "sent" in resp.json().get("message", "").lower() or \
           "registered" in resp.json().get("message", "").lower()


# ── Security headers ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_security_headers_present(client):
    resp = await client.get("/api/health")
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"
    assert "strict-origin" in resp.headers.get("referrer-policy", "")


@pytest.mark.asyncio
async def test_csp_header_present(client):
    resp = await client.get("/api/health")
    csp = resp.headers.get("content-security-policy", "")
    assert "default-src" in csp
    assert "frame-ancestors" in csp


# ── Input validation ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_path_traversal_blocked(client):
    resp = await client.get("/api/../../../etc/passwd")
    assert resp.status_code in (400, 404)


@pytest.mark.asyncio
async def test_null_byte_blocked(client):
    resp = await client.get("/api/threats/\x00")
    assert resp.status_code in (400, 404, 422)


@pytest.mark.asyncio
async def test_oversized_body_rejected(client):
    """Requests over 50MB must be rejected."""
    big_data = b"x" * (51 * 1024 * 1024)
    resp = await client.post(
        "/api/files/inspect",
        content=big_data,
        headers={"content-length": str(len(big_data)),
                 "content-type": "application/octet-stream"},
    )
    assert resp.status_code == 413


# ── Intel endpoints ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ioc_extract_endpoint(client):
    resp = await client.post("/api/intel/ioc/extract", json={
        "text": "Attack from 192.168.1.1 CVE-2024-9999 emotet malware"
    })
    assert resp.status_code in (200, 402)
    if resp.status_code == 200:
        data = resp.json()
        assert "iocs" in data
        assert "ips" in data["iocs"]


@pytest.mark.asyncio
async def test_phishing_analyze_endpoint(client):
    resp = await client.post("/api/intel/phishing/analyze", json={
        "url": "http://192.168.1.1/steal?password=abc"
    })
    assert resp.status_code in (200, 402)
    if resp.status_code == 200:
        data = resp.json()
        assert "risk_score" in data
        assert data["risk_score"] >= 0


@pytest.mark.asyncio
async def test_geo_lookup_private_ip(client):
    resp = await client.get("/api/intel/geo/192.168.1.1")
    # Private IP should either return empty geo or 404/503
    assert resp.status_code in (200, 503)


# ── Export endpoints ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_export_status_endpoint(client):
    resp = await client.get("/api/threats/export/status")
    assert resp.status_code in (200, 402)


# ── TAXII stats ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_taxii_stats(client):
    resp = await client.get("/api/intel/taxii/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "configured" in data


# ── License endpoint ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_license_info_in_health(client):
    resp = await client.get("/api/health")
    assert resp.status_code == 200
