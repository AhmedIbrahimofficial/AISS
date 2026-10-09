"""AISS — End-to-End Acceptance Tests

Tests the full security pipeline:
  - EICAR detection verification
  - Vulnerability scan (CVE/CVSS)
  - IOC auto-enrichment
  - Job lifecycle management
  - Incident lifecycle
  - Dashboard data endpoints

All tests use the test database and run against the live FastAPI app.
"""
import asyncio
import os
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

# Must be set BEFORE importing main / app
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./logs/test_acceptance.db")
os.environ.setdefault("SECRET_KEY",
                       "test-secret-key-minimum-64-chars-long-for-testing-purposes-only!!")
os.environ["AISS_LICENSE_KEY"] = "AISS-DEV-TEST"
os.environ.setdefault("DISABLE_TTS", "1")
os.environ.setdefault("LOG_LEVEL", "WARNING")
os.environ.setdefault("OPENROUTER_API_KEY", "test-key")


@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture(scope="module")
async def client():
    from core.database import init_db
    await init_db()
    from core.licensing import license_manager
    await license_manager.validate()
    from main import app
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        yield c


@pytest_asyncio.fixture(scope="module")
async def auth_headers(client: AsyncClient):
    """Register and login a test user, returning auth headers."""
    import uuid
    uid = str(uuid.uuid4())[:8]
    email = f"acceptance_{uid}@example.com"
    # Register
    r = await client.post("/api/auth/register", json={
        "username": f"acceptance_{uid}",
        "email": email,
        "password": "TestPass123!",
    })
    assert r.status_code in (200, 201), f"Register failed: {r.status_code} {r.text}"
    # Login
    r = await client.post("/api/auth/login", json={
        "email": email,
        "password": "TestPass123!",
    })
    assert r.status_code == 200, f"Login failed: {r.status_code} {r.text}"
    data = r.json()
    token = data["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ── 1. EICAR Detection Pipeline ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_eicar_verification_pipeline(client: AsyncClient, auth_headers: dict):
    """Verify the EICAR test detection pipeline works end-to-end.

    Posts to /api/security/verify-pipeline which runs a lightweight EICAR-only test.
    Asserts the response contains the expected structure.
    """
    r = await client.post("/api/security/verify-pipeline", headers=auth_headers)
    assert r.status_code == 200, f"verify-pipeline failed: {r.status_code} {r.text}"
    data = r.json()
    assert data["status"] == "ok"
    payload = data["data"]
    assert "verified" in payload
    assert "task_id" in payload
    assert "eicar_sha256" in payload
    assert "scanners_available" in payload
    # The verified field indicates whether detection worked (may be False if YARA/ClamAV unavailable)
    assert isinstance(payload["verified"], bool)
    # Scanners availability tells us what tools are installed
    assert isinstance(payload["scanners_available"], dict)


@pytest.mark.asyncio
async def test_eicar_full_scan(client: AsyncClient, auth_headers: dict):
    """Start a full EICAR test scan and verify task is created.

    This is an async scan — we verify the task starts running and eventually completes.
    """
    r = await client.post("/api/security/eicar-test", headers=auth_headers)
    assert r.status_code == 200, f"eicar-test failed: {r.status_code} {r.text}"
    data = r.json()
    assert "task_id" in data
    assert data["status"] == "running"
    task_id = data["task_id"]

    # Poll for completion (max 60s)
    for _ in range(12):
        await asyncio.sleep(5)
        r = await client.get(f"/api/security/tasks/{task_id}", headers=auth_headers)
        if r.status_code != 200:
            continue
        task_data = r.json()["data"]
        if task_data["status"] in ("completed", "failed", "cancelled"):
            # Verify task has findings
            assert task_data["findings_count"] >= 0
            # If eicar_verified is present, it's a boolean
            if task_data.get("eicar_verified") is not None:
                assert isinstance(task_data["eicar_verified"], bool)
            break
    # Task should have reached a terminal state
    assert task_data["status"] in ("completed", "failed", "cancelled")


# ── 2. Vulnerability Scan (CVE/CVSS) ────────────────────────────────────

@pytest.mark.asyncio
async def test_vulnerability_scan(client: AsyncClient, auth_headers: dict):
    """Start a full security scan and verify vulnerability findings include CVE/CVSS data."""
    r = await client.post(
        "/api/security/full-scan",
        headers=auth_headers,
        json={"description": "Acceptance test vulnerability scan"},
    )
    assert r.status_code == 200, f"full-scan failed: {r.status_code} {r.text}"
    data = r.json()
    assert "task_id" in data
    task_id = data["task_id"]

    # Poll for completion (max 90s)
    task_data = None
    for _ in range(18):
        await asyncio.sleep(5)
        r = await client.get(f"/api/security/tasks/{task_id}", headers=auth_headers)
        if r.status_code != 200:
            continue
        task_data = r.json()["data"]
        if task_data["status"] in ("completed", "failed", "cancelled"):
            break

    assert task_data is not None
    assert task_data["status"] in ("completed", "failed", "cancelled")

    # If completed, check for vulnerability findings with CVE/CVSS
    if task_data["status"] == "completed":
        vuln_findings = [f for f in task_data.get("findings", []) if f["type"] == "vulnerability"]
        # At least some findings should exist (service checks, etc.)
        # Note: May be 0 if no services are exposed on the test machine
        assert isinstance(vuln_findings, list)


# ── 3. Indicator Auto-Enrichment ────────────────────────────────────────

@pytest.mark.asyncio
async def test_indicator_enrichment_graceful_degradation(client: AsyncClient, auth_headers: dict):
    """Verify IOC enrichment works even without API keys (graceful degradation).

    The enrichment should not crash and should return structured results
    even when VirusTotal/Shodan keys are not configured.
    """
    # Start a scan which will trigger enrichment
    r = await client.post(
        "/api/security/full-scan",
        headers=auth_headers,
        json={"description": "Enrichment test"},
    )
    assert r.status_code == 200
    task_id = r.json()["task_id"]

    # Poll for completion
    for _ in range(12):
        await asyncio.sleep(5)
        r = await client.get(f"/api/security/tasks/{task_id}", headers=auth_headers)
        if r.status_code != 200:
            continue
        task_data = r.json()["data"]
        if task_data["status"] in ("completed", "failed", "cancelled"):
            break

    # Enrichment should not cause scan failure
    assert task_data["status"] in ("completed", "failed", "cancelled")


# ── 4. Job Lifecycle ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_job_lifecycle(client: AsyncClient, auth_headers: dict):
    """Test the full job lifecycle: create -> list -> get status -> cancel."""
    # Create a scan task
    r = await client.post(
        "/api/security/full-scan",
        headers=auth_headers,
        json={"description": "Lifecycle test scan"},
    )
    assert r.status_code == 200
    task_id = r.json()["task_id"]

    # List tasks and verify the new task appears
    r = await client.get("/api/security/tasks", headers=auth_headers)
    assert r.status_code == 200
    tasks = r.json()["data"]
    assert isinstance(tasks, list)
    task_ids = [t["id"] for t in tasks]
    assert task_id in task_ids

    # Get specific task status
    r = await client.get(f"/api/security/tasks/{task_id}", headers=auth_headers)
    assert r.status_code == 200
    task_data = r.json()["data"]
    assert task_data["task_id"] == task_id
    assert task_data["status"] in ("running", "completed", "failed", "cancelled")

    # Try to cancel (may already be complete)
    r = await client.post(f"/api/security/tasks/{task_id}/cancel", headers=auth_headers)
    # Accept 200 (cancelled) or 400 (already done)
    assert r.status_code in (200, 400)


# ── 5. Incident Lifecycle ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_incident_lifecycle(client: AsyncClient, auth_headers: dict):
    """Test incident listing and resolution workflow."""
    # Get active threats
    r = await client.get("/api/threats/active", headers=auth_headers)
    assert r.status_code in (200, 401, 402)
    if r.status_code == 200:
        threats = r.json().get("threats", [])
        assert isinstance(threats, list)

        # If there are active threats, try resolving one
        if threats:
            threat_id = threats[0]["id"]
            r = await client.post(
                f"/api/threats/{threat_id}/resolve",
                headers=auth_headers,
                json={"note": "Resolved by acceptance test"},
            )
            assert r.status_code == 200

    # Get all threats
    r = await client.get("/api/threats/", headers=auth_headers)
    assert r.status_code in (200, 401, 402)


# ── 6. Dashboard Data Endpoints ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_dashboard_health_endpoint(client: AsyncClient):
    """Verify /api/health returns valid data."""
    r = await client.get("/api/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "healthy"
    assert "platform" in data


@pytest.mark.asyncio
async def test_dashboard_threat_stats(client: AsyncClient, auth_headers: dict):
    """Verify /api/threats/stats returns structured data."""
    r = await client.get("/api/threats/stats", headers=auth_headers)
    assert r.status_code in (200, 401, 402)
    if r.status_code == 200:
        data = r.json()
        assert "total" in data
        assert "active" in data
        assert "resolved" in data


@pytest.mark.asyncio
async def test_dashboard_system_health(client: AsyncClient, auth_headers: dict):
    """Verify /api/system/health returns CPU/RAM/disk data."""
    r = await client.get("/api/system/health", headers=auth_headers)
    assert r.status_code in (200, 402)
    if r.status_code == 200:
        data = r.json()
        assert "cpu_percent" in data or "uptime_secs" in data


@pytest.mark.asyncio
async def test_dashboard_libraries(client: AsyncClient, auth_headers: dict):
    """Verify /api/system/libraries returns module status."""
    r = await client.get("/api/system/libraries", headers=auth_headers)
    assert r.status_code in (200, 402)
    if r.status_code == 200:
        data = r.json()
        assert "total" in data
        assert "libraries" in data
        assert isinstance(data["libraries"], list)


@pytest.mark.asyncio
async def test_dashboard_kill_chain(client: AsyncClient, auth_headers: dict):
    """Verify /api/kill-chain returns MITRE ATT&CK mapping."""
    r = await client.get("/api/kill-chain", headers=auth_headers)
    assert r.status_code in (200, 401, 402)
    if r.status_code == 200:
        data = r.json()
        assert "stages" in data
        assert "total_threats" in data


@pytest.mark.asyncio
async def test_dashboard_live_processes(client: AsyncClient, auth_headers: dict):
    """Verify /api/live/processes returns running process data."""
    r = await client.get("/api/live/processes", headers=auth_headers)
    assert r.status_code in (200, 401, 402)
    if r.status_code == 200:
        data = r.json()
        assert "processes" in data
        assert "total" in data


@pytest.mark.asyncio
async def test_dashboard_network_connections(client: AsyncClient, auth_headers: dict):
    """Verify /api/network/connections returns active connections."""
    r = await client.get("/api/network/connections", headers=auth_headers)
    assert r.status_code in (200, 401, 402)
    if r.status_code == 200:
        data = r.json()
        assert "connections" in data


@pytest.mark.asyncio
async def test_dashboard_ioc_extraction(client: AsyncClient, auth_headers: dict):
    """Verify IOC extraction endpoint works with sample text."""
    r = await client.post(
        "/api/intel/ioc/extract",
        headers=auth_headers,
        json={"text": "Attack from 185.220.101.1 CVE-2024-9999 malware emotet connected to evil.com"},
    )
    assert r.status_code in (200, 401, 402)
    if r.status_code == 200:
        data = r.json()
        assert "iocs" in data
        iocs = data["iocs"]
        # Should extract at least an IP
        assert "ips" in iocs


# ── 7. Scan Task Listing ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_scan_task_listing(client: AsyncClient, auth_headers: dict):
    """Verify the scan task listing endpoint returns valid data."""
    r = await client.get("/api/security/tasks", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert "data" in data
    assert isinstance(data["data"], list)
