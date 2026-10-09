"""AISS Test Configuration — shared fixtures for all test modules."""
import asyncio
import os
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

# Force test environment before any app import
os.environ.setdefault("ENVIRONMENT",    "development")
os.environ.setdefault("DATABASE_URL",   "sqlite+aiosqlite:///./logs/test.db")
os.environ.setdefault("SECRET_KEY",     "test-secret-key-minimum-64-chars-long-for-testing-purposes-only!!")
os.environ.setdefault("EVIDENCE_ENCRYPTION_KEY", "")
os.environ.setdefault("AISS_LICENSE_KEY", "")
os.environ.setdefault("DISABLE_TTS",    "1")
os.environ.setdefault("DISABLE_YOLO",   "1")
os.environ.setdefault("LOG_LEVEL",      "WARNING")


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def app():
    """Import and return the FastAPI app (session-scoped)."""
    from main import app as _app
    yield _app


@pytest.fixture(scope="session")
async def client(app):
    """Async HTTP client bound to the test app."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        yield c


@pytest.fixture
def mock_license_valid(monkeypatch):
    """Patch license_manager to always return valid."""
    from core.licensing import LicenseStatus, LicenseType, LicenseInfo, FEATURE_FLAGS
    info = LicenseInfo(
        key="AISS-DEV-TEST",
        license_type=LicenseType.DEVELOPER,
        status=LicenseStatus.VALID,
        features=FEATURE_FLAGS[LicenseType.DEVELOPER],
        message="Test license",
    )
    monkeypatch.setattr("core.licensing.license_manager._info", info)
    return info
