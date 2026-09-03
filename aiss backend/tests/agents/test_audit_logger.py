"""Unit tests for AuditLogger — Requirements 8.1, 8.2"""
from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from agents.audit_logger import AuditLogger, _REDACTED
from agents.exceptions import AuditPersistenceError


def make_db():
    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.rollback = AsyncMock()
    return db


@pytest.mark.asyncio
async def test_password_field_redacted():
    logger = AuditLogger()
    result = logger._redact_credentials({"password": "secret123"})
    assert result["password"] == _REDACTED


@pytest.mark.asyncio
async def test_api_key_field_redacted():
    logger = AuditLogger()
    result = logger._redact_credentials({"api_key": "sk-abc123"})
    assert result["api_key"] == _REDACTED


@pytest.mark.asyncio
async def test_bearer_token_value_redacted():
    logger = AuditLogger()
    result = logger._redact_credentials({"header": "Bearer eyJhbGciOiJSUzI1NiJ9.test.longtoken"})
    assert result["header"] == _REDACTED


@pytest.mark.asyncio
async def test_sk_prefix_value_redacted():
    logger = AuditLogger()
    result = logger._redact_credentials({"data": "sk-or-v1-abc123DEF456ghi789JKL012mno345"})
    assert result["data"] == _REDACTED


@pytest.mark.asyncio
async def test_clean_dict_passes_through():
    logger = AuditLogger()
    data = {"tool_name": "scan_network", "target": "192.168.1.0/24", "status": "ok"}
    result = logger._redact_credentials(data)
    assert result == data


@pytest.mark.asyncio
async def test_nested_credential_redacted():
    logger = AuditLogger()
    data = {"config": {"auth_token": "secret", "host": "localhost"}}
    result = logger._redact_credentials(data)
    assert result["config"]["auth_token"] == _REDACTED
    assert result["config"]["host"] == "localhost"


@pytest.mark.asyncio
async def test_db_failure_raises_audit_persistence_error():
    logger = AuditLogger()
    db = make_db()
    db.flush.side_effect = Exception("DB connection lost")
    with pytest.raises(AuditPersistenceError):
        await logger.log(db, user_id="u1", event_type="test_event")


@pytest.mark.asyncio
async def test_request_summary_truncated():
    logger = AuditLogger()
    db = make_db()
    long_msg = "x" * 3000
    event = await logger.log(db, user_id="u1", event_type="test", request_summary=long_msg)
    assert len(event.request_summary) <= 2048
