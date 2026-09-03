"""Unit tests for ApprovalManager — Requirements 4.4, 4.5, 4.6"""
from __future__ import annotations
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from agents.approval_manager import ApprovalManager
from agents.schemas import ApprovalDecision


def _make_ws():
    ws = MagicMock()
    ws.broadcast = AsyncMock()
    return ws


def _make_audit():
    a = MagicMock()
    a.log = AsyncMock()
    return a


def _make_db():
    from unittest.mock import AsyncMock, MagicMock
    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()

    # Mock approval fetch
    from agents.models import Approval
    approval = Approval(
        id="appr-123", task_id="task-1", tool_name="revoke_device",
        risk_level="HIGH", description="test", reason="test",
        status="pending",
    )
    from datetime import datetime
    approval.created_at = datetime.utcnow()

    result = MagicMock()
    result.scalar_one_or_none = MagicMock(return_value=approval)
    db.execute = AsyncMock(return_value=result)
    return db, approval


@pytest.mark.asyncio
async def test_approve_sets_decision():
    mgr = ApprovalManager(_make_ws(), _make_audit())
    db, approval = _make_db()
    approval_id = "appr-123"
    mgr._pending[approval_id] = asyncio.Event()
    mgr._decisions[approval_id] = None

    await mgr.approve(approval_id, "user-1", db)

    assert approval.status == "approved"
    assert approval.decided_by == "user-1"
    assert mgr._pending[approval_id].is_set()


@pytest.mark.asyncio
async def test_reject_sets_rejected():
    mgr = ApprovalManager(_make_ws(), _make_audit())
    db, approval = _make_db()
    approval_id = "appr-123"
    mgr._pending[approval_id] = asyncio.Event()

    await mgr.reject(approval_id, "user-2", db)

    assert approval.status == "rejected"
    assert mgr._decisions[approval_id] == ApprovalDecision.REJECTED


@pytest.mark.asyncio
async def test_wait_for_decision_timeout_returns_expired():
    mgr = ApprovalManager(_make_ws(), _make_audit())
    approval_id = "appr-timeout"
    mgr._pending[approval_id] = asyncio.Event()

    decision = await mgr.wait_for_decision(approval_id, timeout=0.01)

    assert decision == ApprovalDecision.EXPIRED
    assert approval_id not in mgr._pending
