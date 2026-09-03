"""
Agentic AI Orchestrator — AuditLogger

Writes immutable AgentAuditEvent records to the database.
Records are INSERT-only; no update/delete methods exist.
Credential redaction is applied before every write.

Requirements: 8.1–8.7
"""
from __future__ import annotations

import copy
import logging
import re
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from agents.exceptions import AuditPersistenceError
from agents.models import AgentAuditEvent

logger = logging.getLogger("agents.audit_logger")

# ---------------------------------------------------------------------------
# Credential redaction patterns
# ---------------------------------------------------------------------------

# Keys whose values should always be redacted (case-insensitive substring match)
_CREDENTIAL_KEY_PATTERN = re.compile(
    r"(api_?key|apikey|password|passwd|secret|token|credential|auth)",
    re.IGNORECASE,
)

# Value patterns that look like secrets regardless of key name
_CREDENTIAL_VALUE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"sk-[A-Za-z0-9]{20,}"),                    # OpenAI / OpenRouter keys
    re.compile(r"Bearer [A-Za-z0-9._\-]{20,}"),             # Authorization header values
    re.compile(r"ghp_[A-Za-z0-9]{36}"),                     # GitHub personal access tokens
    re.compile(r"sk-or-v1-[A-Za-z0-9]{20,}"),               # OpenRouter-specific prefix
]

_REDACTED = "[REDACTED]"


class AuditLogger:
    """Writes immutable audit events; blocks tool execution if persistence fails."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def log(
        self,
        db: AsyncSession,
        *,
        user_id: str,
        event_type: str,
        severity: str = "info",
        request_summary: str | None = None,
        plan_summary: str | None = None,
        tool_name: str | None = None,
        arguments_redacted: dict[str, Any] | None = None,
        auth_result: str | None = None,
        execution_result_summary: str | None = None,
        risk_level: str | None = None,
        approval_status: str | None = None,
        ai_conclusion: str | None = None,
    ) -> AgentAuditEvent:
        """
        Create and persist an AgentAuditEvent.

        - request_summary is truncated to 2048 chars.
        - arguments_redacted is deep-copied and credential-redacted before write.
        - If the DB INSERT fails after one retry, raises AuditPersistenceError.
          Tool execution MUST be blocked by callers when this is raised.
        """
        if request_summary:
            request_summary = request_summary[:2048]

        safe_args = self._redact_credentials(arguments_redacted or {})

        event = AgentAuditEvent(
            id=str(uuid.uuid4()),
            user_id=user_id,
            event_type=event_type,
            severity=severity,
            request_summary=request_summary,
            plan_summary=plan_summary,
            tool_name=tool_name,
            arguments_redacted_json=safe_args if safe_args else None,
            auth_result=auth_result,
            execution_result_summary=execution_result_summary,
            risk_level=risk_level,
            approval_status=approval_status,
            ai_conclusion=ai_conclusion,
            created_at=datetime.utcnow(),
        )

        for attempt in range(2):
            try:
                db.add(event)
                await db.flush()  # write to DB within the current transaction
                return event
            except Exception as exc:
                await db.rollback()
                if attempt == 0:
                    logger.warning(
                        "AuditLogger: DB write failed on attempt 1, retrying. error=%s", exc
                    )
                    continue
                # Second attempt also failed
                logger.error(
                    "AuditLogger: DB write failed after retry. event_type=%s user_id=%s error=%s",
                    event_type, user_id, exc,
                )
                raise AuditPersistenceError(
                    f"Failed to persist audit event '{event_type}' for user {user_id}: {exc}"
                ) from exc

        # Should never reach here
        raise AuditPersistenceError(f"Unexpected exit from audit retry loop for '{event_type}'")

    # ------------------------------------------------------------------
    # Credential redaction
    # ------------------------------------------------------------------

    def _redact_credentials(self, data: Any) -> Any:
        """
        Deep-copy `data` and replace any credential-looking values with '[REDACTED]'.
        Works recursively on dicts, lists, and strings.
        Never modifies the original object.
        """
        if isinstance(data, dict):
            result: dict[str, Any] = {}
            for key, value in data.items():
                if isinstance(key, str) and _CREDENTIAL_KEY_PATTERN.search(key):
                    result[key] = _REDACTED
                else:
                    result[key] = self._redact_credentials(value)
            return result

        if isinstance(data, list):
            return [self._redact_credentials(item) for item in data]

        if isinstance(data, str):
            for pattern in _CREDENTIAL_VALUE_PATTERNS:
                if pattern.search(data):
                    return _REDACTED
            return data

        return copy.deepcopy(data)
