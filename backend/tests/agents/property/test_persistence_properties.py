"""
Property-based tests for AuditLogger credential redaction.

Property 11: Audit events never contain credential material.

For any AgentAuditEvent written to the database, no field in the record
SHALL contain a raw API key, password, token, or secret — verified by
scanning all string fields against the credential redaction regex patterns.

Validates: Requirements 8.1, 8.2, 7.3
Feature: agentic-ai-orchestrator, Property 11
"""
from __future__ import annotations

import re
import string

import pytest
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from agents.audit_logger import AuditLogger, _CREDENTIAL_VALUE_PATTERNS, _REDACTED

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Strategy for generating dict keys that look like credential fields
credential_keys = st.sampled_from([
    "api_key", "apikey", "password", "passwd", "secret", "token",
    "credential", "auth_token", "authorization", "access_token",
    "refresh_token", "api_secret", "private_key",
])

# Strategy for generating dict keys that are NOT credential-like
safe_keys = st.sampled_from([
    "user_id", "tool_name", "status", "description", "result",
    "severity", "event_type", "affected_resource", "title",
])

# Strategy for generating values that look like real secrets
secret_values = st.one_of(
    st.just("sk-abc123DEF456ghi789JKL012mno345pqrSTU"),      # OpenAI-style
    st.just("sk-or-v1-abc123DEF456ghi789JKL012mno345pqr"),   # OpenRouter
    st.just("Bearer eyJhbGciOiJIUzI1NiJ9.test.signature12"),  # Bearer token
    st.just("ghp_abc123DEF456ghi789JKL012mno345pqrSTUV"),    # GitHub PAT
)

# Strategy for building dicts with credential keys/values
def credential_dicts():
    return st.one_of(
        # Dict with credential key
        st.fixed_dictionaries({
            "api_key": st.text(min_size=1, max_size=50),
            "user_id": st.text(min_size=1, max_size=36),
        }),
        # Dict with credential value
        st.fixed_dictionaries({
            "data": secret_values,
            "status": st.just("ok"),
        }),
        # Nested dict with credential key
        st.fixed_dictionaries({
            "config": st.fixed_dictionaries({
                "password": st.text(min_size=1, max_size=50),
            }),
            "name": st.text(min_size=1, max_size=20),
        }),
    )


# ---------------------------------------------------------------------------
# Helper — scan a dict for credential patterns (same logic audit_logger uses)
# ---------------------------------------------------------------------------

_CRED_KEY_RE = re.compile(
    r"(api_?key|apikey|password|passwd|secret|token|credential|auth)",
    re.IGNORECASE,
)


def _contains_credential(data: object) -> bool:
    """Return True if `data` contains any un-redacted credential."""
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(k, str) and _CRED_KEY_RE.search(k) and v != _REDACTED:
                return True
            if _contains_credential(v):
                return True
        return False
    if isinstance(data, list):
        return any(_contains_credential(item) for item in data)
    if isinstance(data, str):
        for pat in _CREDENTIAL_VALUE_PATTERNS:
            if pat.search(data) and data != _REDACTED:
                return True
    return False


# ---------------------------------------------------------------------------
# Property 11: Redacted output never contains credential material
# ---------------------------------------------------------------------------

logger = AuditLogger()


@given(raw_args=credential_dicts())
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_redacted_args_never_contain_credentials(raw_args: dict) -> None:
    """
    For any dict that contains credential keys or secret-looking values,
    _redact_credentials() must return a dict where no such data remains.
    """
    redacted = logger._redact_credentials(raw_args)
    assert not _contains_credential(redacted), (
        f"Credential material found in redacted output.\n"
        f"Input:    {raw_args}\n"
        f"Redacted: {redacted}"
    )


@given(args=st.fixed_dictionaries({
    safe_keys.example(): st.text(min_size=0, max_size=100)
    for _ in range(3)
}))
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_safe_args_pass_through_unchanged(args: dict) -> None:
    """
    Dicts with no credential keys/values should pass through redaction intact
    (values are preserved, only credential-matching ones get replaced).
    """
    redacted = logger._redact_credentials(args)
    # Safe dicts: every value that was not a secret should be unchanged
    for k, v in args.items():
        if not _CRED_KEY_RE.search(k):
            assert redacted.get(k) == v, (
                f"Safe key '{k}' was unexpectedly modified.\n"
                f"Input:    {args}\n"
                f"Redacted: {redacted}"
            )


@given(key=credential_keys, value=st.text(min_size=1, max_size=100))
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_credential_key_always_redacted(key: str, value: str) -> None:
    """Any dict entry whose key matches a credential pattern must be redacted."""
    raw = {key: value, "other_field": "safe_value"}
    redacted = logger._redact_credentials(raw)
    assert redacted[key] == _REDACTED, (
        f"Key '{key}' was not redacted. Got: {redacted[key]!r}"
    )
    assert redacted["other_field"] == "safe_value"


@given(secret=secret_values)
@settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
def test_secret_value_always_redacted(secret: str) -> None:
    """Any value that looks like a real secret must be redacted regardless of key."""
    raw = {"innocent_key": secret}
    redacted = logger._redact_credentials(raw)
    assert redacted["innocent_key"] == _REDACTED, (
        f"Secret value was not redacted under non-credential key.\n"
        f"Input: {raw}\nOutput: {redacted}"
    )
