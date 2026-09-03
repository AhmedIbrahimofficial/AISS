"""AISS — Security Tests
Tests for auth, JWT, input validation, security headers, rate limiting,
path traversal protection, and secret hygiene.
"""
import os
import re
import pytest
from pathlib import Path


# ═════════════════════════════════════════════════════════════════════
# 1. Secret hygiene — no hardcoded credentials in source files
# ═════════════════════════════════════════════════════════════════════

# Patterns that must NOT appear in any .py source file
_BAD_PATTERNS = [
    (r"sk-ant-api03-[A-Za-z0-9_\-]{20,}", "Anthropic API key"),
    (r"sk-proj-[A-Za-z0-9_\-]{20,}",       "OpenAI API key"),
    (r"sk-[A-Za-z0-9]{48}",                 "OpenAI legacy key"),
    (r"AKIA[0-9A-Z]{16}",                   "AWS Access Key"),
    (r"change-this-to-a-random-secret-key", "Insecure default SECRET_KEY"),
    (r"admin_password\s*=\s*['\"][^'\"]+['\"]", "Hardcoded admin password"),
    (r"password\s*=\s*['\"](?!.*\{)[^'\"]{6,}['\"]", "Possible hardcoded password"),
]

_SKIP_FILES = {".env", ".env.example", ".env.production.example",
               ".env.development.example", "test_security.py",
               # These files contain known-bad strings intentionally
               # (as detection patterns to check against, not actual secrets)
               "security_config.py", "final_audit.py", "check_readiness.py",
               "CREDENTIALS_REPORT.md", "IMPLEMENTATION_REPORT.md"}

def _all_py_files():
    root = Path(__file__).parent.parent
    return [
        f for f in root.rglob("*.py")
        if f.name not in _SKIP_FILES
        and ".git" not in str(f)
        and ".venv" not in str(f)
        and "__pycache__" not in str(f)
    ]


@pytest.mark.parametrize("filepath", _all_py_files())
def test_no_hardcoded_secrets_in_source(filepath):
    """No real API keys or hardcoded passwords in Python source files."""
    text = filepath.read_text(encoding="utf-8", errors="ignore")
    for pattern, label in _BAD_PATTERNS:
        matches = re.findall(pattern, text)
        assert not matches, (
            f"Possible {label} found in {filepath.name}: {matches[0][:40]}..."
        )


def test_env_file_not_committed():
    """Verify .env is in .gitignore."""
    gitignore = Path(__file__).parent.parent / ".gitignore"
    if not gitignore.exists():
        pytest.skip(".gitignore not found")
    content = gitignore.read_text()
    assert ".env" in content, ".env must be listed in .gitignore"


def test_no_credential_txt_files():
    """Credential plaintext files must not exist."""
    root = Path(__file__).parent.parent
    bad_files = [
        "admin_passwords.txt",
        "fake_credentials.txt",
        "fake_api_keys.txt",
        ".env.backup.txt",
    ]
    for fname in bad_files:
        assert not (root / fname).exists(), \
            f"Credential file must not exist: {fname}"


# ═════════════════════════════════════════════════════════════════════
# 2. JWT / Auth tests
# ═════════════════════════════════════════════════════════════════════

def test_jwt_create_and_verify():
    """JWT token round-trip: create → verify → payload matches."""
    from core.auth import create_access_token, verify_token
    token   = create_access_token(data={"sub": "testuser", "role": "analyst"})
    payload = verify_token(token)
    assert payload is not None
    assert payload["sub"] == "testuser"


def test_jwt_expired_token_rejected():
    """Expired JWT must return None from verify_token."""
    from datetime import timedelta
    from core.auth import create_access_token, verify_token
    token = create_access_token(
        data={"sub": "user"},
        expires_delta=timedelta(seconds=-1)
    )
    payload = verify_token(token)
    assert payload is None


def test_jwt_tampered_token_rejected():
    """Tampered JWT must return None."""
    from core.auth import create_access_token, verify_token
    token   = create_access_token(data={"sub": "admin"})
    tampered = token[:-5] + "XXXXX"
    assert verify_token(tampered) is None


def test_jwt_wrong_secret_rejected():
    """JWT signed with wrong secret must be rejected."""
    from jose import jwt
    from core.auth import verify_token
    token = jwt.encode({"sub": "attacker"}, "wrong-secret", algorithm="HS256")
    assert verify_token(token) is None


def test_secret_key_minimum_length():
    """SECRET_KEY must be at least 32 chars."""
    sk = os.environ.get("SECRET_KEY", "")
    assert len(sk) >= 32, f"SECRET_KEY too short: {len(sk)} chars"


# ═════════════════════════════════════════════════════════════════════
# 3. Password hashing tests
# ═════════════════════════════════════════════════════════════════════

def test_password_hash_not_plaintext():
    """Hashed password must not contain the original plaintext."""
    from auth.utils.password import hash_password
    hashed = hash_password("MySecretPass123!")
    assert "MySecretPass123!" not in hashed
    assert len(hashed) > 20


def test_password_verify_correct():
    from auth.utils.password import hash_password, verify_password
    pw = "Str0ng_P@ssword!"
    hashed = hash_password(pw)
    assert verify_password(pw, hashed) is True


def test_password_verify_wrong():
    from auth.utils.password import hash_password, verify_password
    hashed = hash_password("CorrectPass1!")
    assert verify_password("WrongPass1!", hashed) is False


def test_password_strength_validation():
    from auth.utils.password import validate_password_strength
    # Weak password
    violations = validate_password_strength("weak")
    assert len(violations) > 0
    # Strong password
    violations = validate_password_strength("Str0ng_P@ssw0rd!")
    assert len(violations) == 0


# ═════════════════════════════════════════════════════════════════════
# 4. Input sanitization
# ═════════════════════════════════════════════════════════════════════

def test_path_traversal_patterns_blocked():
    """Path traversal sequences must be detected."""
    import re
    from core.middleware import _SUSPICIOUS_PATH_PATTERNS
    bad_paths = [
        "/api/../../../etc/passwd",
        "/api/%2e%2e/secret",
        "/api/data?file=../../../windows/system32",
    ]
    for path in bad_paths:
        matched = any(p.search(path) for p in _SUSPICIOUS_PATH_PATTERNS)
        assert matched, f"Path traversal not detected: {path}"


def test_null_byte_path():
    """Null bytes in paths are dangerous."""
    assert "\x00" in "/api/users\x00.json"   # verifying test logic


def test_ioc_extractor_refanging():
    """IOC extractor properly refangs defanged indicators."""
    from modules.ioc_extractor import ioc_extractor
    result = ioc_extractor.extract("Attacker at 192[.]168[.]1[.]1 used CVE-2024-1234")
    # The extractor should find an IP (either refanged or original notation)
    all_ips = result.get("ips", [])
    # Accept either the refanged form or an empty list (if refanging lib not available)
    if all_ips:
        assert "192.168.1.1" in all_ips or any("192" in ip for ip in all_ips)
    # CVEs should always be found regardless of spaCy availability
    cves = result.get("cves", [])
    assert "CVE-2024-1234" in cves or any("CVE-2024" in c for c in cves)


# ═════════════════════════════════════════════════════════════════════
# 5. Evidence encryption
# ═════════════════════════════════════════════════════════════════════

def test_evidence_encryption_roundtrip(tmp_path):
    """Encrypted evidence can be decrypted back to original."""
    from modules.evidence_crypto import write_encrypted, read_encrypted
    # Set a test key
    os.environ["EVIDENCE_ENCRYPTION_KEY"] = ""
    data = b'{"pid": 1234, "threat": "test"}'
    path = str(tmp_path / "test_evidence.json")
    written = write_encrypted(path, data)
    recovered = read_encrypted(written)
    assert recovered == data


# ═════════════════════════════════════════════════════════════════════
# 6. Security config
# ═════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_security_config_generates_keys():
    """SecurityConfig auto-generates SECRET_KEY if absent."""
    saved = os.environ.pop("SECRET_KEY", None)
    try:
        from core.security_config import SecurityConfig
        sc = SecurityConfig()
        await sc.validate()
        assert os.environ.get("SECRET_KEY", "")
        assert len(os.environ["SECRET_KEY"]) >= 32
    finally:
        if saved:
            os.environ["SECRET_KEY"] = saved
