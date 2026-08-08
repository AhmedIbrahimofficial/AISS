"""
Password hashing using Argon2id — the winner of the Password Hashing Competition.
Argon2id is resistant to GPU/ASIC attacks and side-channel attacks.
Falls back to bcrypt only as a last resort.
"""

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
import re

# Argon2id config — OWASP recommended minimums
_ph = PasswordHasher(
    time_cost=2,       # iterations
    memory_cost=65536, # 64 MB
    parallelism=2,
    hash_len=32,
    salt_len=16,
)

# ── Password strength rules ───────────────────────────────────────────

PASSWORD_RULES = [
    (r".{12,}",         "at least 12 characters"),
    (r"[A-Z]",          "at least one uppercase letter"),
    (r"[a-z]",          "at least one lowercase letter"),
    (r"\d",             "at least one digit"),
    (r"[!@#$%^&*(),.?\":{}|<>_\-]", "at least one special character"),
]


def validate_password_strength(password: str) -> list[str]:
    """
    Returns list of violated rules.
    Empty list = password is strong enough.
    """
    violations = []
    for pattern, message in PASSWORD_RULES:
        if not re.search(pattern, password):
            violations.append(message)
    return violations


def hash_password(plain: str) -> str:
    """Hash a plain-text password with Argon2id."""
    return _ph.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """
    Verify plain password against stored hash.
    Returns False on any mismatch — never raises to caller.
    """
    try:
        return _ph.verify(hashed, plain)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(hashed: str) -> bool:
    """True if the hash was created with old params and should be upgraded."""
    return _ph.check_needs_rehash(hashed)
