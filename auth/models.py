"""
Auth — SQLAlchemy ORM Models
Tables: users, sessions, verification_tokens, otp_verifications
All primary keys are UUIDs.
"""

import uuid
from datetime import datetime
from sqlalchemy import (
    Boolean, Column, DateTime, Integer, String,
    Text, ForeignKey, Enum as SAEnum, Index,
)
from sqlalchemy.orm import relationship

from core.models import Base   # reuse shared Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.utcnow()


# ─────────────────────────────────────────────────────────────────────
# USERS
# ─────────────────────────────────────────────────────────────────────
class AuthUser(Base):
    __tablename__ = "auth_users"

    id               = Column(String(36),  primary_key=True, default=_uuid)
    username         = Column(String(64),  nullable=False, unique=True, index=True)
    email            = Column(String(255), nullable=False, unique=True, index=True)
    hashed_password  = Column(String(255), nullable=False)

    role             = Column(
                         SAEnum("admin", "analyst", "viewer", name="auth_user_role"),
                         nullable=False, default="viewer"
                       )

    # Account state
    is_active        = Column(Boolean, nullable=False, default=True)
    is_verified      = Column(Boolean, nullable=False, default=False)  # email verified
    is_phone_verified = Column(Boolean, nullable=False, default=False)
    phone_number     = Column(String(20), nullable=True)

    # Brute-force protection
    failed_login_attempts = Column(Integer, nullable=False, default=0)
    locked_until          = Column(DateTime, nullable=True)
    last_failed_ip        = Column(String(45), nullable=True)

    # Timestamps
    created_at       = Column(DateTime, nullable=False, default=_now)
    last_login_at    = Column(DateTime, nullable=True)
    last_login_ip    = Column(String(45), nullable=True)

    # Relationships
    sessions             = relationship("AuthSession",          back_populates="user", cascade="all, delete-orphan")
    verification_tokens  = relationship("VerificationToken",    back_populates="user", cascade="all, delete-orphan")
    otp_verifications    = relationship("OtpVerification",      back_populates="user", cascade="all, delete-orphan")

    def is_locked(self) -> bool:
        if not self.locked_until:
            return False
        return datetime.utcnow() < self.locked_until

    def to_dict(self) -> dict:
        return {
            "id":                self.id,
            "username":          self.username,
            "email":             self.email,
            "role":              self.role,
            "is_active":         self.is_active,
            "is_verified":       self.is_verified,
            "is_phone_verified": self.is_phone_verified,
            "created_at":        self.created_at.isoformat(),
            "last_login_at":     self.last_login_at.isoformat() if self.last_login_at else None,
        }


# ─────────────────────────────────────────────────────────────────────
# SESSIONS (refresh token store)
# ─────────────────────────────────────────────────────────────────────
class AuthSession(Base):
    __tablename__ = "auth_sessions"

    id                  = Column(String(36),  primary_key=True, default=_uuid)
    user_id             = Column(String(36),  ForeignKey("auth_users.id", ondelete="CASCADE"), nullable=False, index=True)
    refresh_token_hash  = Column(String(64),  nullable=False, unique=True, index=True)

    # Device / context
    device_info         = Column(Text,        nullable=True)
    ip_address          = Column(String(45),  nullable=True)
    user_agent          = Column(Text,        nullable=True)

    # Lifecycle
    created_at          = Column(DateTime,    nullable=False, default=_now)
    expires_at          = Column(DateTime,    nullable=False)
    is_revoked          = Column(Boolean,     nullable=False, default=False)
    last_used_at        = Column(DateTime,    nullable=True)

    user = relationship("AuthUser", back_populates="sessions")

    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

    def is_valid(self) -> bool:
        return not self.is_revoked and not self.is_expired()


# ─────────────────────────────────────────────────────────────────────
# VERIFICATION TOKENS (email verification + password reset)
# ─────────────────────────────────────────────────────────────────────
class VerificationToken(Base):
    __tablename__ = "auth_verification_tokens"

    id          = Column(String(36),  primary_key=True, default=_uuid)
    user_id     = Column(String(36),  ForeignKey("auth_users.id", ondelete="CASCADE"), nullable=False, index=True)
    token       = Column(String(128), nullable=False, unique=True, index=True)
    token_type  = Column(
                    SAEnum("email_verify", "password_reset", name="verification_token_type"),
                    nullable=False
                  )
    expires_at  = Column(DateTime,   nullable=False)
    used_at     = Column(DateTime,   nullable=True)   # None = not yet used

    user = relationship("AuthUser", back_populates="verification_tokens")

    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

    def is_used(self) -> bool:
        return self.used_at is not None

    def is_valid(self) -> bool:
        return not self.is_expired() and not self.is_used()


# ─────────────────────────────────────────────────────────────────────
# OTP VERIFICATIONS (phone / 2FA)
# ─────────────────────────────────────────────────────────────────────
class OtpVerification(Base):
    __tablename__ = "auth_otp_verifications"

    id          = Column(String(36),  primary_key=True, default=_uuid)
    user_id     = Column(String(36),  ForeignKey("auth_users.id", ondelete="CASCADE"), nullable=False, index=True)
    otp_hash    = Column(String(64),  nullable=False)   # SHA-256 of the OTP
    purpose     = Column(
                    SAEnum("phone_verify", "login_2fa", "email_otp", name="otp_purpose"),
                    nullable=False, default="login_2fa"
                  )
    expires_at  = Column(DateTime,   nullable=False)
    attempts    = Column(Integer,    nullable=False, default=0)  # prevent brute-force
    verified_at = Column(DateTime,   nullable=True)

    user = relationship("AuthUser", back_populates="otp_verifications")

    MAX_ATTEMPTS = 5

    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

    def is_used(self) -> bool:
        return self.verified_at is not None

    def is_valid(self) -> bool:
        return (
            not self.is_expired()
            and not self.is_used()
            and self.attempts < self.MAX_ATTEMPTS
        )
