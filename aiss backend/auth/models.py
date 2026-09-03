"""
Auth — SQLAlchemy ORM Models
Tables: auth_users, auth_sessions, auth_verification_tokens,
        auth_otp_verifications, auth_onboarding, registered_devices
All primary keys are UUIDs.
"""

import uuid
from datetime import datetime
from sqlalchemy import (
    Boolean, Column, DateTime, Integer, String,
    Text, ForeignKey, Enum as SAEnum, Index, JSON,
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

    # Security
    must_change_password = Column(Boolean, nullable=False, default=False)  # force change on first login

    # OAuth social login
    oauth_provider   = Column(String(32),  nullable=True)   # "google" | "github" | None
    oauth_subject    = Column(String(255), nullable=True)   # provider user ID
    avatar_url       = Column(String(512), nullable=True)   # profile picture URL

    # Relationships
    sessions             = relationship("AuthSession",          back_populates="user", cascade="all, delete-orphan")
    verification_tokens  = relationship("VerificationToken",    back_populates="user", cascade="all, delete-orphan")
    otp_verifications    = relationship("OtpVerification",      back_populates="user", cascade="all, delete-orphan")
    onboarding           = relationship("AuthOnboarding",       back_populates="user", uselist=False, cascade="all, delete-orphan")
    devices              = relationship("RegisteredDevice",     back_populates="user", cascade="all, delete-orphan")

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
            "must_change_password": self.must_change_password,
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


# ─────────────────────────────────────────────────────────────────────
# ONBOARDING STATE (persisted in DB — not a frontend variable)
# ─────────────────────────────────────────────────────────────────────
class AuthOnboarding(Base):
    """
    Tracks first-run setup completion per user.
    Created when the user first logs in. Never recreated after completion.
    """
    __tablename__ = "auth_onboarding"

    id                   = Column(String(36),  primary_key=True, default=_uuid)
    user_id              = Column(String(36),  ForeignKey("auth_users.id", ondelete="CASCADE"),
                                               nullable=False, unique=True, index=True)
    is_completed         = Column(Boolean,     nullable=False, default=False)
    completed_at         = Column(DateTime,    nullable=True)
    # Which steps were completed (stored as JSON list of step IDs)
    completed_steps      = Column(Text,        nullable=True)   # JSON: ["welcome","permissions","config"]
    # Allow admin to reset onboarding for a user
    reset_at             = Column(DateTime,    nullable=True)
    created_at           = Column(DateTime,    nullable=False, default=_now)

    user = relationship("AuthUser", back_populates="onboarding")

    def mark_complete(self) -> None:
        self.is_completed = True
        self.completed_at = _now()

    def reset(self) -> None:
        self.is_completed    = False
        self.completed_at    = None
        self.completed_steps = None
        self.reset_at        = _now()


# ─────────────────────────────────────────────────────────────────────
# REGISTERED DEVICES (real device pairing — persisted in DB)
# ─────────────────────────────────────────────────────────────────────
class RegisteredDevice(Base):
    """
    A device that has been paired with AISS.
    Token is a one-time pairing credential; after pairing it is replaced
    with a long-lived device_secret used for subsequent authentication.
    """
    __tablename__ = "registered_devices"

    id               = Column(String(36),  primary_key=True, default=_uuid)
    user_id          = Column(String(36),  ForeignKey("auth_users.id", ondelete="CASCADE"),
                                           nullable=False, index=True)

    # Device identity
    device_name      = Column(String(128), nullable=False)           # user-assigned or auto-detected
    device_type      = Column(String(32),  nullable=False, default="desktop")  # desktop|mobile|server
    platform         = Column(String(32),  nullable=True)            # windows|linux|macos|android|ios
    hostname         = Column(String(255), nullable=True)
    os_info          = Column(String(255), nullable=True)

    # Pairing token (one-time use, cryptographically random, hashed)
    pairing_token_hash  = Column(String(64),  nullable=True,  index=True)  # SHA-256; null after pairing
    pairing_expires_at  = Column(DateTime,    nullable=True)
    pairing_used_at     = Column(DateTime,    nullable=True)
    is_paired           = Column(Boolean,     nullable=False, default=False)
    paired_at           = Column(DateTime,    nullable=True)

    # Long-lived device credential (issued after successful pairing)
    device_secret_hash  = Column(String(64),  nullable=True)          # SHA-256 of device secret
    device_secret_expires = Column(DateTime,  nullable=True)

    # Connection state
    status           = Column(
                         SAEnum("pending", "paired", "connected", "disconnected", "revoked",
                                name="device_status"),
                         nullable=False, default="pending"
                       )
    last_seen_at     = Column(DateTime,    nullable=True)
    last_seen_ip     = Column(String(45),  nullable=True)
    connection_count = Column(Integer,     nullable=False, default=0)

    # Revocation
    is_revoked       = Column(Boolean,     nullable=False, default=False)
    revoked_at       = Column(DateTime,    nullable=True)
    revoke_reason    = Column(String(255), nullable=True)

    # Metadata
    extra_info       = Column(JSON,        nullable=True)   # arbitrary device metadata
    created_at       = Column(DateTime,    nullable=False, default=_now)

    user = relationship("AuthUser", back_populates="devices")

    __table_args__ = (
        Index("ix_device_user_status", "user_id", "status"),
    )

    def is_pairing_valid(self) -> bool:
        """True if pairing token is unused and not expired."""
        if self.is_paired or self.pairing_used_at:
            return False
        if not self.pairing_expires_at:
            return False
        return datetime.utcnow() < self.pairing_expires_at

    def to_dict(self) -> dict:
        return {
            "id":             self.id,
            "device_name":    self.device_name,
            "device_type":    self.device_type,
            "platform":       self.platform,
            "hostname":       self.hostname,
            "os_info":        self.os_info,
            "status":         self.status,
            "is_paired":      self.is_paired,
            "is_revoked":     self.is_revoked,
            "paired_at":      self.paired_at.isoformat() if self.paired_at else None,
            "last_seen_at":   self.last_seen_at.isoformat() if self.last_seen_at else None,
            "last_seen_ip":   self.last_seen_ip,
            "connection_count": self.connection_count,
            "created_at":     self.created_at.isoformat(),
        }
