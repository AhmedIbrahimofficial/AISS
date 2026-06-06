"""
Cybersecurity Platform — SQLAlchemy ORM Models
Tables: users, threat_logs, blocked_ips, system_events, scan_results
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean, Column, DateTime, Float, Integer,
    String, Text, JSON, ForeignKey, Enum as SAEnum,
    UniqueConstraint, Index,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, relationship


# ── Base ──────────────────────────────────────────────────────────────
class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.utcnow()


# ─────────────────────────────────────────────────────────────────────
# 1. USERS
# ─────────────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id              = Column(String(36), primary_key=True, default=_uuid)
    username        = Column(String(64),  nullable=False, unique=True, index=True)
    email           = Column(String(255), nullable=True,  unique=True, index=True)
    hashed_password = Column(String(255), nullable=False)
    role            = Column(
                        SAEnum("admin", "analyst", "viewer", name="user_role"),
                        nullable=False, default="viewer"
                      )
    is_active       = Column(Boolean, nullable=False, default=True)
    is_verified          = Column(Boolean,     nullable=False, default=False)
    email_verify_token   = Column(String(100), nullable=True)
    email_verify_expires = Column(DateTime,    nullable=True)
    reset_token          = Column(String(100), nullable=True)
    reset_token_expires  = Column(DateTime,    nullable=True)
    refresh_token_hash   = Column(String(255), nullable=True)
    login_attempts  = Column(Integer, nullable=False, default=0)
    locked_until    = Column(DateTime, nullable=True)
    created_at      = Column(DateTime, nullable=False, default=_now)
    last_login      = Column(DateTime, nullable=True)

    # relationships
    blocked_ips     = relationship("BlockedIP",    back_populates="blocker",
                                   foreign_keys="BlockedIP.blocked_by")
    system_events   = relationship("SystemEvent",  back_populates="user")

    def __repr__(self):
        return f"<User {self.username} [{self.role}]>"

    def is_locked(self) -> bool:
        if self.locked_until is None:
            return False
        return datetime.utcnow() < self.locked_until

    def to_dict(self) -> dict:
        return {
            "id":             self.id,
            "username":       self.username,
            "email":          self.email,
            "role":           self.role,
            "is_active":      self.is_active,
            "login_attempts": self.login_attempts,
            "locked_until":   self.locked_until.isoformat() if self.locked_until else None,
            "created_at":     self.created_at.isoformat(),
            "last_login":     self.last_login.isoformat() if self.last_login else None,
        }


# ─────────────────────────────────────────────────────────────────────
# 2. THREAT LOGS
# ─────────────────────────────────────────────────────────────────────
class ThreatLog(Base):
    __tablename__ = "threat_logs"

    id              = Column(String(36),  primary_key=True, default=_uuid)
    threat_type     = Column(String(64),  nullable=False, index=True)
    severity        = Column(
                        SAEnum("low", "medium", "high", "critical", name="threat_severity"),
                        nullable=False, index=True
                      )
    status          = Column(
                        SAEnum("active", "analyzing", "responding", "resolved",
                               "false_positive", name="threat_status"),
                        nullable=False, default="active", index=True
                      )
    source_ip       = Column(String(45),  nullable=True,  index=True)
    target          = Column(String(255), nullable=True)
    description     = Column(Text,        nullable=False)
    raw_data        = Column(JSON,        nullable=True,  default=dict)
    ai_analysis     = Column(Text,        nullable=True)
    ai_confidence   = Column(Float,       nullable=True)
    response_action = Column(Text,        nullable=True)
    module          = Column(String(64),  nullable=True)
    detected_at     = Column(DateTime,    nullable=False, default=_now, index=True)
    resolved_at     = Column(DateTime,    nullable=True)
    resolution_note = Column(Text,        nullable=True)

    # Composite index for common query: active critical threats
    __table_args__ = (
        Index("ix_tl_severity_status", "severity", "status"),
    )

    def __repr__(self):
        return f"<ThreatLog {self.threat_type} [{self.severity}] {self.status}>"

    def to_dict(self) -> dict:
        return {
            "id":              self.id,
            "threat_type":     self.threat_type,
            "severity":        self.severity,
            "status":          self.status,
            "source_ip":       self.source_ip,
            "target":          self.target,
            "description":     self.description,
            "raw_data":        self.raw_data or {},
            "ai_analysis":     self.ai_analysis,
            "ai_confidence":   self.ai_confidence,
            "response_action": self.response_action,
            "module":          self.module,
            "detected_at":     self.detected_at.isoformat(),
            "resolved_at":     self.resolved_at.isoformat() if self.resolved_at else None,
            "resolution_note": self.resolution_note,
        }


# ─────────────────────────────────────────────────────────────────────
# 3. BLOCKED IPs
# ─────────────────────────────────────────────────────────────────────
class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id          = Column(String(36),  primary_key=True, default=_uuid)
    ip          = Column(String(45),  nullable=False, unique=True, index=True)
    reason      = Column(Text,        nullable=False)
    blocked_by  = Column(String(64),  ForeignKey("users.username"), nullable=True)
    blocked_at  = Column(DateTime,    nullable=False, default=_now)
    expires_at  = Column(DateTime,    nullable=True)   # None = permanent
    is_active   = Column(Boolean,     nullable=False, default=True)

    blocker     = relationship("User", back_populates="blocked_ips",
                               foreign_keys=[blocked_by])

    def __repr__(self):
        return f"<BlockedIP {self.ip}>"

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def to_dict(self) -> dict:
        return {
            "id":         self.id,
            "ip":         self.ip,
            "reason":     self.reason,
            "blocked_by": self.blocked_by,
            "blocked_at": self.blocked_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_active":  self.is_active,
            "is_expired": self.is_expired(),
        }


# ─────────────────────────────────────────────────────────────────────
# 4. SYSTEM EVENTS  (audit log)
# ─────────────────────────────────────────────────────────────────────
class SystemEvent(Base):
    __tablename__ = "system_events"

    id          = Column(String(36),  primary_key=True, default=_uuid)
    event_type  = Column(String(64),  nullable=False, index=True)
    # e.g. "login", "logout", "threat_resolved", "ip_blocked", "config_changed"
    severity    = Column(
                    SAEnum("info", "warning", "error", "critical", name="event_severity"),
                    nullable=False, default="info"
                  )
    username    = Column(String(64),  ForeignKey("users.username"), nullable=True)
    ip_address  = Column(String(45),  nullable=True)
    description = Column(Text,        nullable=False)
    extra_data  = Column(JSON,        nullable=True, default=dict)   # renamed: metadata is reserved
    created_at  = Column(DateTime,    nullable=False, default=_now, index=True)

    user        = relationship("User", back_populates="system_events")

    __table_args__ = (
        Index("ix_se_type_created", "event_type", "created_at"),
    )

    def __repr__(self):
        return f"<SystemEvent {self.event_type} by {self.username}>"

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "event_type":  self.event_type,
            "severity":    self.severity,
            "username":    self.username,
            "ip_address":  self.ip_address,
            "description": self.description,
            "extra_data":  self.extra_data or {},
            "created_at":  self.created_at.isoformat(),
        }


# ─────────────────────────────────────────────────────────────────────
# 5. SCAN RESULTS
# ─────────────────────────────────────────────────────────────────────
class ScanResult(Base):
    __tablename__ = "scan_results"

    id              = Column(String(36),  primary_key=True, default=_uuid)
    scan_type       = Column(String(64),  nullable=False, index=True)
    # e.g. "full", "quick", "network", "file", "process"
    target          = Column(String(255), nullable=False)
    status          = Column(
                        SAEnum("running", "completed", "failed", name="scan_status"),
                        nullable=False, default="running"
                      )
    initiated_by    = Column(String(64),  ForeignKey("users.username"), nullable=True)
    threats_found   = Column(Integer,     nullable=False, default=0)
    duration_secs   = Column(Float,       nullable=True)
    findings        = Column(JSON,        nullable=True, default=list)  # list of threat IDs
    error_message   = Column(Text,        nullable=True)
    started_at      = Column(DateTime,    nullable=False, default=_now, index=True)
    completed_at    = Column(DateTime,    nullable=True)

    def __repr__(self):
        return f"<ScanResult {self.scan_type} on {self.target} [{self.status}]>"

    def to_dict(self) -> dict:
        return {
            "id":            self.id,
            "scan_type":     self.scan_type,
            "target":        self.target,
            "status":        self.status,
            "initiated_by":  self.initiated_by,
            "threats_found": self.threats_found,
            "duration_secs": self.duration_secs,
            "findings":      self.findings or [],
            "error_message": self.error_message,
            "started_at":    self.started_at.isoformat(),
            "completed_at":  self.completed_at.isoformat() if self.completed_at else None,
        }
