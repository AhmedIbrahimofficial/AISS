"""Network Discovery — SQLAlchemy ORM model for persisting scan results."""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, Text, DateTime, JSON, Enum as SAEnum
from core.models import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.utcnow()


class NetworkScan(Base):
    """Persists every network discovery / port scan result."""
    __tablename__ = "network_scans"

    id              = Column(String(36),  primary_key=True, default=_uuid)
    scan_type       = Column(String(32),  nullable=False, index=True)
    # host_discovery | port_scan | service_detection | full_scan
    target          = Column(String(255), nullable=False, index=True)
    status          = Column(
                        SAEnum("running", "completed", "failed", name="nd_scan_status"),
                        nullable=False, default="running"
                      )
    hosts_found     = Column(Integer,    nullable=False, default=0)
    hosts_up        = Column(Integer,    nullable=False, default=0)
    open_ports_count = Column(Integer,   nullable=False, default=0)
    duration_secs   = Column(Float,      nullable=True)
    result          = Column(JSON,       nullable=True)   # full DiscoveryResult dict
    error_message   = Column(Text,       nullable=True)
    initiated_by    = Column(String(64), nullable=True)
    started_at      = Column(DateTime,   nullable=False, default=_now, index=True)
    completed_at    = Column(DateTime,   nullable=True)

    def to_dict(self) -> dict:
        return {
            "id":               self.id,
            "scan_type":        self.scan_type,
            "target":           self.target,
            "status":           self.status,
            "hosts_found":      self.hosts_found,
            "hosts_up":         self.hosts_up,
            "open_ports_count": self.open_ports_count,
            "duration_secs":    self.duration_secs,
            "error_message":    self.error_message,
            "initiated_by":     self.initiated_by,
            "started_at":       self.started_at.isoformat(),
            "completed_at":     self.completed_at.isoformat() if self.completed_at else None,
        }
