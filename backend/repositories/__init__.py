# Repositories package — exports all repository classes
from .scan_repository import ScanRepository
from .threat_repository import ThreatRepository

__all__ = ["ScanRepository", "ThreatRepository"]
