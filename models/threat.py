"""
Cybersecurity - Threat Model
Defines all threat types, severities, and the Threat dataclass
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import uuid


class ThreatType(str, Enum):
    # Malware types
    VIRUS          = "Virus"
    TROJAN         = "Trojan"
    WORM           = "Worm"
    RANSOMWARE     = "Ransomware"
    SPYWARE        = "Spyware"
    ADWARE         = "Adware"
    ROOTKIT        = "Rootkit"
    KEYLOGGER      = "Keylogger"
    BOTNET         = "Botnet"
    CRYPTOMINER    = "Cryptominer"
    FILELESS       = "Fileless Malware"

    # Network threats
    PORT_SCAN      = "Port Scan"
    DDOS           = "DDoS Attack"
    MITM           = "Man-in-the-Middle"
    DNS_HIJACK     = "DNS Hijacking"
    ARP_SPOOFING   = "ARP Spoofing"
    PACKET_SNIFF   = "Packet Sniffing"
    INTRUSION      = "Network Intrusion"
    C2_TRAFFIC     = "Command & Control Traffic"

    # Auth threats
    BRUTE_FORCE    = "Brute Force Attack"
    CREDENTIAL_STUFF = "Credential Stuffing"
    PRIVILEGE_ESC  = "Privilege Escalation"

    # File threats
    SUSPICIOUS_FILE = "Suspicious File"
    MALICIOUS_SCRIPT = "Malicious Script"
    DATA_EXFIL     = "Data Exfiltration"

    # Other
    ZERO_DAY       = "Zero-Day Exploit"
    PHISHING       = "Phishing Attempt"
    UNKNOWN        = "Unknown Threat"


class ThreatSeverity(str, Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class ThreatStatus(str, Enum):
    ACTIVE     = "active"
    ANALYZING  = "analyzing"
    RESPONDING = "responding"
    RESOLVED   = "resolved"
    FALSE_POSITIVE = "false_positive"


@dataclass
class Threat:
    type: ThreatType
    description: str
    severity: ThreatSeverity
    source: str                        # IP, file path, process name, etc.
    module: str                        # Which detection module found it
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: ThreatStatus = ThreatStatus.ACTIVE
    detected_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    resolved_at: str = ""
    resolution_note: str = ""
    metadata: dict = field(default_factory=dict)
    ai_analysis: str = ""
    recommended_action: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "description": self.description,
            "severity": self.severity,
            "source": self.source,
            "module": self.module,
            "status": self.status,
            "detected_at": self.detected_at,
            "resolved_at": self.resolved_at,
            "resolution_note": self.resolution_note,
            "metadata": self.metadata,
            "ai_analysis": self.ai_analysis,
            "recommended_action": self.recommended_action,
        }
