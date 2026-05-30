# 🛡️ CyberSentinel — AI-Powered Threat Detection & Response Platform

## Overview
CyberSentinel is a full-spectrum cybersecurity platform that **detects, analyzes, and automatically responds** to threats in real-time using AI.

## Architecture
```
cybersentinel/
├── main.py                    ← FastAPI app + WebSocket server
├── requirements.txt
├── core/
│   ├── threat_engine.py       ← Central threat coordinator
│   └── websocket_manager.py   ← Real-time broadcasting
├── models/
│   └── threat.py              ← Threat dataclass + enums
├── modules/
│   ├── network_monitor.py     ← Port scans, C2, DNS hijack, ARP spoofing
│   ├── auth_monitor.py        ← Brute force, credential stuffing, privesc
│   ├── file_monitor.py        ← Malware hashes, ransomware, malicious scripts
│   ├── malware_scanner.py     ← Viruses, trojans, worms, rootkits, cryptominers
│   ├── response_engine.py     ← Auto-response: block IPs, kill processes, quarantine
│   ├── ai_analyst.py          ← Claude AI threat analysis
│   └── simulator.py           ← Demo threat injection
├── api/routes/
│   ├── threats.py             ← CRUD for threats
│   ├── scanner.py             ← Manual scan trigger
│   ├── network.py             ← Network info
│   ├── auth_guard.py          ← Auth monitoring
│   ├── files.py               ← File upload inspection
│   └── ai_analyst.py          ← AI analysis endpoints
└── utils/
    └── logger.py              ← Structured logging
```

## Detected Threats
| Category | Threats |
|----------|---------|
| **Malware** | Virus, Trojan, Worm, Ransomware, Spyware, Adware, Rootkit, Keylogger, Botnet, Cryptominer, Fileless |
| **Network** | Port Scan, DDoS, MITM, DNS Hijack, ARP Spoofing, C2 Traffic, Intrusion |
| **Auth** | Brute Force, Credential Stuffing, Privilege Escalation |
| **Files** | Malicious Scripts, Suspicious Files, Data Exfiltration |

## Setup & Run

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Start the backend
```bash
python main.py
```
Server runs at: `http://localhost:8000`

### 3. API Docs
Visit: `http://localhost:8000/docs`

## WebSocket Real-Time Feed
```javascript
const ws = new WebSocket("ws://localhost:8000/ws");
ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    // Events: threat_detected, threat_resolved, monitoring_started
    console.log(data);
};

// Start monitoring
ws.send(JSON.stringify({ action: "start_monitoring" }));
```

## Key API Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/threats/` | All detected threats |
| GET | `/api/threats/active` | Active threats only |
| GET | `/api/threats/stats` | Threat statistics |
| POST | `/api/threats/{id}/resolve` | Manually resolve threat |
| POST | `/api/scanner/scan` | Trigger manual scan |
| GET | `/api/network/connections` | Active network connections |
| POST | `/api/files/inspect` | Upload file for inspection |
| POST | `/api/ai/analyze` | AI threat analysis |

## Response Actions
| Threat Type | Auto Response |
|-------------|--------------|
| Port Scan | Block IP via iptables |
| Brute Force | Block IP via iptables |
| Trojan/RAT | Kill process + quarantine file |
| Ransomware | Emergency response + admin alert |
| Cryptominer | Kill process |
| DNS Hijack | Flush DNS cache |
| Rootkit | Admin alert + elevated monitoring |

## Next Steps (Frontend)
Connect a React dashboard to:
1. WebSocket at `ws://localhost:8000/ws`
2. REST endpoints at `http://localhost:8000/api/`
3. Show real-time threat feed with severity colors
4. Display "✅ Threat Resolved" on resolution events
