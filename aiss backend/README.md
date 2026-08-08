# AISS — AI Intelligent Security System

**Enterprise-grade AI-powered cybersecurity platform for real-time threat detection, analysis, and automated response.**

[![License](https://img.shields.io/badge/license-Commercial-blue)](./LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](./Dockerfile)

---

## What is AISS?

AISS is a full-stack AI security operations platform that continuously monitors your infrastructure, detects threats across 30+ attack categories, and responds automatically — all powered by state-of-the-art AI models including Claude, GPT-4, Groq, and local Llama.

---

## Key Capabilities

### Threat Detection (30+ Categories)
| Category | Threats Detected |
|---|---|
| **Malware** | Virus, Trojan, Worm, Ransomware, Spyware, Adware, Rootkit, Keylogger, Botnet, Cryptominer, Fileless |
| **Network** | Port Scan, DDoS, MITM, DNS Hijack, ARP Spoofing, C2 Beaconing, Data Exfiltration, Lateral Movement |
| **Auth** | Brute Force, Credential Stuffing, Privilege Escalation |
| **File** | Malicious Scripts, Suspicious Executables, Office Macros, Packed PE files |
| **AI** | Prompt Injection, Jailbreak, Data Extraction, Model Abuse, Token Flooding |

### AI & Intelligence
- **Multi-LLM Router** — Claude, GPT-4, Groq, Gemini, local Llama with automatic fallback
- **Semantic Threat Search** — vector embeddings (ChromaDB + sentence-transformers)
- **Online ML Anomaly Detection** — River HalfSpaceTrees adapts to your traffic baseline in real-time
- **MITRE ATT&CK Integration** — full ATT&CK framework via pyattck + STIX/TAXII feeds
- **IOC Auto-extraction** — extracts IPs, hashes, CVEs, MITRE techniques from any text
- **SOC Chat Assistant** — conversational security analysis

### Response & Forensics
- **Automated Response** — block IPs, kill processes, quarantine files, flush DNS
- **Evidence Collection** — encrypted forensic snapshots before process termination
- **Kill Chain Analysis** — multi-stage APT detection and correlation
- **YARA Scanning** — real YARA rules on process memory

### Integrations (85+ libraries)
- **Threat Intel** — VirusTotal, Shodan, Censys, GeoIP2
- **Alerts** — 80+ channels via Apprise (Slack, Teams, PagerDuty, Telegram, email)
- **Cloud** — AWS S3, Azure Blob, Kubernetes
- **Observability** — Prometheus, OpenTelemetry, Sentry, Logfire
- **Export** — Excel (xlsxwriter), Plotly dashboards, Matplotlib charts, PDF reports

---

## Quick Start

### Option 1: One-click installer
```bash
python install.py
```

### Option 2: Manual setup
```bash
# 1. Clone and enter directory
cd "aiss backend"

# 2. Create virtual environment
python -m venv .venv
.venv\Scripts\activate    # Windows
source .venv/bin/activate  # Linux/macOS

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env with your API keys

# 5. Run migrations
alembic upgrade head

# 6. Start
python main.py
```

### Option 3: Docker
```bash
cp .env.production.example .env
# Fill in your values
docker-compose up -d
```

API docs: http://localhost:8000/docs
Health: http://localhost:8000/api/health

---

## API Overview

### Authentication
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/register` | Create account |
| POST | `/api/auth/login` | Get JWT tokens |
| POST | `/api/auth/refresh` | Rotate refresh token |
| POST | `/api/auth/logout` | Revoke session |
| GET  | `/api/auth/me` | Current user profile |
| POST | `/api/auth/forgot-password` | Password reset request |

### Threats
| Method | Endpoint | Description |
|---|---|---|
| GET  | `/api/threats/` | All threats |
| GET  | `/api/threats/active` | Active threats only |
| GET  | `/api/threats/stats` | Statistics |
| POST | `/api/threats/{id}/resolve` | Resolve threat |
| GET  | `/api/threats/export/excel` | Export to Excel |
| GET  | `/api/threats/export/chart.png` | PNG chart |
| GET  | `/api/threats/export/dashboard.html` | Plotly dashboard |

### Intelligence
| Method | Endpoint | Description |
|---|---|---|
| GET  | `/api/intel/enrich/ip/{ip}` | VT + Shodan + GeoIP enrichment |
| POST | `/api/intel/ioc/extract` | Extract IOCs from text |
| POST | `/api/intel/phishing/analyze` | Phishing URL analysis |
| POST | `/api/intel/semantic/search` | Semantic threat search |
| POST | `/api/intel/llm/analyze` | AI threat analysis |
| POST | `/api/intel/anomaly/score` | Online ML anomaly score |

### System
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/system/health` | System metrics |
| GET | `/api/system/libraries` | Library status |
| GET | `/api/system/llm-providers` | Available LLM providers |
| GET | `/api/system/semantic-store` | Vector store stats |
| GET | `/metrics` | Prometheus metrics |

### WebSocket
```javascript
const ws = new WebSocket("ws://localhost:8000/ws");
// First message must be auth
ws.send(JSON.stringify({ action: "auth", token: "<jwt>" }));
ws.onmessage = ({ data }) => console.log(JSON.parse(data));
// Events: threat_detected, threat_resolved, monitoring_started
ws.send(JSON.stringify({ action: "start_monitoring" }));
```

---

## Licensing

AISS uses a commercial licensing model:

| Plan | Seats | Features |
|---|---|---|
| Trial | 1 | Core detection, basic AI, 14 days |
| Standard | 5 | + Auto-response, Excel export, YARA |
| Enterprise | Unlimited | + SSO, white-label, cloud backup, audit log |

Set `AISS_LICENSE_KEY` in `.env`. Contact licensing@aiss.io.

---

## Documentation

- [INSTALL.md](./INSTALL.md) — Detailed installation guide
- [DEPLOYMENT.md](./DEPLOYMENT.md) — Production deployment
- [SECURITY.md](./SECURITY.md) — Security policy and hardening
- [ARCHITECTURE.md](./ARCHITECTURE.md) — System architecture
- [CHANGELOG.md](./CHANGELOG.md) — Version history
