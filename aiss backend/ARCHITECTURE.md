# AISS — System Architecture

## Overview

```
┌─────────────────────────────────────────────────────────────┐
│                         AISS Backend                         │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐  │
│  │ FastAPI  │  │ WebSocket│  │ Celery   │  │ Prometheus│  │
│  │  REST    │  │ Real-time│  │ Workers  │  │ /metrics  │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └───────────┘  │
│       │             │             │                          │
│  ┌────▼─────────────▼─────────────▼─────────────────────┐  │
│  │              Core Services Layer                       │  │
│  │  ThreatEngine │ LicenseManager │ SecurityConfig        │  │
│  │  WebSocketManager │ LibRegistry │ Metrics               │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Detection Modules                         │  │
│  │  NetworkMonitor │ MalwareScanner │ AuthMonitor         │  │
│  │  FileMonitor │ USBMonitor │ SystemMonitor               │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              AI & Intelligence                         │  │
│  │  LLMRouter │ AIAnalyst │ SemanticThreatStore           │  │
│  │  OnlineAnomalyDetector │ IOCExtractor                  │  │
│  │  KillChain │ SigmaLoader │ YARAScanner                 │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Data & Storage                            │  │
│  │  SQLAlchemy (PostgreSQL/MySQL/SQLite)                  │  │
│  │  ChromaDB (vectors) │ Redis (cache/queue)              │  │
│  │  Evidence Files (Fernet-encrypted)                    │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
aiss backend/
├── main.py                    # FastAPI app + lifespan
├── install.py                 # One-click installer
├── alembic.ini
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
│
├── core/                      # Framework core
│   ├── auth.py                # JWT token utilities
│   ├── database.py            # SQLAlchemy async engine
│   ├── dependencies.py        # FastAPI DI singletons
│   ├── licensing.py           # Commercial licensing system
│   ├── metrics.py             # Prometheus custom metrics
│   ├── middleware.py          # Security middleware stack
│   ├── models.py              # SQLAlchemy ORM models
│   ├── security_config.py     # Secret management + validation
│   ├── startup_validator.py   # Pre-launch checklist
│   ├── threat_engine.py       # Central threat orchestration
│   └── websocket_manager.py   # WS broadcast manager
│
├── api/routes/                # REST endpoints
│   ├── threats.py             # CRUD + export
│   ├── intel.py               # IOC, phishing, semantic, LLM
│   ├── scanner.py             # Manual scan trigger
│   ├── network.py             # Network info
│   ├── files.py               # File analysis
│   ├── ai_analyst.py          # Direct AI analysis
│   ├── soc_chat.py            # SOC assistant
│   ├── kill_chain.py          # Kill chain API
│   ├── ai_firewall.py         # AI prompt firewall
│   ├── learning.py            # Self-learning
│   ├── dataset.py             # Dataset management
│   ├── system_health.py       # Health + library status
│   └── network_discovery.py   # LAN discovery
│
├── auth/                      # Auth subsystem
│   ├── router.py              # Auth endpoints
│   ├── service.py             # Business logic
│   ├── models.py              # Auth ORM models
│   ├── schemas.py             # Pydantic schemas
│   └── utils/                 # tokens, password, email, otp
│
├── modules/                   # Detection & analysis modules
│   ├── ai_analyst.py          # Claude/GPT threat analysis
│   ├── ai_firewall.py         # Prompt injection protection
│   ├── alert_manager.py       # Apprise multi-channel alerts
│   ├── auth_monitor.py        # Auth failure detection
│   ├── celery_app.py          # Task queue config
│   ├── dataset_loader.py      # CSV dataset → thresholds
│   ├── document_analyzer.py   # PDF/Office/PE deep analysis
│   ├── evidence_crypto.py     # Fernet evidence encryption
│   ├── file_monitor.py        # Filesystem monitoring
│   ├── geo_lookup.py          # MaxMind GeoIP2
│   ├── ioc_extractor.py       # IOC auto-extraction
│   ├── keyword_learner.py     # YouTube threat learning
│   ├── llm_router.py          # Multi-provider LLM router
│   ├── malware_scanner.py     # Process + YARA scanning
│   ├── network_monitor.py     # Network threat detection
│   ├── online_anomaly_detector.py  # River online ML
│   ├── phishing_analyzer.py   # URL phishing analysis
│   ├── report_exporter.py     # Excel/Plotly/PNG reports
│   ├── response_engine.py     # Automated incident response
│   ├── self_learner.py        # YouTube-based self-learning
│   ├── semantic_threat_store.py  # ChromaDB vector store
│   ├── sigma_loader.py        # Sigma rule loading
│   ├── threat_intel.py        # VT + Shodan enrichment
│   ├── threat_intel_feeds.py  # STIX/TAXII ingestion
│   ├── voice_alerts.py        # TTS voice alerts
│   └── yara_scanner.py        # YARA rule engine
│
├── utils/
│   ├── logger.py              # structlog dual-mode logging
│   ├── oauth_helper.py        # Authlib social login
│   └── token_counter.py       # tiktoken LLM token counting
│
├── tests/                     # Test suite
│   ├── test_security.py       # Secret hygiene, JWT, headers
│   ├── test_api.py            # API endpoint integration
│   ├── test_licensing.py      # License system tests
│   └── test_modules.py        # Module unit tests
│
├── rules/                     # Detection rules
│   ├── malware_strings.yar
│   ├── reverse_shell.yar
│   └── sigma_rules.yml
│
├── data/                      # Runtime data (gitignored)
│   ├── GeoLite2-City.mmdb     # GeoIP database
│   ├── dataset_patterns.json  # Computed ML thresholds
│   ├── online_model.pkl       # River model state
│   ├── chroma_db/             # ChromaDB vector store
│   └── models/                # Downloaded ML models
│
└── deploy/
    └── nginx/
        ├── aiss.conf          # Nginx reverse proxy config
        └── ssl/               # TLS certificates
```

## New Files Created (this session)

```
modules/remote_agent.py        — Multi-computer remote agent system
modules/setup_wizard.py        — Setup wizard (popup questions engine)
modules/frontend_bridge.py     — Auto popup injection into frontend
modules/network_topology.py    — LAN/WAN/VPN/MAN topology manager
api/routes/agents.py           — Remote agents REST API
api/routes/topology.py         — Network topology REST API
aiss_agent.py                  — Standalone agent for remote machines
aiss.py                        — Single-command launcher (type: aiss)
aiss.bat                       — Windows: registers 'aiss' globally
aiss.sh                        — Linux/macOS: registers 'aiss' globally
```

## Remote Agent Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  AISS Server (your main machine)                                │
│                                                                 │
│  POST /api/agents/token/generate → get TOKEN                   │
│  GET  /api/topology/map          → full network map            │
│  GET  /api/agents/               → all connected machines      │
│  WS   /ws/agent                  → agent connection endpoint   │
└──────────────────────────┬──────────────────────────────────────┘
                           │  WebSocket (ws:// or wss://)
         ┌─────────────────┼─────────────────┐
         │                 │                 │
  ┌──────▼──────┐  ┌───────▼──────┐  ┌──────▼──────┐
  │  LAN PC     │  │  WAN Server  │  │  VPN Client │
  │ 192.168.x.x │  │ 203.0.113.x  │  │ 10.8.x.x    │
  │             │  │              │  │             │
  │ aiss_agent  │  │ aiss_agent   │  │ aiss_agent  │
  │ .py         │  │ .py          │  │ .py         │
  └─────────────┘  └──────────────┘  └─────────────┘
```

## Single Command Usage

```bash
# First time (installs everything, asks setup questions):
python aiss.py

# After registration — just type:
aiss

# Re-run configuration wizard:
aiss --wizard

# Force reinstall all packages:
aiss --reinstall

# Install only (no server start):
aiss --install-only
```

## Setup Wizard — Popup System

When frontend is connected via WebSocket, AISS automatically sends
configuration questions as popup dialogs on first connection.

```
Frontend WS connect → { event: "wizard_start", questions: [...] }
User fills popup    → { action: "popup_answer", question_id: "...", value: "..." }
AISS saves to .env  → confirmed automatically
```

New modules register their own questions:
```python
from modules.frontend_bridge import register_popup
register_popup({
    "id": "MY_API_KEY",
    "title": "My Service",
    "label": "Enter your API key",
    "type": "password",
    "step": "3_ai",
})
# → appears automatically in next frontend popup batch
```


```
Event (network/process/file/auth)
    │
    ▼
Detection Module (scan every 5s)
    │
    ▼
ThreatEngine.register_threat()
    │
    ├── Deduplication (60s window)
    ├── Geo enrichment (GeoIP2)
    ├── Intel enrichment (VT + Shodan, async)
    ├── Persist to DB
    ├── WebSocket broadcast
    ├── Prometheus metrics
    ├── Semantic vector store (ChromaDB)
    ├── IOC extraction (spaCy + ioc_finder)
    ├── Online ML learning (River)
    ├── Voice alert (CRITICAL only)
    ├── Apprise alert (HIGH+)
    ├── Correlation analysis (5-min window)
    └── Attack chain detection (MITRE ATT&CK)
```

## LLM Provider Fallback Chain

```
Request → LiteLLM Router
    │
    ├── 1. Anthropic Claude (if ANTHROPIC_API_KEY)
    ├── 2. OpenAI GPT (if OPENAI_API_KEY)
    ├── 3. Groq (if GROQ_API_KEY — ultra-fast)
    ├── 4. Google Gemini (if GOOGLE_API_KEY)
    └── 5. Local Llama (if LLAMA_MODEL_PATH — offline)
```

## License Validation Flow

```
Startup
    │
    ├── AISS_LICENSE_KEY not set → Trial mode (14 days, limited features)
    ├── Key starts with AISS-DEV- → Developer mode (unlimited)
    ├── AISS_LICENSE_SERVER configured → Online validation (HMAC-signed response)
    └── No server → Offline validation (key format + device binding)
```
