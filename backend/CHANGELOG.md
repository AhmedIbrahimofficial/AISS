# AISS — Changelog

All notable changes are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).

---

## [2.1.0] — 2026-08-07

### Added — Single Command Launcher
- `aiss.py` — Type `python aiss.py` (or just `aiss`) for everything:
  - Auto-detects 120+ already-installed packages, skips them
  - Installs only missing packages with live per-package progress bar
  - Auto-generates secure keys (SECRET_KEY, EVIDENCE_ENCRYPTION_KEY)
  - Runs DB migrations, downloads ML models, integrates all libraries
  - Registers `aiss` as global system command (Windows PATH / Linux /usr/local/bin)
  - Shows setup wizard questions in CMD
  - Starts backend + opens browser
- `aiss.bat` — Windows launcher (UTF-8, ANSI colours, passes all flags)
- `aiss.sh`  — Linux/macOS launcher (auto-finds venv/system Python)
- `monitor.py` — Live CMD dashboard: threats, agents, metrics, severity bars
- `aiss_agent.py` — Standalone agent for remote machines (LAN/WAN/VPN/MAN)

### Added — Multi-Computer Monitoring
- `modules/remote_agent.py` — Remote agent WebSocket manager
  - Token-based authentication (HMAC-SHA256)
  - Per-agent heartbeat, metrics, threat forwarding
  - Automatic network type classification (LAN/WAN/VPN/MAN)
- `api/routes/agents.py` — REST API for agent management
  - `POST /api/agents/token/generate` — create auth token
  - `GET  /api/agents/`               — list all agents + stats
  - `GET  /api/agents/{id}/threats`   — agent threat history
  - `POST /api/agents/{id}/command`   — send command to agent
- `WS /ws/agent` — WebSocket endpoint for remote agents

### Added — Network Topology
- `modules/network_topology.py` — Full topology manager
  - Auto-discovers all local network interfaces
  - Classifies each interface/IP as LAN/WAN/VPN/MAN/loopback
  - Maintains node/edge graph of all known devices
  - Exports topology map for D3.js/Cytoscape/React-Flow
- `api/routes/topology.py` — Topology REST API
  - `GET  /api/topology/map`       — full network map (nodes + edges)
  - `GET  /api/topology/segments`  — known network segments
  - `POST /api/topology/segments`  — add new segment to monitor
  - `GET  /api/topology/interfaces`— local network interfaces
  - `POST /api/topology/scan`      — discover hosts on all segments
  - `GET  /api/topology/agents`    — agents with network positions

### Added — Setup Wizard & Popup System
- `modules/setup_wizard.py` — 10-step configuration wizard
  - 24+ questions covering all AISS settings
  - CMD mode: interactive terminal questions
  - Frontend mode: auto-sends as popup dialogs on WS connect
  - Saves all answers to `.env` automatically
  - New modules can register their own questions via `register_module_questions()`
- `modules/frontend_bridge.py` — Auto popup injection engine
  - Queues popups for frontend; sends immediately when connected
  - Persists state in `data/popup_state.json`
  - `register_popup()` — any module can add its own popup question
  - Frontend WS receives: `{event: "wizard_start", questions: [...]}`
  - Frontend responds: `{action: "popup_answer", question_id, value}`
  - Auto-writes answers to `.env`

### Added — API Endpoints
- `GET  /api/system/wizard`         — get all wizard questions + current values
- `POST /api/system/wizard/apply`   — apply wizard answers to .env
- `GET  /api/system/popup-status`   — wizard completion status
- `POST /api/system/popup-answer`   — submit single popup answer (REST fallback)
- `WS   /ws` (enhanced)            — now auto-sends wizard popups on frontend connect
  - Handles `popup_answer` and `popup_dismiss` actions

### Added — Background Tasks (Celery)
- `topology_scan_task`    — discovers hosts on all registered network segments
- `agent_health_task`     — marks idle agents (no heartbeat > 60s)
- `analyze_document_task` — deep file analysis in background
- `llm_batch_task`        — process multiple LLM prompts in background

### Changed
- `main.py` — 5 APScheduler jobs (was 3): added topology refresh + agent health
- `main.py` — WS /ws endpoint now handles popup_answer/popup_dismiss actions
- `main.py` — Added /ws/agent WebSocket endpoint for remote agents
- `tasks.py` — 7 Celery tasks (was 3): added topology, agent health, doc analysis, LLM batch
- `aiss.bat` — Rewrote with UTF-8, ANSI, flag documentation, venv detection
- `aiss.sh`  — Rewrote with Python version check and venv detection



### Added — Security & Production Hardening
- Commercial licensing system with trial/standard/enterprise/developer tiers
- Startup validation system with pre-launch checks (DB, Redis, keys, dirs)
- Automatic cryptographic key generation on first launch
- `SecurityConfig` module — centralised secret resolution with auto-generation
- Full security middleware stack: CSP, HSTS, request size limits, path traversal protection, license validation
- `.env.example`, `.env.production.example`, `.env.development.example` templates
- Dockerfile (multi-stage, non-root user, health check)
- `docker-compose.yml` (AISS + Celery + PostgreSQL + Redis + Nginx)
- Nginx reverse proxy config with TLS, rate limiting, WebSocket support
- One-click installer (`install.py`) for Windows/Linux/macOS
- `requirements-dev.txt` and `requirements-prod.txt`
- Complete test suite: security, API, licensing, module tests

### Added — AI & Intelligence
- Multi-provider LLM router (`llm_router.py`) — Claude → GPT → Groq → Gemini → Llama fallback
- Semantic threat vector store (`semantic_threat_store.py`) — ChromaDB + sentence-transformers
- Online ML anomaly detector (`online_anomaly_detector.py`) — River HalfSpaceTrees
- IOC auto-extractor (`ioc_extractor.py`) — ioc_finder + ioc_fanger + spaCy NER
- Phishing URL analyzer (`phishing_analyzer.py`) — multi-layer scoring + Playwright
- Document intelligence (`document_analyzer.py`) — pymupdf + oletools + pefile + easyocr + docling
- Voice alerts (`voice_alerts.py`) — edge-tts / pyttsx3

### Added — Integrations (85 libraries)
- `lib_registry.py` — auto-detects and initialises all installed libraries at startup
- Custom Prometheus metrics (`metrics.py`) — 8 custom metrics for threats, LLM, anomaly, scans
- Report exporter (`report_exporter.py`) — Excel (xlsxwriter/openpyxl), Plotly HTML, Matplotlib PNG
- Token counter (`token_counter.py`) — tiktoken token counting + cost estimation
- OAuth helper (`oauth_helper.py`) — Authlib social login (Google/GitHub/Microsoft)

### Added — API Endpoints
- `GET /api/system/libraries` — all library integration statuses
- `GET /api/system/llm-providers` — available LLM providers
- `GET /api/system/semantic-store` — vector store stats
- `GET /api/system/anomaly-detector` — online ML stats
- `POST /api/intel/ioc/extract` — IOC extraction from text
- `POST /api/intel/phishing/analyze` — phishing URL analysis
- `POST /api/intel/semantic/search` — semantic threat similarity search
- `POST /api/intel/llm/analyze` — multi-provider AI analysis
- `POST /api/intel/anomaly/score` — online anomaly scoring
- `POST /api/files/analyze` — deep document analysis
- `GET /api/threats/export/excel` — Excel export
- `GET /api/threats/export/chart.png` — PNG chart export
- `GET /api/threats/export/dashboard.html` — Plotly dashboard export
- `GET /api/threats/export/status` — export capability status

### Changed
- `core/middleware.py` — complete rewrite with all 6 security middlewares
- `main.py` — integrated security config, licensing, startup validation
- `core/threat_engine.py` — 4 new pipeline hooks + Prometheus metrics
- `modules/response_engine.py` — Prometheus blocked IPs gauge
- `README.md` — complete rewrite (was referencing CyberSentinel)

### Removed — Security
- `admin_passwords.txt` — contained plaintext passwords
- `.env.backup.txt` — contained hardcoded credentials
- `config.json.txt` — contained hardcoded DB passwords
- `database.sql.txt` — contained hardcoded DB schema with fake passwords
- All real API keys scrubbed from `.env`

### Fixed
- JWT default `SECRET_KEY` fallback replaced with auto-generation
- Evidence encryption key no longer committed to repository
- `INTERNAL_SERVICE_TOKEN` default value replaced with auto-generation

---

## [1.5.0] — 2026-07-15

### Added
- STIX/TAXII threat feed ingestion (6-hour scheduled job)
- YARA rule scanning with real yara-python
- Sigma rule loading and matching
- Network discovery module (LAN scanning, port enumeration, banner grabbing)
- Kill chain analysis and APT detection
- Apprise multi-channel alerts
- APScheduler background jobs

### Changed
- Malware scanner upgraded with psutil deep process inspection
- Network monitor upgraded with River + IsolationForest ML scoring
- AI analyst upgraded to support both Claude and GPT with fallback

---

## [1.0.0] — 2026-06-01

### Added
- Initial AISS release
- FastAPI backend with JWT auth
- Real-time WebSocket threat feed
- Network, auth, file, malware detection modules
- Claude AI threat analysis
- VirusTotal + Shodan enrichment
- GeoIP2 enrichment
- Evidence encryption
- Prometheus instrumentation
- SQLAlchemy multi-database support
