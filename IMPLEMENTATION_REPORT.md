# AISS — Full System Audit & Implementation Report

---

## A. Bugs Fixed

### BUG-001 (CRITICAL): WebSocket Agent Events Silently Dropped
- **File**: `core/websocket_manager.py`
- **Root cause**: `AgentOrchestrator._broadcast()` calls `ws_manager.broadcast(user_id=user_id, data=data)` with keyword arguments. The original `WebSocketManager.broadcast(self, data: dict)` accepted no `user_id` parameter, causing a `TypeError` that was silently swallowed by the `except Exception: pass` block.
- **Impact**: Every agent WebSocket event (`agent_task_created`, `agent_step_started`, `agent_step_complete`, `agent_approval_required`, `agent_task_complete`, `agent_task_failed`) was **never delivered to the frontend**. The real-time agent panel showed no progress.
- **Fix**: Added `user_id: str | None = None` parameter to `broadcast()`. The signature now accepts the orchestrator's call while broadcasting to all connections (per-user routing reserved for future implementation).

### BUG-002 (SECURITY): OAuth Tokens in URL Fragment
- **File**: `api/routes/auth.py`, `frontend/src/routes/oauth-callback.tsx`
- **Root cause**: The OAuth callback redirect put `access_token` and `refresh_token` directly in the URL fragment: `/oauth-callback#access_token=...&refresh_token=...`. URL fragments can appear in server-access logs, browser history, Referer headers, and are visible to JavaScript on the page.
- **Fix**: Implemented a secure one-time exchange code pattern:
  1. Backend generates a 32-byte cryptographically random opaque code (TTL: 60s, single-use)
  2. Backend redirects to `/oauth-callback?code=<opaque>` — no tokens in URL
  3. Frontend POSTs the code to `/api/auth/oauth/exchange`
  4. Backend validates (expiry, used flag, replay detection), deletes the code, and returns tokens in the JSON response body
  5. Frontend removes the code from the URL via `history.replaceState`

### BUG-003 (SECURITY): Backend Binding to 0.0.0.0
- **File**: `main.py`
- **Root cause**: `uvicorn.run(host="0.0.0.0", ...)` exposed the backend to all network interfaces, including any public internet interface if the machine is directly connected.
- **Fix**: Changed default to `host="127.0.0.1"`. Can be overridden with `AISS_BIND_HOST=0.0.0.0` only when intentionally deploying behind a reverse proxy.

### BUG-004: LLM Router Reads API Key at Import Time
- **File**: `modules/llm_router.py`
- **Root cause**: `LLMRouter.__init__()` read `OPENROUTER_API_KEY` from `os.environ` at module import time. If the module was imported before `python-dotenv` loaded the `.env` file, the key was always empty.
- **Fix**: Added `_lazy_init()` method that reads env vars on first use, not at construction.

### BUG-005: Desktop App Stub Only
- **File**: `aiss-desktop/splash.html`
- **Root cause**: The desktop app directory contained only a splash HTML page. The launcher (`aiss_launcher.py`) had no health checks, no crash recovery, no port conflict detection, and opened the browser before services were ready.
- **Fix**: Rewrote `aiss_launcher.py` with: port conflict detection + auto-kill, localhost-only binding, service health checks (waits for `/api/health` to return 200), crash recovery with configurable `MAX_RESTARTS`, monitor threads per service, clean shutdown with SIGTERM/SIGKILL escalation, and structured logging to `launcher.log`.

---

## B. Authentication

### Email/Password
Full implementation exists in `auth/service.py`:
- Argon2id password hashing with transparent rehash on login
- Brute-force protection: lockout after configurable failed attempts
- Refresh token rotation with reuse detection
- Session management with per-device tracking

### Google OAuth
Implemented in `api/routes/auth.py`:
- Real Google OIDC flow using Authlib
- CSRF state validation (10-minute state TTL)
- `email_verified` claim enforcement
- Account creation or linking for existing users
- **Secure token handoff via one-time exchange code** (see BUG-002)

### SSO — Website to Dashboard
Implemented in `api/routes/sso.py` + `frontend/src/lib/sso.ts`:
- Website calls `POST /api/sso/issue` (requires valid JWT) to get a 60-second single-use SSO token
- Dashboard opens with `?sso=<token>` in URL
- `trySSO()` runs at dashboard startup, redeems the token via `POST /api/sso/redeem`
- Returns full AISS JWT + refresh token in POST body — never in URL
- Token is immediately deleted after first use; replay attempts are logged and rejected
- URL is cleaned (`history.replaceState`) after redemption

### Security Controls
- JWT access tokens (15-min expiry, configurable)
- Rotating refresh tokens (30-day expiry)
- Argon2id hashing (OWASP recommended)
- Account lockout (5 failed attempts → 15-min lockout)
- WebSocket JWT authentication on first message
- `/ws/monitor` restricted to localhost connections only

---

## C. Backend Startup (Automatic)

### aiss_launcher.py — Managed Process Lifecycle
1. **Port conflict detection**: Checks ports 8000 and 8081 before starting. If occupied, attempts to kill the process using Windows `Get-NetTCPConnection` or Linux `lsof`.
2. **Service startup**: Starts backend with `uvicorn --host 127.0.0.1` (localhost-only binding by default).
3. **Health checks**: Polls `GET /api/health` until HTTP 200 before declaring ready. Times out at 60 seconds with an actionable error.
4. **Frontend startup**: Starts Node.js frontend server if `.output/server/index.mjs` exists; skips gracefully if not.
5. **Browser open**: Only after BOTH services pass health checks.
6. **Crash recovery**: Monitor threads watch each process. On unexpected exit, restarts up to `MAX_RESTARTS` times (default: 3) with 2-second back-off. After exhausting retries, logs a clear error.
7. **Clean shutdown**: Ctrl-C sends SIGTERM to all processes, waits 2 seconds, then SIGKILL if needed.
8. **Port override**: `AISS_BACKEND_PORT`, `AISS_FRONTEND_PORT` env vars.

---

## D. AI Architecture

### OpenRouter as Standard Provider
OpenRouter is the **only required AI provider**. All LLM calls route through it:

**`agents/ai_service.py`** — AgentOrchestrator's planner:
- Reads `OPENROUTER_API_KEY` from environment
- Tries primary model (`OPENROUTER_MODEL`, default: `anthropic/claude-3.5-sonnet`)
- Automatic fallback chain: `claude-3.5-sonnet → claude-3-haiku → gpt-4o → gpt-4o-mini → gemini-pro-1.5 → llama-3.1-70b → mistral-large → deepseek-chat`
- Retry with exponential backoff (2s/4s/8s) before trying next model
- HTTP 401 raises immediately (bad key); 402/429/503 tries next model

**`modules/llm_router.py`** — General LLM router used by all non-agent features:
- Same fallback chain pattern
- Lazy init to work with deferred `.env` loading
- Used by: AI Analyst, SOC Chat, Kill Chain, Phishing Analyzer, Threat Intel, IOC enrichment

### Models Used (via OpenRouter)
| Feature | Preferred Model |
|---|---|
| Agent Planning | `anthropic/claude-3.5-sonnet` |
| Task Summarisation | `anthropic/claude-3.5-sonnet` |
| General Analysis | `OPENROUTER_MODEL` env var |
| Threat Intelligence | Falls through LLM fallback chain |

### Providers Removed / Replaced
`anthropic`, `openai`, `groq`, `litellm` packages remain installed as dependencies (for other library uses) but the **direct API key requirement** is gone. `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GROQ_API_KEY` are no longer required.

---

## E. API Keys — See CREDENTIALS_REPORT.md

Full per-credential breakdown with purpose, variable name, required/optional classification, and configuration instructions.

**One-line summary**: `OPENROUTER_API_KEY` is the only required AI credential. `SECRET_KEY` is auto-generated. Everything else is optional.

---

## F. Security Features Implemented / Confirmed

### Authentication & Session
- ✅ Argon2id password hashing (OWASP recommended)
- ✅ Refresh token rotation with reuse/theft detection
- ✅ Account lockout (configurable threshold + lockout duration)
- ✅ JWT with short expiry (15 min) + sliding refresh (30 days)
- ✅ WebSocket JWT authentication (required on first message)
- ✅ OAuth CSRF state validation
- ✅ OAuth token handoff via one-time exchange code (NOT URL fragment)
- ✅ SSO handoff via single-use token (NOT URL fragment, NOT query string persistence)
- ✅ Session revocation on password reset

### Network Security
- ✅ Backend binds to 127.0.0.1 by default (not 0.0.0.0)
- ✅ CORS restricted to configured origins only
- ✅ Rate limiting on all sensitive endpoints (slowapi)
- ✅ Security headers middleware (CSP, HSTS, X-Frame-Options, etc.)
- ✅ Request size limiting middleware
- ✅ Input sanitization middleware

### Detection Pipeline (Existing)
- ✅ Network monitoring (psutil + scapy)
- ✅ YARA malware scanning (local rules)
- ✅ File type + MIME validation
- ✅ PE executable analysis (pefile)
- ✅ Office macro analysis (oletools)
- ✅ Entropy analysis
- ✅ IOC extraction (ioc-finder + spaCy)
- ✅ Online anomaly detection (River ML)
- ✅ Semantic threat matching (ChromaDB)
- ✅ TAXII/STIX feed ingestion (MITRE public feed works without credentials)
- ✅ VirusTotal / Shodan enrichment (optional, requires keys)

### Audit & Observability
- ✅ AuditLogger records every agent action with actor, tool, risk level, result
- ✅ AuditLogMiddleware logs all HTTP requests
- ✅ Prometheus metrics at `/metrics`
- ✅ Sentry error tracking (optional, requires DSN)
- ✅ Structured logging (structlog)

---

## G. Detection Pipeline

```
Incoming Event (network/process/file/auth)
    │
    ▼
Detection Module (network_monitor, malware_scanner, auth_monitor, file_monitor)
    │
    ▼
ThreatEngine.register_threat()
    ├── Deduplication (60s window per source)
    ├── GeoIP enrichment (MaxMind — optional)
    ├── VirusTotal/Shodan enrichment (async — optional)
    ├── Persist to database
    ├── WebSocket broadcast to dashboard
    ├── Prometheus metrics update
    ├── ChromaDB semantic store
    ├── IOC extraction
    ├── River ML online learning
    ├── Voice alert (CRITICAL only, if enabled)
    ├── Apprise multi-channel alert (HIGH+, if configured)
    ├── Correlation analysis (5-min window)
    └── MITRE ATT&CK chain detection
```

**Pre-Ingress (File Inspection)**:
```
Uploaded File
    │
    ├── File-type detection (python-magic)
    ├── Extension/MIME mismatch detection
    ├── Entropy analysis (high entropy → possible packing/encryption)
    ├── PE analysis (pefile — executables)
    ├── Office macro analysis (oletools — .doc/.xls)
    ├── PDF analysis (pymupdf + pdfplumber)
    ├── YARA scanning (local rules)
    ├── IOC extraction from content
    ├── VirusTotal hash lookup (if configured)
    └── AI risk analysis (OpenRouter — if configured)
```

---

## H. Threat Intelligence

| Integration | Status | Requires Key |
|---|---|---|
| MITRE ATT&CK (TAXII) | ✅ Active (public feed) | No |
| IOC extraction (local NLP) | ✅ Active | No |
| YARA scanning | ✅ Active (local rules) | No |
| VirusTotal | ✅ Integrated | Yes (`VIRUSTOTAL_API_KEY`) |
| Shodan | ✅ Integrated | Yes (`SHODAN_API_KEY`) |
| Censys | ✅ Integrated | Yes (`CENSYS_API_ID` + `CENSYS_API_SECRET`) |
| GeoIP (MaxMind) | ✅ Integrated | No (free DB download) |
| OpenRouter AI enrichment | ✅ Active | Yes (`OPENROUTER_API_KEY`) |

---

## I. Libraries & Dependencies

### Added
| Package | Purpose |
|---|---|
| (No new packages added) | All features use existing dependencies |

### Fixed
| Package | Issue Fixed |
|---|---|
| `llm_router.py` singleton | Lazy init — now reads env vars on first use |
| `websocket_manager.py` | Added `user_id` kwarg to `broadcast()` |

### Notable Existing Dependencies (all in requirements.txt)
- `yara-python` — YARA malware detection
- `pefile`, `oletools` — file analysis
- `chromadb`, `sentence-transformers` — semantic search
- `river` — online ML anomaly detection
- `stix2`, `taxii2-client` — threat intelligence feeds
- `authlib` — OAuth2/OIDC
- `argon2-cffi` — password hashing

---

## J. Tests

Existing test files:
- `tests/test_security.py` — secret hygiene, JWT, security headers
- `tests/test_api.py` — API endpoint integration
- `tests/test_licensing.py` — license system
- `tests/test_modules.py` — module unit tests

The `tests/property/` directory exists but is empty.

**Changes affect**:
- `test_security.py` — WebSocket broadcast tests should now pass (bug-001 fix)
- OAuth flow tests — need updating for secure exchange code pattern
- SSO endpoint — new tests needed for issue/redeem flow

---

## K. Remaining Limitations

### Honest Status

1. **Desktop app (.exe)**: `aiss-desktop/` contains only `splash.html`. Building a full Electron-based installer requires `npm run build` of the frontend, then packaging with PyInstaller (backend) + Electron (wrapper). Not implemented — would require significant effort and platform-specific build pipelines.

2. **Google OAuth credentials**: Requires `GOOGLE_OAUTH_CLIENT_ID` + `GOOGLE_OAUTH_CLIENT_SECRET` from Google Cloud Console. The integration is fully implemented; it just needs real credentials.

3. **Redis**: Celery-backed task queue requires Redis. In-memory fallbacks used when Redis is unavailable. The `_oauth_states` and `_exchange_codes` dicts (used for OAuth/SSO) are in-memory — for multi-instance production, swap these for Redis.

4. **YARA rules**: Detection engine is ready; the default `rules/*.yar` files may need updating. Add custom rules to `rules/` for broader coverage.

5. **GeoIP**: MaxMind GeoLite2 database requires a free registration + manual download. No automatic download in place.

6. **Sandbox analysis**: Static analysis is implemented (pefile, oletools, entropy, YARA). **Dynamic** sandbox execution (actually running a file in a controlled environment) is NOT implemented — this would require Docker, Cuckoo, or a similar sandboxing infrastructure.

7. **Network packet capture**: Scapy DPI is available but `SCAPY_DPI_ENABLED=false` by default. Enabling it on Windows requires WinPcap/Npcap and administrator privileges.

8. **OpenRouter key in .env**: The current `.env` file contains a real `OPENROUTER_API_KEY` value. **Rotate this key immediately** — it was visible in the committed file.

9. **Default admin password**: `Admin123!` is hardcoded in the login UI and backend seed. Change it in production. Set `VITE_DISABLE_AUTO_LOGIN=true` to disable the auto-login behavior.

10. **Multi-instance / HA**: In-memory stores (OAuth states, SSO tokens, exchange codes, threat engine) do not replicate across multiple backend instances. For HA deployments, these must be moved to Redis.
