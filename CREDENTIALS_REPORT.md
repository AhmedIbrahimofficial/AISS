# AISS — Required Credentials Report

Generated after full codebase audit.

---

## Summary

| Category | Count |
|---|---|
| Required | 2 |
| Optional — enhances functionality | 9 |
| Local / No API key required | 12 |
| Replaced by OpenRouter | 4 |

---

## REQUIRED Credentials

### 1. OPENROUTER_API_KEY
| Field | Value |
|---|---|
| **Service** | OpenRouter |
| **Purpose** | Centralized AI gateway — all LLM features route through this |
| **Environment Variable** | `OPENROUTER_API_KEY` |
| **Used By** | Agent Orchestrator, AI Analyst, SOC Chat, Threat Analysis, Kill Chain, IOC Analysis, Vulnerability Explanations, Security Copilot, RAG pipeline, Incident Reports |
| **Required / Optional** | **REQUIRED** |
| **How to Configure** | Sign up at https://openrouter.ai → Keys → Create key → paste into `.env` |
| **Impact if missing** | All AI/LLM features disabled. Agent Orchestrator will not start. |

### 2. SECRET_KEY
| Field | Value |
|---|---|
| **Service** | Internal (AISS) |
| **Purpose** | JWT signing key |
| **Environment Variable** | `SECRET_KEY` |
| **Required / Optional** | **REQUIRED** |
| **How to Configure** | Auto-generated on first startup. For production, run: `python -c "import secrets; print(secrets.token_hex(64))"` and set in `.env` |
| **Impact if missing** | Auto-generated but NOT persistent across restarts — all sessions invalidated on restart |

---

## OPTIONAL Credentials (enable additional integrations)

### 3. GOOGLE_OAUTH_CLIENT_ID + GOOGLE_OAUTH_CLIENT_SECRET
| Field | Value |
|---|---|
| **Service** | Google OAuth 2.0 |
| **Purpose** | Google Sign-In on website and dashboard |
| **Environment Variables** | `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET` |
| **Required / Optional** | Optional (email/password login works without it) |
| **How to Configure** | Google Cloud Console → APIs & Services → Credentials → Create OAuth 2.0 Client ID. Set Authorized Redirect URI to `http://localhost:8000/api/auth/oauth/google/callback` |

### 4. VIRUSTOTAL_API_KEY
| Field | Value |
|---|---|
| **Service** | VirusTotal |
| **Purpose** | File hash reputation checks, URL scanning, IP enrichment |
| **Environment Variable** | `VIRUSTOTAL_API_KEY` |
| **Required / Optional** | Optional |
| **How to Configure** | https://www.virustotal.com/gui/my-apikey (free tier available) |
| **Impact if missing** | Reputation lookups skip VT; hash analysis is local-only |

### 5. SHODAN_API_KEY
| Field | Value |
|---|---|
| **Service** | Shodan |
| **Purpose** | Host/port intelligence for IP enrichment |
| **Environment Variable** | `SHODAN_API_KEY` |
| **Required / Optional** | Optional |
| **How to Configure** | https://account.shodan.io/ |

### 6. CENSYS_API_ID + CENSYS_API_SECRET
| Field | Value |
|---|---|
| **Service** | Censys |
| **Purpose** | Certificate and host intelligence |
| **Environment Variables** | `CENSYS_API_ID`, `CENSYS_API_SECRET` |
| **Required / Optional** | Optional |
| **How to Configure** | https://search.censys.io/account/api |

### 7. GEOIP_DB_PATH
| Field | Value |
|---|---|
| **Service** | MaxMind GeoLite2 (local database, no API key) |
| **Purpose** | Geo-enrichment for threat IPs (country, city, lat/lon) |
| **Environment Variable** | `GEOIP_DB_PATH` |
| **Required / Optional** | Optional |
| **How to Configure** | Register free at https://www.maxmind.com/en/geolite2/signup, download GeoLite2-City.mmdb, place in `data/` and set path in `.env` |

### 8. SMTP_HOST + SMTP_USER + SMTP_PASSWORD
| Field | Value |
|---|---|
| **Service** | Any SMTP provider (Gmail, SendGrid, Mailgun, etc.) |
| **Purpose** | Email verification, password reset, OTP delivery |
| **Environment Variables** | `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD` |
| **Required / Optional** | Optional (auth works without it; verification emails not sent) |
| **How to Configure** | Point to any SMTP relay. For dev: use Mailpit (local) |

### 9. EVIDENCE_ENCRYPTION_KEY
| Field | Value |
|---|---|
| **Service** | Internal (Fernet) |
| **Purpose** | Encrypts quarantined forensic evidence files |
| **Environment Variable** | `EVIDENCE_ENCRYPTION_KEY` |
| **Required / Optional** | Optional (auto-generated on startup; NOT persistent) |
| **How to Configure** | `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |

### 10. APPRISE_URLS
| Field | Value |
|---|---|
| **Service** | Apprise (80+ alert channels: Slack, Discord, Teams, ntfy, etc.) |
| **Purpose** | Multi-channel security alerting |
| **Environment Variable** | `APPRISE_URLS` |
| **Required / Optional** | Optional |
| **How to Configure** | Examples: `ntfy://ntfy.sh/my-topic`, `discord://webhookid/token` |

### 11. SENTRY_DSN
| Field | Value |
|---|---|
| **Service** | Sentry |
| **Purpose** | Error tracking and performance monitoring |
| **Environment Variable** | `SENTRY_DSN` |
| **Required / Optional** | Optional |
| **How to Configure** | https://sentry.io → New Project → get DSN |

---

## LOCAL / No API Key Required

These features work entirely locally without any external credentials:

| Feature | How |
|---|---|
| Core threat detection | psutil, watchdog, scapy — OS-level monitoring |
| YARA malware scanning | Local YARA rules in `rules/*.yar` |
| File type detection | python-magic (libmagic), pefile, oletools |
| Entropy analysis | Local Shannon entropy calculation |
| IOC extraction | ioc-finder (local NLP) |
| Network monitoring | psutil, netifaces2 |
| Process monitoring | psutil |
| Sigma rules | pySigma (local rule engine) |
| Kill chain analysis | Local logic + threat correlation |
| Online anomaly detection | River ML (online learning, local) |
| Semantic search | sentence-transformers + ChromaDB (local vectors) |
| Report generation | matplotlib, reportlab, weasyprint (local) |
| JWT auth | python-jose + argon2 (local) |
| SQLite database | aiosqlite (local, zero-config) |

---

## Replaced by OpenRouter

These AI providers were referenced in legacy code or `.env.example` but are **no longer required** because OpenRouter handles all LLM calls:

| Old Provider | Old Variable | Status | Notes |
|---|---|---|---|
| Anthropic Claude | `ANTHROPIC_API_KEY` | **Replaced** | Used via OpenRouter as `anthropic/claude-3.5-sonnet` |
| OpenAI GPT | `OPENAI_API_KEY` | **Replaced** | Used via OpenRouter as `openai/gpt-4o` |
| Groq | `GROQ_API_KEY` | **Replaced** | Used via OpenRouter as `meta-llama/llama-3.1-70b` |
| Google Gemini | `GOOGLE_API_KEY` | **Replaced** | Used via OpenRouter as `google/gemini-pro-1.5` |
| Local Llama | `LLAMA_MODEL_PATH` | **Replaced** | Local fallback; OpenRouter preferred |

These variables can remain in `.env` for future use but are not read by `llm_router.py` or `ai_service.py`.

---

## TAXII / STIX Threat Feeds (Optional, Public)

| Variable | Default | Notes |
|---|---|---|
| `TAXII_SERVER_URL` | `https://cti-taxii.mitre.org/taxii/` | Public MITRE feed — works without credentials |
| `TAXII_USERNAME` | (empty) | Required only for private feeds |
| `TAXII_PASSWORD` | (empty) | Required only for private feeds |
| `TAXII_COLLECTION` | `Enterprise ATT&CK` | Which TAXII collection to pull |

---

## Minimal Working Configuration

To run AISS with all core features enabled, you only need:

```env
# .env — minimum production configuration
SECRET_KEY=<64+ char hex — generate with: python -c "import secrets; print(secrets.token_hex(64))">
OPENROUTER_API_KEY=sk-or-v1-...
DATABASE_URL=sqlite+aiosqlite:///./logs/aiss.db
ENVIRONMENT=production
```

Everything else is optional or auto-generated.
