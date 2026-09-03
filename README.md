# AISS — AI Integrated Security System

Real-time cybersecurity platform with autonomous AI agent, threat detection,
malware scanning, network monitoring, and automated incident response.

---

## What is this?

AISS is a full-stack security operations platform that runs on your own machine:

- **Threat Detection** — live network, process, file, and auth monitoring
- **AI Security Agent** — talk to it in plain English; it runs security tools, investigates threats, and generates PDF reports
- **Malware Scanner** — YARA rules, entropy analysis, hash matching across all drives
- **Kill Chain Monitor** — maps threats to MITRE ATT&CK stages
- **Network Topology** — discovers and maps your LAN/WAN/VPN devices
- **Automated Response** — quarantines files, kills processes, blocks IPs automatically

**Stack:** Python (FastAPI) + React (TanStack Router) + SQLite (or MySQL/PostgreSQL)

---

## Quick Start — New Computer

### Prerequisites

| What | Version | Download |
|---|---|---|
| Python | 3.11 or 3.12 | https://www.python.org/downloads/ |
| Node.js | 18+ | https://nodejs.org/ |
| Git | any | https://git-scm.com/ |

---

### Step 1 — Clone

```bash
git clone https://github.com/AhmedIbrahimofficial/AISS.git
cd AISS
```

---

### Step 2 — Configure (the only manual step)

Copy the example environment file and fill in your keys:

```bash
cd "aiss backend"
copy .env.example .env        # Windows
# cp .env.example .env        # Linux / Mac
```

Then open `.env` in any text editor and set these two values:

```env
# REQUIRED — generates a secure JWT signing key:
# Run this and paste the output:
#   python -c "import secrets; print(secrets.token_hex(64))"
SECRET_KEY=your_64_char_hex_key_here

# REQUIRED for AI features — get a free key at https://openrouter.ai/keys
OPENROUTER_API_KEY=sk-or-v1-...
```

Everything else in `.env` is optional and has safe defaults.

**Without `OPENROUTER_API_KEY`:** All AI features (Agent chat, threat analysis,
report generation) are disabled. Threat detection, YARA scanning, and network
monitoring still work fully.

---

### Step 3 — Install and Start

```bash
# From the repo root:
cd "aiss backend"
python aiss.py
```

That's it. `aiss.py` does everything automatically:

1. Creates Python virtual environment (`.venv`)
2. Installs all 120+ Python packages
3. Creates database and runs migrations
4. Downloads ML models (spaCy, sentence-transformers — first run only, ~500 MB)
5. Starts the backend at `http://localhost:8000`

**First run takes 5–15 minutes** because of model downloads.
Subsequent runs start in under 10 seconds.

---

### Step 4 — Start the Frontend

In a second terminal:

```bash
cd frontend
npm install          # first time only
npm run dev          # development (hot reload)
```

Or for production (faster, no hot reload):

```bash
npm run build
node .output/server/index.mjs
```

Frontend opens at `http://localhost:5173` (dev) or `http://localhost:8081` (prod).

---

### One-command startup (after first setup)

Once installed, you can start both services with:

```bash
cd "aiss backend"
python aiss_launcher.py
```

This starts backend + frontend together, waits for both to be healthy, then
opens the browser automatically.

---

## First Login

1. Go to `http://localhost:5173`
2. Click **Sign Up** — create your admin account
3. Log in — the dashboard loads with live threat data immediately

---

## Project Structure

```
AISS/
├── aiss backend/          # FastAPI backend
│   ├── agents/            # AI Orchestrator (51 tools)
│   ├── api/routes/        # REST API endpoints
│   ├── auth/              # JWT auth + OAuth
│   ├── core/              # Threat engine, WebSocket, DB
│   ├── modules/           # Detection modules (malware, network, file, auth)
│   ├── rules/             # YARA detection rules
│   ├── aiss.py            # One-command installer + launcher
│   ├── aiss_launcher.py   # Start backend + frontend together
│   ├── main.py            # FastAPI app entry point
│   ├── requirements.txt   # Python dependencies
│   └── .env.example       # Configuration template
│
└── frontend/              # React dashboard
    ├── src/
    │   ├── routes/        # All pages (50+ views)
    │   ├── components/    # UI components
    │   ├── api/           # Backend API client
    │   └── context/       # Agent state management
    ├── package.json
    └── vite.config.ts
```

---

## Configuration Reference

All settings are in `aiss backend/.env`. Key variables:

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | ✅ Yes | JWT signing key. Generate: `python -c "import secrets; print(secrets.token_hex(64))"` |
| `OPENROUTER_API_KEY` | ⚡ For AI | All LLM features. Get at https://openrouter.ai/keys |
| `DATABASE_URL` | Default: SQLite | Use MySQL/PostgreSQL for production |
| `VIRUSTOTAL_API_KEY` | Optional | File/IP reputation checks |
| `SHODAN_API_KEY` | Optional | Host intelligence |
| `GOOGLE_OAUTH_CLIENT_ID` | Optional | Google Sign-In |

Full list in [`aiss backend/.env.example`](aiss%20backend/.env.example) and
[`CREDENTIALS_REPORT.md`](CREDENTIALS_REPORT.md).

---

## Troubleshooting

**Backend won't start**
```bash
# Check Python version — must be 3.11 or 3.12
python --version

# Check for errors in the logs
cd "aiss backend"
cat logs/aiss.log
```

**"ModuleNotFoundError" errors**
```bash
# Reinstall all packages
cd "aiss backend"
python aiss.py --reinstall
```

**Frontend can't connect to backend**
```bash
# Create a .env file in frontend/ if it doesn't exist
echo VITE_AISS_API_URL=http://localhost:8000 > frontend/.env.local
```

**Port 8000 already in use**
```bash
# Change the port in aiss backend/.env
AISS_BACKEND_PORT=8001
```

**AI Agent says "LLM unavailable"**
- Add your `OPENROUTER_API_KEY` to `aiss backend/.env`
- Get a free key at https://openrouter.ai/keys (free tier available)

---

## Connecting Remote Machines

AISS can monitor other computers on your network. On each remote machine:

```bash
# Copy aiss_agent.py to the remote machine, then:
python aiss_agent.py --server http://YOUR_AISS_SERVER_IP:8000 --token YOUR_TOKEN
```

Generate a token from the AISS dashboard: **Settings → Devices → Generate Token**

---

## Security Notes

- AISS binds to `127.0.0.1` by default — not exposed to the internet
- Never commit your `.env` file — it is gitignored
- Rotate `OPENROUTER_API_KEY` if it was ever shared
- For production deployment behind nginx, see `aiss backend/deploy/nginx/`

---

## License

See [LICENSE](aiss%20backend/LICENSE)
