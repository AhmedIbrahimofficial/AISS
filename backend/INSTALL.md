# AISS — Installation Guide

## Requirements

| Component | Minimum | Recommended |
|---|---|---|
| Python | 3.11 | 3.12 |
| RAM | 4 GB | 16 GB |
| Disk | 10 GB | 50 GB |
| CPU | 2 cores | 8 cores |
| OS | Windows 10 / Ubuntu 22.04 / macOS 13 | |

**Required services:**
- Redis 6+ (for Celery task queue)
- PostgreSQL 14+ or MySQL 8+ (SQLite for local dev only)

**Optional services:**
- Ollama (local LLM inference)
- MaxMind GeoLite2 (geo enrichment)

---

## One-Click Installer

```bash
python install.py
```

The installer handles everything: venv, deps, directories, .env, migrations, spaCy model download, startup validation.

---

## Manual Installation

### Windows

```powershell
# 1. Install Python 3.12 from python.org
# 2. Install Redis (Memurai from memurai.com)
# 3. Install PostgreSQL (optional)

cd "aiss backend"
python -m venv .venv
.venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
python -m spacy download en_core_web_sm

copy .env.example .env
# Edit .env with Notepad

alembic upgrade head
python main.py
```

### Linux (Ubuntu/Debian)

```bash
sudo apt update && sudo apt install -y python3.12 python3.12-venv redis-server \
    build-essential libmagic1 libpq-dev

cd "aiss backend"
python3.12 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python -m spacy download en_core_web_sm

cp .env.example .env
nano .env

alembic upgrade head
python main.py
```

### macOS

```bash
brew install python@3.12 redis postgresql@16 libmagic

cd "aiss backend"
python3.12 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python -m spacy download en_core_web_sm

cp .env.example .env

alembic upgrade head
python main.py
```

---

## Environment Variables

Copy `.env.example` to `.env` and fill in:

### Required
| Variable | Description |
|---|---|
| `DATABASE_URL` | Database connection string |
| `SECRET_KEY` | JWT signing key (auto-generated if blank) |
| `EVIDENCE_ENCRYPTION_KEY` | Fernet key for evidence files (auto-generated if blank) |

### Strongly Recommended
| Variable | Description |
|---|---|
| `ANTHROPIC_API_KEY` | Claude AI analysis |
| `OPENAI_API_KEY` | GPT fallback |
| `AISS_LICENSE_KEY` | Commercial license (trial mode if blank) |

### Optional
| Variable | Description |
|---|---|
| `VIRUSTOTAL_API_KEY` | VT threat enrichment |
| `SHODAN_API_KEY` | Shodan host intelligence |
| `GEOIP_DB_PATH` | MaxMind GeoLite2 database path |
| `APPRISE_URLS` | Alert channels (Slack, Discord, etc.) |
| `SENTRY_DSN` | Error tracking |

See `.env.example` for the full list with descriptions.

---

## Database Setup

### SQLite (local dev — zero config)
Leave `DATABASE_URL=sqlite+aiosqlite:///./logs/cybersecurity.db`

### PostgreSQL
```bash
psql -U postgres
CREATE DATABASE aiss_db;
CREATE USER aiss_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE aiss_db TO aiss_user;
\q
```
Set: `DATABASE_URL=postgresql+asyncpg://aiss_user:your_password@localhost:5432/aiss_db`

### MySQL
```sql
CREATE DATABASE aiss_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'aiss_user'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON aiss_db.* TO 'aiss_user'@'localhost';
```
Set: `DATABASE_URL=mysql+aiomysql://aiss_user:your_password@localhost:3306/aiss_db`

---

## GeoIP Setup (optional)

1. Register at https://www.maxmind.com/en/geolite2/signup
2. Download `GeoLite2-City.mmdb`
3. Place at `data/GeoLite2-City.mmdb`
4. Set `GEOIP_DB_PATH=data/GeoLite2-City.mmdb`

---

## Playwright Setup (optional — for phishing screenshots)

```bash
playwright install chromium
```

---

## Verifying the Installation

```bash
# API health
curl http://localhost:8000/api/health

# Library status
curl http://localhost:8000/api/system/libraries

# API docs
open http://localhost:8000/docs
```

---

## Troubleshooting

**Port 8000 already in use:**
```bash
# Windows
netstat -ano | findstr :8000
taskkill /PID <pid> /F
# Linux
lsof -ti:8000 | xargs kill -9
```

**Redis connection refused:**
```bash
# Windows: start Memurai service
# Linux:
sudo systemctl start redis
```

**spaCy model missing:**
```bash
python -m spacy download en_core_web_sm
```

**Database migration error:**
```bash
alembic downgrade base
alembic upgrade head
```
