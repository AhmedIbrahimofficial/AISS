# AISS Backend — Setup Guide

FastAPI backend for the AISS security platform.

## Minimum Setup (3 commands)

```bash
# 1. Copy environment file
copy .env.example .env

# 2. Set your keys in .env (open in any text editor):
#    SECRET_KEY  = python -c "import secrets; print(secrets.token_hex(64))"
#    OPENROUTER_API_KEY = your key from https://openrouter.ai/keys

# 3. Install everything and start
python aiss.py
```

Server starts at http://localhost:8000
API docs at http://localhost:8000/docs

## Manual setup (if aiss.py fails)

```bash
python -m venv .venv

# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

pip install -r requirements.txt
python -m spacy download en_core_web_sm
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

## Environment Variables

See `.env.example` for all variables with descriptions.

Minimum required:
```env
SECRET_KEY=<64 hex chars>
OPENROUTER_API_KEY=sk-or-v1-...   # optional — disables AI features if missing
DATABASE_URL=sqlite+aiosqlite:///./logs/cybersecurity.db
```

## Running Tests

```bash
pytest tests/ -v
```
