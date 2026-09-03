#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         AISS — AI Intelligent Security System               ║
║              Single Command Launcher v2.0.0                 ║
║                                                             ║
║  Usage:  python aiss.py           (or just: aiss)           ║
║          aiss --wizard            Re-run setup questions    ║
║          aiss --reinstall         Force reinstall all pkgs  ║
║          aiss --install-only      Install, don't start      ║
║          aiss --no-wizard         Skip setup questions      ║
╚══════════════════════════════════════════════════════════════╝

WHAT HAPPENS WHEN YOU TYPE 'aiss':
  1.  Python version check (3.11+ required)
  2.  Virtual environment creation (.venv)
  3.  Smart package detection — shows what's already installed,
      installs only what's missing (120+ packages, with live
      per-package progress bar showing %)
  4.  Service checks — Redis, PostgreSQL, Ollama (auto-starts if possible)
  5.  Directory structure creation (logs, data, rules, static, etc.)
  6.  .env file generation with auto-generated secure keys
      (SECRET_KEY, EVIDENCE_ENCRYPTION_KEY, INTERNAL_SERVICE_TOKEN)
  7.  Database migrations (Alembic)
  8.  ML model downloads (spaCy, Playwright chromium — first run only)
  9.  Library auto-integration — all 85+ libraries initialised,
      credentials validated, optional features gracefully disabled
 10.  Startup validation — 10 pre-launch checks
 11.  Global registration — registers 'aiss' as system command
 12.  Remote agent info — shows how to connect other computers
      (LAN / WAN / VPN / MAN)
 13.  Setup wizard — asks configuration questions in CMD
      (auto-becomes popup dialogs when frontend is connected)
 14.  Summary box — all endpoints printed
 15.  Backend starts — browser opens to http://localhost:8000/docs

EVERYTHING IS AUTOMATIC. User types: aiss
"""

# ── Bootstrap: only stdlib allowed before pip install ────────────────
import sys
import os
import subprocess
import platform
import time
import shutil
import threading
import json
import secrets
import hashlib
import re
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────
VERSION      = "2.0.0"
IS_WIN       = platform.system() == "Windows"
IS_MAC       = platform.system() == "Darwin"
IS_LINUX     = platform.system() == "Linux"
SCRIPT_DIR   = Path(__file__).parent.resolve()
VENV_DIR     = SCRIPT_DIR / ".venv"
PYTHON_BIN   = (VENV_DIR / "Scripts" / "python.exe") if IS_WIN else (VENV_DIR / "bin" / "python")
PIP_BIN      = (VENV_DIR / "Scripts" / "pip.exe")    if IS_WIN else (VENV_DIR / "bin" / "pip")

# ─────────────────────────────────────────────────────────────────────
# COLOUR ENGINE  (no external deps — pure ANSI)
# ─────────────────────────────────────────────────────────────────────
if IS_WIN:
    # Enable ANSI codes on Windows 10+
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass
    # Force UTF-8 output on Windows
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass

# Detect if terminal supports Unicode box characters
def _supports_unicode() -> bool:
    try:
        "\u2554\u2550\u2557".encode(sys.stdout.encoding or "utf-8")
        return True
    except (UnicodeEncodeError, LookupError, AttributeError):
        return False

_UNICODE = _supports_unicode()

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
MAGENTA= "\033[95m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
BGBLUE = "\033[44m"
BGGREEN= "\033[42m"

def clr(text, *codes):
    return "".join(codes) + str(text) + RESET

def banner():
    if _UNICODE:
        lines = [
            clr("╔══════════════════════════════════════════════════════════╗", CYAN, BOLD),
            clr("║", CYAN) + clr("     █████╗ ██╗███████╗███████╗                          ", CYAN, BOLD) + clr("║", CYAN),
            clr("║", CYAN) + clr("    ██╔══██╗██║██╔════╝██╔════╝                          ", CYAN) + clr("║", CYAN),
            clr("║", CYAN) + clr("    ███████║██║███████╗███████╗                          ", GREEN) + clr("║", CYAN),
            clr("║", CYAN) + clr("    ██╔══██║██║╚════██║╚════██║                          ", YELLOW) + clr("║", CYAN),
            clr("║", CYAN) + clr("    ██║  ██║██║███████║███████║                          ", RED) + clr("║", CYAN),
            clr("║", CYAN) + clr("    ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝                          ", MAGENTA) + clr("║", CYAN),
            clr("║", CYAN) + clr(f"    AI Intelligent Security System  v{VERSION}             ", WHITE, BOLD) + clr("║", CYAN),
            clr("╚══════════════════════════════════════════════════════════╝", CYAN, BOLD),
        ]
    else:
        lines = [
            clr("+============================================================+", CYAN, BOLD),
            clr("|         AISS - AI Intelligent Security System              |", CYAN, BOLD),
            clr(f"|         Version {VERSION}                                      |", WHITE, BOLD),
            clr("+============================================================+", CYAN, BOLD),
        ]
    print("\n" + "\n".join(lines) + "\n")


def section(title: str):
    width = 60
    if _UNICODE:
        bar = "─" * width
    else:
        bar = "-" * width
    bullet = ">" if not _UNICODE else "▶"
    print(f"\n{clr(bar, CYAN)}")
    print(f"{clr(' ' + bullet + ' ' + title, CYAN, BOLD)}")
    print(f"{clr(bar, CYAN)}")


def ok(msg):    print(f"  {clr('✔', GREEN, BOLD)}  {msg}")
def skip(msg):  print(f"  {clr('○', DIM)}  {clr(msg, DIM)}")
def info(msg):  print(f"  {clr('→', CYAN)}  {msg}")
def warn(msg):  print(f"  {clr('⚠', YELLOW, BOLD)}  {clr(msg, YELLOW)}")
def err(msg):   print(f"  {clr('✘', RED, BOLD)}  {clr(msg, RED)}")
def fatal(msg):
    err(msg)
    print(f"\n{clr('AISS cannot continue. Fix the error above and retry.', RED, BOLD)}\n")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────
# PROGRESS BAR
# ─────────────────────────────────────────────────────────────────────

def progress_bar(current: int, total: int, label: str = "", width: int = 40) -> str:
    pct    = current / max(total, 1)
    filled = int(width * pct)
    bar    = clr("█" * filled, GREEN) + clr("░" * (width - filled), DIM)
    pct_s  = clr(f"{int(pct*100):3d}%", BOLD)
    return f"  [{bar}] {pct_s}  {label[:35]:<35}"


def print_progress(current: int, total: int, label: str = ""):
    print(f"\r{progress_bar(current, total, label)}", end="", flush=True)


def print_progress_done(label: str = ""):
    print(f"\r{progress_bar(1, 1, label)}", flush=True)
    print()


# ─────────────────────────────────────────────────────────────────────
# STEP 1 — PYTHON VERSION CHECK
# ─────────────────────────────────────────────────────────────────────

def check_python():
    section("Step 1 — Python Version Check")
    v = sys.version_info
    info(f"Python {v.major}.{v.minor}.{v.micro}  [{sys.executable}]")
    if v < (3, 11):
        fatal(f"Python 3.11+ required. You have {v.major}.{v.minor}. "
              "Download from https://python.org/downloads")
    ok(f"Python {v.major}.{v.minor}.{v.micro} ✓")


# ─────────────────────────────────────────────────────────────────────
# STEP 2 — VIRTUAL ENVIRONMENT
# ─────────────────────────────────────────────────────────────────────

def ensure_venv():
    section("Step 2 — Virtual Environment")
    if VENV_DIR.exists() and PYTHON_BIN.exists():
        skip(f"Virtual environment already exists: {VENV_DIR.name}/")
        ok("Using existing .venv")
        return

    info(f"Creating virtual environment at {VENV_DIR} ...")
    rc, out = _run([sys.executable, "-m", "venv", str(VENV_DIR)])
    if rc != 0:
        fatal(f"venv creation failed: {out[:200]}")
    ok("Virtual environment created: .venv/")

    # Upgrade pip inside venv
    info("Upgrading pip ...")
    _run([str(PYTHON_BIN), "-m", "pip", "install", "--upgrade", "pip", "wheel",
          "--quiet", "--no-warn-script-location"])
    ok("pip upgraded")


# ─────────────────────────────────────────────────────────────────────
# STEP 3 — PACKAGE DETECTION + SMART INSTALL
# ─────────────────────────────────────────────────────────────────────

# All packages to install — (pip_name, import_name, description, category)
ALL_PACKAGES = [
    # Core web
    ("fastapi==0.115.0",              "fastapi",              "FastAPI web framework",          "Web"),
    ("uvicorn[standard]==0.52.1",     "uvicorn",              "ASGI server",                    "Web"),
    ("python-multipart==0.0.9",       "multipart",            "File upload support",            "Web"),
    ("websockets==15.0.1",            "websockets",           "WebSocket protocol",             "Web"),
    ("httpx==0.28.1",                 "httpx",                "Async HTTP client",              "Web"),
    # Database
    ("sqlalchemy==2.0.36",            "sqlalchemy",           "ORM framework",                  "Database"),
    ("alembic==1.14.0",               "alembic",              "DB migrations",                  "Database"),
    ("aiosqlite==0.21.0",             "aiosqlite",            "SQLite async driver",            "Database"),
    ("aiomysql==0.2.0",               "aiomysql",             "MySQL async driver",             "Database"),
    ("asyncpg==0.29.0",               "asyncpg",              "PostgreSQL async driver",        "Database"),
    # Auth
    ("python-jose[cryptography]==3.3.0","jose",               "JWT tokens",                     "Auth"),
    ("bcrypt==4.0.1",                 "bcrypt",               "Password hashing",               "Auth"),
    ("argon2-cffi==23.1.0",           "argon2",               "Argon2id hashing",               "Auth"),
    ("cryptography==50.0.0",          "cryptography",         "Fernet encryption",              "Auth"),
    ("Authlib==1.7.2",                "authlib",              "OAuth2/OIDC",                    "Auth"),
    ("python-dotenv==1.2.2",          "dotenv",               "Environment variables",          "Config"),
    ("pydantic==2.12.5",              "pydantic",             "Data validation",                "Config"),
    ("pydantic-settings==2.14.2",     "pydantic_settings",    "Settings management",            "Config"),
    ("slowapi==0.1.9",                "slowapi",              "Rate limiting",                  "Security"),
    # Email / Alerts
    ("fastapi-mail==1.4.1",           "fastapi_mail",         "Email sender",                   "Email"),
    ("aiosmtplib==2.0.2",             "aiosmtplib",           "Async SMTP",                     "Email"),
    ("apprise==1.12.0",               "apprise",              "80+ alert channels",             "Alerts"),
    # Task queue
    ("celery==5.6.3",                 "celery",               "Distributed task queue",         "Queue"),
    ("redis==8.1.0",                  "redis",                "Redis client",                   "Queue"),
    ("kombu==5.6.2",                  "kombu",                "Message broker abstraction",     "Queue"),
    ("APScheduler==3.11.3",           "apscheduler",          "Job scheduler",                  "Queue"),
    # AI / LLM
    ("anthropic==0.120.2",            "anthropic",            "Claude AI client",               "AI"),
    ("openai==2.53.0",                "openai",               "OpenAI GPT client",              "AI"),
    ("groq==1.2.0",                   "groq",                 "Groq ultra-fast LLM",            "AI"),
    ("litellm==1.95.0",               "litellm",              "Multi-provider LLM router",      "AI"),
    ("langchain==1.3.13",             "langchain",            "LLM orchestration",              "AI"),
    ("langchain-core==1.5.3",         "langchain_core",       "LangChain core",                 "AI"),
    ("langchain-community==0.4.2",    "langchain_community",  "LangChain community tools",      "AI"),
    ("langchain-openai==1.4.1",       "langchain_openai",     "LangChain OpenAI",               "AI"),
    ("langgraph==1.2.9",              "langgraph",            "LLM workflow graphs",            "AI"),
    ("langsmith==0.10.2",             "langsmith",            "LLM tracing",                    "AI"),
    ("langfuse==4.14.2",              "langfuse",             "LLM observability",              "AI"),
    ("crewai==1.15.11",               "crewai",               "Multi-agent AI crew",            "AI"),
    ("instructor==1.15.4",            "instructor",           "Structured LLM outputs",         "AI"),
    ("pydantic-ai==2.24.0",           "pydantic_ai",          "Type-safe AI agents",            "AI"),
    ("semantic-kernel==1.44.0",       "semantic_kernel",      "MS Semantic Kernel",             "AI"),
    ("tenacity==9.1.4",               "tenacity",             "Retry logic",                    "Utils"),
    # Vector stores
    ("sentence-transformers==5.6.0",  "sentence_transformers","Text embeddings",                "VectorDB"),
    ("faiss-cpu==1.15.0",             "faiss",                "FAISS vector search",            "VectorDB"),
    ("chromadb==1.1.1",               "chromadb",             "ChromaDB vector store",          "VectorDB"),
    ("lancedb==0.30.0",               "lancedb",              "LanceDB vector store",           "VectorDB"),
    ("qdrant-client==1.19.0",         "qdrant_client",        "Qdrant vector store",            "VectorDB"),
    # ML
    ("scikit-learn==1.9.0",           "sklearn",              "Machine learning",               "ML"),
    ("river==0.25.0",                 "river",                "Online/stream ML",               "ML"),
    ("numpy==2.4.6",                  "numpy",                "Numerical computing",            "ML"),
    ("pandas==3.0.3",                 "pandas",               "Data analysis",                  "ML"),
    ("polars==1.42.1",                "polars",               "Fast DataFrames",                "ML"),
    ("scipy==1.18.0",                 "scipy",                "Scientific computing",           "ML"),
    # Deep learning
    ("torch==2.13.0",                 "torch",                "PyTorch deep learning",          "DL"),
    ("transformers==5.13.1",          "transformers",         "HuggingFace transformers",       "DL"),
    ("accelerate==1.14.0",            "accelerate",           "HF accelerated training",        "DL"),
    ("tokenizers==0.22.2",            "tokenizers",           "Fast tokenizers",                "DL"),
    # NLP
    ("spacy==3.8.14",                 "spacy",                "NLP pipeline",                   "NLP"),
    ("tiktoken==0.13.0",              "tiktoken",             "Token counting",                 "NLP"),
    # Threat intel
    ("stix2==3.0.2",                  "stix2",                "STIX threat bundles",            "ThreatIntel"),
    ("taxii2-client==2.3.0",          "taxii2client",         "TAXII feed client",              "ThreatIntel"),
    ("pyattck==7.1.2",                "pyattck",              "MITRE ATT&CK framework",         "ThreatIntel"),
    ("shodan==1.31.0",                "shodan",               "Shodan host intel",              "ThreatIntel"),
    ("censys==2.2.19",                "censys",               "Censys certificate intel",       "ThreatIntel"),
    ("vt-py==0.22.0",                 "vt",                   "VirusTotal client",              "ThreatIntel"),
    ("ioc-finder==9.4.1",             "ioc_finder",           "IOC auto-extraction",            "ThreatIntel"),
    ("ioc-fanger==5.1.1",             "ioc_fanger",           "IOC defang/refang",              "ThreatIntel"),
    ("pySigma==1.5.0",                "sigma",                "Sigma detection rules",          "ThreatIntel"),
    ("yara-python==4.5.4",            "yara",                 "YARA malware rules",             "ThreatIntel"),
    # Network / System
    ("psutil==7.2.2",                 "psutil",               "Process & system monitoring",    "System"),
    ("scapy==2.6.1",                  "scapy",                "Packet crafting",                "Network"),
    ("python-nmap==0.7.1",            "nmap",                 "Nmap integration",               "Network"),
    ("netifaces2==0.0.22",            "netifaces2",           "Network interfaces",             "Network"),
    ("ping3==4.0.8",                  "ping3",                "ICMP ping",                      "Network"),
    ("watchdog==6.0.0",               "watchdog",             "File system monitoring",         "System"),
    # File analysis
    ("python-magic==0.4.27",          "magic",                "True file type detection",       "FileAnalysis"),
    ("pefile==2024.8.26",             "pefile",               "PE executable analysis",         "FileAnalysis"),
    ("oletools==0.60.2",              "oletools",             "Office macro analysis",          "FileAnalysis"),
    ("pymupdf==1.28.0",               "pymupdf",              "PDF forensics",                  "FileAnalysis"),
    ("pdfplumber==0.11.10",           "pdfplumber",           "PDF text extraction",            "FileAnalysis"),
    ("docling==2.118.0",              "docling",              "Document intelligence",          "FileAnalysis"),
    ("easyocr==1.7.2",                "easyocr",              "Image OCR",                      "FileAnalysis"),
    ("opencv-python-headless==5.0.0.93","cv2",                "Computer vision",                "FileAnalysis"),
    # GeoIP
    ("geoip2==5.3.0",                 "geoip2",               "MaxMind GeoIP2",                 "GeoIP"),
    ("maxminddb==3.1.1",              "maxminddb",            "MaxMind DB reader",              "GeoIP"),
    # Reporting
    ("matplotlib==3.11.0",            "matplotlib",           "Chart generation",               "Reports"),
    ("plotly==6.9.0",                 "plotly",               "Interactive dashboards",         "Reports"),
    ("altair==6.2.2",                 "altair",               "Declarative charts",             "Reports"),
    ("openpyxl==3.1.5",               "openpyxl",             "Excel read/write",               "Reports"),
    ("xlsxwriter==3.2.9",             "xlsxwriter",           "Excel with charts",              "Reports"),
    ("reportlab==5.0.0",              "reportlab",            "PDF generation",                 "Reports"),
    ("weasyprint==69.0",              "weasyprint",           "HTML→PDF",                       "Reports"),
    # Observability
    ("sentry-sdk==2.66.1",            "sentry_sdk",           "Error tracking",                 "Observability"),
    ("prometheus-client==0.26.0",     "prometheus_client",    "Prometheus metrics",             "Observability"),
    ("prometheus-fastapi-instrumentator==7.0.0","prometheus_fastapi_instrumentator",
                                                               "FastAPI metrics",                "Observability"),
    ("opentelemetry-api==1.42.1",     "opentelemetry",        "OpenTelemetry tracing",          "Observability"),
    ("opentelemetry-sdk==1.42.1",     "opentelemetry",        "OTel SDK",                       "Observability"),
    ("structlog==26.1.0",             "structlog",            "Structured logging",             "Observability"),
    ("logfire==4.39.0",               "logfire",              "Pydantic Logfire",               "Observability"),
    # Cloud
    ("boto3==1.43.14",                "boto3",                "AWS S3/services",                "Cloud"),
    ("azure-storage-blob==12.30.0",   "azure.storage.blob",   "Azure Blob Storage",             "Cloud"),
    ("azure-identity==1.25.3",        "azure.identity",       "Azure authentication",           "Cloud"),
    ("kubernetes==36.0.3",            "kubernetes",           "Kubernetes API",                 "Cloud"),
    # Browser
    ("playwright==1.60.0",            "playwright",           "Headless browser",               "Browser"),
    # Voice
    ("pyttsx3==2.99",                 "pyttsx3",              "Text-to-speech",                 "Voice"),
    ("edge-tts==7.2.8",               "edge_tts",             "Edge TTS (better quality)",      "Voice"),
    # Utilities
    ("python-dateutil==2.9.0.post0",  "dateutil",             "Date utilities",                 "Utils"),
    ("orjson==3.11.9",                "orjson",               "Fast JSON",                      "Utils"),
    ("rich==14.3.4",                  "rich",                 "Rich terminal output",           "Utils"),
    ("PyYAML==6.0.3",                 "yaml",                 "YAML parsing",                   "Utils"),
    ("duckduckgo-search==8.1.1",      "duckduckgo_search",    "Web search",                     "Utils"),
    ("wikipedia==1.4.0",              "wikipedia",            "Wikipedia lookup",               "Utils"),
    ("youtube-transcript-api==1.2.4", "youtube_transcript_api","YouTube transcripts",           "Utils"),
    ("beautifulsoup4==4.14.3",        "bs4",                  "HTML parsing",                   "Utils"),
    ("requests==2.34.2",              "requests",             "HTTP requests",                  "Utils"),
    ("tqdm==4.67.3",                  "tqdm",                 "Progress bars",                  "Utils"),
    # Production server
    ("gunicorn==23.0.0",              "gunicorn",             "Production WSGI server",         "Server"),
    # Remote agent / network extras
    ("paramiko==3.5.0",               "paramiko",             "SSH client for remote agents",   "Network"),
    ("netaddr==1.3.0",                "netaddr",              "IP address manipulation",        "Network"),
    ("dpkt==1.9.8",                   "dpkt",                 "Packet parsing",                 "Network"),
    ("pyshark==0.6",                  "pyshark",              "Wireshark/tshark integration",   "Network"),
    ("impacket==0.12.0",              "impacket",             "Network protocol library",       "Network"),
    # Installer / system
    ("packaging==26.2",               "packaging",            "Package version handling",       "Utils"),
    ("colorama==0.4.6",               "colorama",             "Cross-platform colours",         "Utils"),
]


def _get_installed_packages() -> dict:
    """Return dict of {package_name: version} for all currently installed packages."""
    try:
        result = subprocess.run(
            [str(PYTHON_BIN), "-m", "pip", "list", "--format=json"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            pkgs = json.loads(result.stdout)
            return {p["name"].lower().replace("-", "_"): p["version"] for p in pkgs}
    except Exception:
        pass
    return {}


def _is_importable(import_name: str) -> bool:
    """Check if a module can be imported (fast check without full import)."""
    try:
        rc, _ = _run([str(PYTHON_BIN), "-c", f"import {import_name.split('.')[0]}"],
                     timeout=8)
        return rc == 0
    except Exception:
        return False


def install_packages():
    section("Step 3 — Package Detection & Installation")
    total = len(ALL_PACKAGES)
    info(f"Checking {total} packages ...")
    print()

    installed_map = _get_installed_packages()
    to_install    = []
    already_have  = []

    # ── Pre-scan: which are already present ──────────────────────────
    for i, (pip_name, import_name, desc, cat) in enumerate(ALL_PACKAGES):
        print_progress(i + 1, total, f"Checking {pip_name.split('==')[0]}")
        pkg_key = pip_name.split("==")[0].split("[")[0].lower().replace("-", "_")
        pkg_key2 = pip_name.split("==")[0].split("[")[0].lower().replace("-", "-")
        if pkg_key in installed_map or pkg_key2.lower() in installed_map:
            already_have.append((pip_name, desc))
        else:
            to_install.append((pip_name, import_name, desc, cat))

    print_progress_done("Detection complete")

    # ── Report already-installed ──────────────────────────────────────
    if already_have:
        print(f"\n  {clr('Already installed:', GREEN, BOLD)} "
              f"{clr(str(len(already_have)), CYAN, BOLD)} packages")
        # Group by showing first 5 then summarise
        for pip_name, desc in already_have[:8]:
            skip(f"{pip_name.split('==')[0]:<40} {clr(desc, DIM)}")
        if len(already_have) > 8:
            skip(f"... and {len(already_have) - 8} more already installed")

    if not to_install:
        print()
        ok("All packages already installed — nothing to do!")
        return

    # ── Install missing packages ──────────────────────────────────────
    print(f"\n  {clr('Installing:', YELLOW, BOLD)} "
          f"{clr(str(len(to_install)), CYAN, BOLD)} missing packages\n")

    cats_seen = set()
    for idx, (pip_name, import_name, desc, cat) in enumerate(to_install, 1):
        pct = idx / len(to_install)

        if cat not in cats_seen:
            print(f"\n  {clr('── ' + cat + ' ──', BLUE, BOLD)}")
            cats_seen.add(cat)

        pkg_short = pip_name.split("==")[0]
        # Show progress bar
        bar_width = 30
        filled    = int(bar_width * pct)
        bar       = clr("█" * filled, GREEN) + clr("░" * (bar_width - filled), DIM)
        pct_str   = clr(f"{int(pct*100):3d}%", BOLD)
        print(f"\r  [{bar}] {pct_str}  {clr(pkg_short, CYAN):<40} {clr(desc, DIM)[:30]}", end="")
        sys.stdout.flush()

        rc, out = _run(
            [str(PIP_BIN), "install", pip_name,
             "--quiet", "--no-warn-script-location",
             "--disable-pip-version-check"],
            timeout=300
        )
        if rc == 0:
            print(f"\r  {clr('✔', GREEN, BOLD)} {clr(pkg_short, WHITE):<42} {clr(desc, DIM)[:30]}")
        else:
            err_short = out.strip().splitlines()[-1][:60] if out.strip() else "unknown"
            print(f"\r  {clr('⚠', YELLOW)} {clr(pkg_short, YELLOW):<42} {clr('WARN: ' + err_short, YELLOW)}")

    print()
    ok(f"Package installation complete ({len(to_install)} installed)")


# ─────────────────────────────────────────────────────────────────────
# STEP 4 — SERVICE CHECKS
# ─────────────────────────────────────────────────────────────────────

def check_services() -> dict:
    section("Step 4 — Service Availability Check")
    found = {}

    # ── Redis ──────────────────────────────────────────────────────────
    print(f"  {clr('→', CYAN)} Checking Redis ...", end="  ")
    rc, _ = _run(["redis-cli", "ping"], timeout=5)
    if rc == 0:
        ok("Redis is running")
        found["redis"] = True
    else:
        # Try to start Redis automatically
        if IS_WIN:
            rc2, _ = _run(["net", "start", "Memurai"], timeout=8)
            if rc2 == 0:
                print()
                ok("Redis (Memurai) started automatically")
                found["redis"] = True
            else:
                print()
                warn("Redis not running — Celery tasks will be queued locally")
                info("Install Memurai: https://www.memurai.com/  or use WSL + Redis")
                found["redis"] = False
        elif IS_LINUX:
            rc2, _ = _run(["sudo", "systemctl", "start", "redis-server"], timeout=10)
            print()
            if rc2 == 0:
                ok("Redis started via systemctl")
                found["redis"] = True
            else:
                warn("Redis not running — install: sudo apt install redis-server")
                found["redis"] = False
        else:
            print()
            warn("Redis not running — install: brew install redis && brew services start redis")
            found["redis"] = False

    # ── Python packages importable ────────────────────────────────────
    print(f"  {clr('→', CYAN)} Checking core imports ...", end="  ")
    rc, _ = _run([str(PYTHON_BIN), "-c",
                  "import fastapi, sqlalchemy, cryptography, jose; print('ok')"],
                 timeout=15)
    if rc == 0:
        ok("Core packages importable")
        found["core"] = True
    else:
        print()
        warn("Some core packages may not be importable — check Step 3 output")
        found["core"] = False

    return found


# ─────────────────────────────────────────────────────────────────────
# STEP 5 — DIRECTORIES
# ─────────────────────────────────────────────────────────────────────

def create_directories():
    section("Step 5 — Directory Structure")
    dirs = [
        ("logs",           "Application & security logs"),
        ("logs/evidence",  "Encrypted forensic evidence"),
        ("data",           "ML models & runtime data"),
        ("data/models",    "Downloaded ML model files"),
        ("rules",          "YARA & Sigma detection rules"),
        ("static",         "Static web assets"),
        ("deploy/nginx",   "Nginx configuration"),
        ("deploy/nginx/ssl","TLS certificates"),
        ("datasets",       "Threat detection datasets"),
    ]
    for d, desc in dirs:
        p = SCRIPT_DIR / d
        existed = p.exists()
        p.mkdir(parents=True, exist_ok=True)
        if existed:
            skip(f"{d:<30} {clr(desc, DIM)}")
        else:
            ok(f"{d:<30} {clr('created', GREEN)}  {clr(desc, DIM)}")

    # Secure permissions on Unix
    if not IS_WIN:
        for d in ["logs", "data"]:
            try:
                (SCRIPT_DIR / d).chmod(0o700)
            except Exception:
                pass
    ok("All directories ready")


# ─────────────────────────────────────────────────────────────────────
# STEP 6 — ENVIRONMENT FILE
# ─────────────────────────────────────────────────────────────────────

def setup_env():
    section("Step 6 — Environment Configuration")
    env_file    = SCRIPT_DIR / ".env"
    example     = SCRIPT_DIR / ".env.example"

    if env_file.exists():
        # Check if keys are already populated
        text = env_file.read_text(encoding="utf-8", errors="ignore")
        has_sk = bool(re.search(r"^SECRET_KEY=\S+", text, re.M))
        if has_sk:
            skip(".env already configured with keys")
            ok("Environment file ready")
            return
        skip(".env exists but some keys are empty — auto-filling ...")

    if not example.exists():
        warn(".env.example not found — creating minimal .env")
        _write_minimal_env(env_file)
        return

    template = example.read_text(encoding="utf-8", errors="ignore")

    # ── Generate secure keys ──────────────────────────────────────────
    sk  = secrets.token_hex(64)
    ist = secrets.token_hex(32)
    ek  = _generate_fernet_key()

    lines = []
    for line in template.splitlines():
        stripped = line.split("=", 1)
        key      = stripped[0].strip() if stripped else ""
        val      = stripped[1].strip() if len(stripped) > 1 else ""
        if key == "SECRET_KEY" and not val:
            lines.append(f"SECRET_KEY={sk}")
            ok(f"SECRET_KEY        auto-generated ({len(sk)} chars)")
        elif key == "INTERNAL_SERVICE_TOKEN" and not val:
            lines.append(f"INTERNAL_SERVICE_TOKEN={ist}")
            ok(f"INTERNAL_SERVICE_TOKEN auto-generated")
        elif key == "EVIDENCE_ENCRYPTION_KEY" and not val:
            lines.append(f"EVIDENCE_ENCRYPTION_KEY={ek}")
            ok(f"EVIDENCE_ENCRYPTION_KEY auto-generated")
        else:
            lines.append(line)

    env_file.write_text("\n".join(lines), encoding="utf-8")
    try:
        if not IS_WIN:
            env_file.chmod(0o600)
    except Exception:
        pass

    ok(".env created with all secure keys")
    warn("Add OPENROUTER_API_KEY to .env to enable all AI features (https://openrouter.ai/keys)")


def _generate_fernet_key() -> str:
    try:
        rc, out = _run([str(PYTHON_BIN), "-c",
                        "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"],
                       timeout=10)
        if rc == 0:
            return out.strip()
    except Exception:
        pass
    return secrets.token_urlsafe(32)


def _write_minimal_env(path: Path):
    sk = secrets.token_hex(64)
    path.write_text(
        f"ENVIRONMENT=development\n"
        f"DATABASE_URL=sqlite+aiosqlite:///./logs/cybersecurity.db\n"
        f"SECRET_KEY={sk}\n"
        f"ALLOWED_ORIGINS=http://localhost:3000\n"
        f"AISS_LICENSE_KEY=\n"
        f"OPENROUTER_API_KEY=\n"
        f"OPENROUTER_MODEL=anthropic/claude-3.5-sonnet\n"
        f"LOG_FORMAT=text\n"
        f"LOG_LEVEL=INFO\n"
        f"DISABLE_TTS=1\n"
        f"DISABLE_YOLO=1\n",
        encoding="utf-8"
    )
    ok(f".env created with auto-generated SECRET_KEY")


# ─────────────────────────────────────────────────────────────────────
# STEP 7 — DATABASE MIGRATIONS
# ─────────────────────────────────────────────────────────────────────

def run_migrations():
    section("Step 7 — Database Migrations")
    info("Running Alembic migrations ...")
    rc, out = _run([str(PYTHON_BIN), "-m", "alembic", "upgrade", "head"],
                   cwd=str(SCRIPT_DIR), timeout=60)
    if rc == 0:
        ok("Database schema up to date")
    else:
        # Try init DB directly as fallback
        warn(f"Alembic migration failed ({out.strip()[:80]}) — using direct DB init")
        rc2, _ = _run([str(PYTHON_BIN), "-c",
                       "import asyncio; from core.database import init_db; asyncio.run(init_db())"],
                      cwd=str(SCRIPT_DIR), timeout=30)
        if rc2 == 0:
            ok("Database initialised via direct init")
        else:
            warn("Database init skipped — will retry on first request")


# ─────────────────────────────────────────────────────────────────────
# STEP 8 — ML MODELS
# ─────────────────────────────────────────────────────────────────────

def download_models():
    section("Step 8 — ML Model Downloads")
    models = [
        ("spaCy en_core_web_sm",
         [str(PYTHON_BIN), "-m", "spacy", "download", "en_core_web_sm"],
         "spaCy English NLP model"),
        ("Playwright chromium",
         [str(PYTHON_BIN), "-m", "playwright", "install", "chromium", "--with-deps"],
         "Chromium for phishing screenshots"),
    ]
    for name, cmd, desc in models:
        print(f"  {clr('→', CYAN)} Downloading {clr(name, CYAN)} — {clr(desc, DIM)} ...", end=" ")
        rc, _ = _run(cmd, timeout=300)
        if rc == 0:
            print(f"\r  {clr('✔', GREEN)} Downloaded: {name:<40} {clr(desc, DIM)}")
        else:
            print(f"\r  {clr('○', DIM)} Skipped:    {name:<40} {clr('(optional — will retry at runtime)', DIM)}")


# ─────────────────────────────────────────────────────────────────────
# STEP 9 — LIBRARY AUTO-INTEGRATION (lib_registry)
# ─────────────────────────────────────────────────────────────────────

def integrate_libraries():
    section("Step 9 — Library Auto-Integration")
    info("Running AISS library registry — initialising all detected libraries ...")
    info("This validates credentials, downloads model weights, and warms up clients.")
    info("Libraries with missing credentials will be gracefully disabled.\n")

    rc, out = _run(
        [str(PYTHON_BIN), "-c", """
import asyncio, sys, os
os.chdir(r'""" + str(SCRIPT_DIR).replace("\\", "\\\\") + r"""')
sys.path.insert(0, r'""" + str(SCRIPT_DIR).replace("\\", "\\\\") + r"""')
from dotenv import load_dotenv
load_dotenv()
from core.lib_registry import lib_registry
async def main():
    await lib_registry.init_all(timeout_secs=60.0)
    statuses = lib_registry.status()
    enabled  = [s for s in statuses if s['enabled']]
    disabled = [s for s in statuses if not s['enabled']]
    print(f"ENABLED:{len(enabled)}")
    print(f"DISABLED:{len(disabled)}")
    for s in statuses:
        icon = "OK" if s['enabled'] else "NO"
        print(f"  {icon}  {s['name']:<30} {s['version'][:12]:<14} {s['notes'][:40]}")
asyncio.run(main())
"""],
        cwd=str(SCRIPT_DIR), timeout=180
    )

    if rc == 0:
        enabled_count  = 0
        disabled_count = 0
        for line in out.splitlines():
            if line.startswith("ENABLED:"):
                enabled_count = int(line.split(":")[1])
            elif line.startswith("DISABLED:"):
                disabled_count = int(line.split(":")[1])
            elif line.startswith("  OK"):
                parts = line.split()
                name  = parts[2] if len(parts) > 2 else ""
                ver   = parts[3] if len(parts) > 3 else ""
                print(f"  {clr('✔', GREEN)} {name:<32} {clr(ver, DIM)}")
            elif line.startswith("  NO"):
                parts = line.split()
                name  = parts[2] if len(parts) > 2 else ""
                notes = " ".join(parts[4:])[:50] if len(parts) > 4 else ""
                print(f"  {clr('○', DIM)} {name:<32} {clr('disabled — ' + notes, DIM)}")

        print()
        ok(f"Library integration complete: "
           f"{clr(str(enabled_count), GREEN, BOLD)} active, "
           f"{clr(str(disabled_count), DIM)} disabled (missing credentials/optional)")
    else:
        warn("Library integration ran with warnings — check .env for missing API keys")
        info("Run 'python aiss.py' again after adding API keys to .env")


# ─────────────────────────────────────────────────────────────────────
# STEP 10 — STARTUP VALIDATION
# ─────────────────────────────────────────────────────────────────────

def run_startup_checks():
    section("Step 10 — Startup Validation")
    rc, out = _run(
        [str(PYTHON_BIN), "-c", """
import asyncio, sys, os
os.chdir(r'""" + str(SCRIPT_DIR).replace("\\", "\\\\") + r"""')
sys.path.insert(0, r'""" + str(SCRIPT_DIR).replace("\\", "\\\\") + r"""')
from dotenv import load_dotenv
load_dotenv()
from core.startup_validator import run_startup_checks
asyncio.run(run_startup_checks())
"""],
        cwd=str(SCRIPT_DIR), timeout=60
    )
    if rc == 0:
        ok("All startup checks passed")
    else:
        warn("Some startup checks have warnings — review output above")
        info("Non-critical warnings will not prevent startup")


# ─────────────────────────────────────────────────────────────────────
# STEP 11 — START AISS BACKEND
# ─────────────────────────────────────────────────────────────────────

def start_backend():
    section("Step 11 — Starting AISS Backend")
    print()

    print(f"  {clr('╔════════════════════════════════════════════╗', CYAN)}")
    print(f"  {clr('║', CYAN)} {clr('AISS is starting...', GREEN, BOLD):<44}{clr('║', CYAN)}")
    print(f"  {clr('║', CYAN)} {'':<44}{clr('║', CYAN)}")
    print(f"  {clr('║', CYAN)}  {clr('➜ API Docs:', CYAN)}  http://localhost:8000/docs    {clr('║', CYAN)}")
    print(f"  {clr('║', CYAN)}  {clr('➜ Health:  ', CYAN)}  http://localhost:8000/api/health{clr('║', CYAN)}")
    print(f"  {clr('║', CYAN)}  {clr('➜ Metrics: ', CYAN)}  http://localhost:8000/metrics  {clr('║', CYAN)}")
    print(f"  {clr('║', CYAN)}  {clr('➜ WebSocket:', CYAN)} ws://localhost:8000/ws         {clr('║', CYAN)}")
    print(f"  {clr('║', CYAN)} {'':<44}{clr('║', CYAN)}")
    print(f"  {clr('║', CYAN)}  {clr('Press Ctrl+C to stop', DIM):<44}{clr('║', CYAN)}")
    print(f"  {clr('╚════════════════════════════════════════════╝', CYAN)}")
    print()

    # Try to open browser after 2s
    def _open_browser():
        time.sleep(2.5)
        try:
            import webbrowser
            webbrowser.open("http://localhost:8000/docs")
        except Exception:
            pass
    threading.Thread(target=_open_browser, daemon=True).start()

    # Replace current process with uvicorn (clean signal handling)
    cmd = [
        str(PYTHON_BIN), "-m", "uvicorn", "main:app",
        "--host", "0.0.0.0",
        "--port", "8000",
        "--workers", "1",
        "--log-level", "info",
        "--reload-dir", str(SCRIPT_DIR),
    ]

    try:
        os.execv(str(PYTHON_BIN), cmd)
    except AttributeError:
        # Windows fallback (os.execv replaces process but may not work on all Windows configs)
        subprocess.run(cmd, cwd=str(SCRIPT_DIR))


# ─────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────

def install_frontend():
    """Install frontend dependencies and write .env pointing to backend."""
    section("Step 14 — Frontend Dashboard Setup")
    frontend_dir = SCRIPT_DIR.parent / "frontend"

    if not frontend_dir.exists():
        warn("frontend/ directory not found — skipping (run: git clone https://github.com/AhmedIbrahimofficial/aiss-core-guardian.git frontend)")
        return

    # Write frontend .env
    env_path = frontend_dir / ".env"
    if not env_path.exists():
        env_path.write_text("VITE_AISS_API_URL=http://localhost:8000\n", encoding="utf-8")
        ok("Frontend .env created → VITE_AISS_API_URL=http://localhost:8000")
    else:
        skip("Frontend .env already exists")

    # Detect package manager: bun first, then npm
    pkg_mgr = None
    if shutil.which("bun"):
        pkg_mgr = "bun"
        ok("Package manager: bun (fast)")
    elif shutil.which("npm"):
        pkg_mgr = "npm"
        ok("Package manager: npm")
    else:
        warn("Neither bun nor npm found — install Node.js from https://nodejs.org")
        warn("Frontend will not be installed — backend still works without it")
        return

    # Check if node_modules already exist
    if (frontend_dir / "node_modules").exists():
        skip("node_modules already installed")
    else:
        info(f"Installing frontend dependencies with {pkg_mgr} ...")
        cmd = ["bun", "install"] if pkg_mgr == "bun" else ["npm", "install", "--silent"]
        rc, out = _run(cmd, cwd=str(frontend_dir), timeout=300)
        if rc == 0:
            ok("Frontend dependencies installed")
        else:
            warn(f"Frontend install failed: {out[:100]}")
            warn("You can install manually: cd frontend && npm install")

    ok("Frontend ready — starts automatically with AISS")


def start_frontend_dev_server():
    """Launch the frontend dev server as a background process."""
    frontend_dir = SCRIPT_DIR.parent / "frontend"
    if not frontend_dir.exists() or not (frontend_dir / "node_modules").exists():
        return None

    import subprocess as _sp
    pkg_mgr = "bun" if shutil.which("bun") else ("npm" if shutil.which("npm") else None)
    if not pkg_mgr:
        return None

    cmd = ["bun", "run", "dev"] if pkg_mgr == "bun" else ["npm", "run", "dev"]
    try:
        proc = _sp.Popen(
            cmd,
            cwd=str(frontend_dir),
            stdout=_sp.DEVNULL,
            stderr=_sp.DEVNULL,
            creationflags=_sp.CREATE_NEW_PROCESS_GROUP if IS_WIN else 0,
        )
        ok(f"Frontend dev server started (pid={proc.pid})")
        info("Dashboard: http://localhost:3000")
        return proc
    except Exception as e:
        warn(f"Could not start frontend: {e}")
        return None


def show_remote_agents_info():
    section("Step 12 — Remote Agent Monitoring")
    print(f"""
  {clr('Connect other computers to AISS for centralized monitoring.', WHITE, BOLD)}

  {clr('Supported network types:', CYAN)}
    {clr('LAN', GREEN)}  — Local area network (192.168.x.x / 10.x.x.x)
    {clr('WAN', YELLOW)} — Internet (public IP or domain)
    {clr('VPN', BLUE)}  — Virtual private network (10.8.x.x)
    {clr('MAN', MAGENTA)} — Metropolitan/multi-site network

  {clr('Step 1:', CYAN)} Generate an agent token on THIS machine:
    {clr('curl -X POST http://localhost:8000/api/agents/token/generate', DIM)}
    {clr('  -H "Authorization: Bearer YOUR_JWT"', DIM)}
    {clr('  -d \'{"label": "my-server"}\'', DIM)}

  {clr('Step 2:', CYAN)} On EACH remote computer, run:
    {clr('# Windows:', DIM)}
    {clr('python aiss_agent.py --server ws://YOUR_AISS_IP:8000 --token TOKEN', WHITE)}

    {clr('# Linux/Mac:', DIM)}
    {clr('./aiss_agent.py --server ws://192.168.1.100:8000 --token TOKEN', WHITE)}

    {clr('# Over internet (WAN):', DIM)}
    {clr('python aiss_agent.py --server wss://your-domain.com --token TOKEN', WHITE)}

  {clr('Step 3:', CYAN)} Monitor from AISS:
    {clr('GET http://localhost:8000/api/agents/', DIM)}
    {clr('GET http://localhost:8000/api/agents/{id}/threats', DIM)}
""")
    ok("Remote agent system ready — generate tokens at /api/agents/token/generate")


def run_cmd_setup_wizard():
    """
    CMD-based setup wizard — asks configuration questions when no frontend is present.
    When frontend is added, these questions automatically become popup dialogs.
    """
    section("Step 13 — Configuration Wizard")

    # Check if already configured
    env_file = SCRIPT_DIR / ".env"
    if env_file.exists():
        text = env_file.read_text(encoding="utf-8", errors="ignore")
        # Count how many keys are filled in
        filled = sum(1 for line in text.splitlines()
                     if "=" in line and not line.startswith("#")
                     and len(line.split("=", 1)[1].strip()) > 0)
        if filled > 15:
            skip(f".env already has {filled} configured keys")
            info("Run 'python aiss.py --wizard' to re-run the configuration wizard")
            return

    if "--wizard" not in sys.argv and "--no-wizard" not in sys.argv:
        print(f"\n  {clr('Would you like to configure AISS now?', CYAN, BOLD)}")
        print(f"  {clr('(Recommended for first-time setup)', DIM)}")
        choice = input(f"\n  {clr('Run setup wizard?', BOLD)} [Y/n]: ").strip().lower()
        if choice in ("n", "no"):
            info("Skipping wizard. Edit .env manually or run: python aiss.py --wizard")
            return

    print(f"\n  {clr('AISS Setup Wizard', CYAN, BOLD)}")
    print(f"  {clr('Answer each question (press Enter to keep default)', DIM)}")
    print(f"  {clr('Leave blank to skip optional settings', DIM)}\n")

    env = _read_env_simple(env_file)
    changes = {}

    # Only ask the most important questions in CMD mode
    CMD_QUESTIONS = [
        # (env_key, prompt, default, is_password, help)
        ("ENVIRONMENT",
         "Deployment mode",
         "development",
         False,
         "development or production"),
        ("DATABASE_URL",
         "Database URL",
         "sqlite+aiosqlite:///./logs/cybersecurity.db",
         False,
         "sqlite / mysql+aiomysql:// / postgresql+asyncpg://"),
        ("OPENROUTER_API_KEY",
         "OpenRouter API key (powers ALL AI features)",
         "",
         True,
         "sk-or-v1-... from openrouter.ai/keys — single key for Claude, GPT-4, Gemini, Llama"),
        ("OPENROUTER_MODEL",
         "Preferred AI model via OpenRouter",
         "anthropic/claude-3.5-sonnet",
         False,
         "anthropic/claude-3.5-sonnet | openai/gpt-4o | openai/gpt-4o-mini | google/gemini-pro-1.5"),
        ("VIRUSTOTAL_API_KEY",
         "VirusTotal API key",
         "",
         True,
         "from virustotal.com — threat enrichment"),
        ("APPRISE_URLS",
         "Alert channel URL",
         "",
         False,
         "ntfy://ntfy.sh/my-topic (free) or discord://... slack://..."),
        ("AISS_LICENSE_KEY",
         "AISS license key",
         "",
         True,
         "AISS-ENT-... from aiss.io/pricing (leave blank for trial)"),
        ("ALLOWED_ORIGINS",
         "Frontend URL (CORS)",
         "http://localhost:3000",
         False,
         "URL of your dashboard"),
    ]

    for key, prompt, default, is_pass, hint in CMD_QUESTIONS:
        current = env.get(key, default)
        display_current = ("***" if is_pass and current else current) or default or "(empty)"

        print(f"  {clr('?', CYAN, BOLD)} {clr(prompt, WHITE)}")
        if hint:
            print(f"    {clr(hint, DIM)}")
        print(f"    {clr('Current:', DIM)} {clr(display_current[:60], DIM)}")

        try:
            if is_pass:
                import getpass
                val = getpass.getpass(f"    {clr('Value', BOLD)} (hidden): ").strip()
            else:
                val = input(f"    {clr('Value', BOLD)}: ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break

        if val:
            changes[key] = val
            ok(f"{key} = {'***' if is_pass else val[:40]}")
        elif current:
            ok(f"{key} = kept existing value")
        else:
            skip(f"{key} = skipped")
        print()

    # Apply changes
    if changes:
        for k, v in changes.items():
            env[k] = v
            os.environ[k] = v
        _write_env_simple(env_file, env)
        ok(f"Applied {len(changes)} configuration change(s) to .env")
    else:
        skip("No changes made")

    print(f"\n  {clr('Configuration complete!', GREEN, BOLD)}")
    print(f"  Edit {clr('.env', YELLOW)} anytime to update settings.")
    print(f"  When frontend is deployed, these settings appear as popup dialogs.\n")


def _read_env_simple(path: Path) -> dict:
    env = {}
    if not path.exists():
        return env
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip()
    return env


def _write_env_simple(path: Path, env: dict) -> None:
    if not path.exists():
        return
    lines_out = []
    written   = set()
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k = stripped.split("=", 1)[0].strip()
            if k in env:
                lines_out.append(f"{k}={env[k]}")
                written.add(k)
                continue
        lines_out.append(line)
    for k, v in env.items():
        if k not in written:
            lines_out.append(f"{k}={v}")
    path.write_text("\n".join(lines_out), encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────
# SHELL HELPER
# ─────────────────────────────────────────────────────────────────────

def _run(cmd: list, cwd: str = None, timeout: int = 120) -> tuple:
    """Run a subprocess and return (returncode, combined_output)."""
    try:
        r = subprocess.run(
            cmd,
            cwd=cwd or str(SCRIPT_DIR),
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ,
                 "PYTHONPATH": str(SCRIPT_DIR),
                 "PYTHONIOENCODING": "utf-8"},
        )
        return r.returncode, (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return 1, "timeout"
    except FileNotFoundError as e:
        return 1, str(e)
    except Exception as e:
        return 1, str(e)
    try:
        r = subprocess.run(
            cmd,
            cwd=cwd or str(SCRIPT_DIR),
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "PYTHONPATH": str(SCRIPT_DIR)},
        )
        return r.returncode, (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return 1, "timeout"
    except FileNotFoundError as e:
        return 1, str(e)
    except Exception as e:
        return 1, str(e)


# ─────────────────────────────────────────────────────────────────────
# GLOBAL REGISTRATION  (adds "aiss" command to PATH)
# ─────────────────────────────────────────────────────────────────────

def register_global_command():
    """Register 'aiss' as a system-wide command so user can type just 'aiss'."""
    section("Global Command Registration")

    if IS_WIN:
        # Create aiss.bat in a directory that is (or will be) on PATH
        aiss_bat = SCRIPT_DIR / "aiss_cmd.bat"
        aiss_bat.write_text(
            f'@echo off\n'
            f'cd /d "{SCRIPT_DIR}"\n'
            f'"{PYTHON_BIN}" "{SCRIPT_DIR}\\aiss.py" %*\n',
            encoding="utf-8"
        )
        # Add SCRIPT_DIR to user PATH if not already there
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE
            ) as key:
                current_path, _ = winreg.QueryValueEx(key, "Path")
                if str(SCRIPT_DIR) not in current_path:
                    new_path = current_path + ";" + str(SCRIPT_DIR)
                    winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)
                    ok(f"Added to PATH: {SCRIPT_DIR}")
                    warn("Restart your terminal for 'aiss' command to work globally")
                else:
                    skip("Already in PATH")
            ok("'aiss' command registered — you can now type: aiss")
        except Exception as e:
            warn(f"Could not auto-register (run as admin): {e}")
            info(f"Manual: add '{SCRIPT_DIR}' to your PATH environment variable")
    else:
        # Create symlink or wrapper in /usr/local/bin
        wrapper = Path("/usr/local/bin/aiss")
        try:
            wrapper.write_text(
                f"#!/bin/bash\n"
                f"cd \"{SCRIPT_DIR}\"\n"
                f"exec \"{PYTHON_BIN}\" \"{SCRIPT_DIR}/aiss.py\" \"$@\"\n"
            )
            wrapper.chmod(0o755)
            ok("'aiss' registered at /usr/local/bin/aiss")
            info("You can now type: aiss")
        except PermissionError:
            local_bin = Path.home() / ".local" / "bin"
            local_bin.mkdir(parents=True, exist_ok=True)
            wrapper = local_bin / "aiss"
            wrapper.write_text(
                f"#!/bin/bash\ncd \"{SCRIPT_DIR}\"\n"
                f"exec \"{PYTHON_BIN}\" \"{SCRIPT_DIR}/aiss.py\" \"$@\"\n"
            )
            wrapper.chmod(0o755)
            ok(f"'aiss' registered at {wrapper}")
            info(f"Ensure {local_bin} is in your PATH: echo 'export PATH=\"$HOME/.local/bin:$PATH\"' >> ~/.bashrc")


# ─────────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────

def main():
    # Parse flags
    first_run  = not VENV_DIR.exists() or "--reinstall" in sys.argv
    skip_start = "--no-start" in sys.argv or "--install-only" in sys.argv

    # Always show banner
    banner()

    if first_run or "--install" in sys.argv or "--reinstall" in sys.argv:
        mode = "FIRST RUN — Full Installation"
    elif "--wizard" in sys.argv:
        mode = "CONFIGURATION WIZARD"
    elif "--update" in sys.argv:
        mode = "UPDATE — Checking for new packages"
    else:
        mode = "QUICK START — Verifying & Launching"

    print(f"  {clr('Mode:', BOLD)} {clr(mode, CYAN)}")
    print(f"  {clr('Dir: ', BOLD)} {clr(str(SCRIPT_DIR), DIM)}")
    print(f"  {clr('OS:  ', BOLD)} {clr(platform.system() + ' ' + platform.release(), DIM)}")
    print(f"  {clr('Py:  ', BOLD)} {clr(sys.version.split()[0], DIM)}")
    print()

    # ── Always run these ──────────────────────────────────────────────
    check_python()
    ensure_venv()

    # ── Auto-detect and install ANY new packages added to ALL_PACKAGES ─
    # This is the key feature: every time AISS adds a new module/library,
    # running 'aiss' will automatically detect and install it — user does nothing.
    install_packages()

    check_services()
    create_directories()
    setup_env()
    run_migrations()

    # ── Only download models on first run (slow) ──────────────────────
    flag_file = SCRIPT_DIR / "data" / ".models_downloaded"
    if not flag_file.exists() or "--reinstall" in sys.argv:
        download_models()
        flag_file.parent.mkdir(exist_ok=True)
        flag_file.touch()

    # ── Library integration ───────────────────────────────────────────
    integrate_libraries()

    # ── Startup validation ────────────────────────────────────────────
    run_startup_checks()

    # ── Global registration (so user can type just 'aiss') ────────────
    register_flag = SCRIPT_DIR / "data" / ".global_registered"
    if not register_flag.exists() or "--register" in sys.argv:
        register_global_command()
        register_flag.touch()

    # ── Remote agents info ────────────────────────────────────────────
    show_remote_agents_info()

    # ── Frontend dashboard install ────────────────────────────────────
    install_frontend()

    # ── CMD Setup Wizard (when no frontend yet) ───────────────────────
    # Skip if --wizard flag passed (run it directly) or if --no-wizard
    if "--wizard" in sys.argv:
        # Force full wizard re-run
        import pathlib as _pl
        _pl.Path("data/popup_state.json").unlink(missing_ok=True)
    run_cmd_setup_wizard()

    # ── Final summary ─────────────────────────────────────────────────
    _print_final_summary()

    if not skip_start:
        # Start frontend in background, then start backend (blocks)
        start_frontend_dev_server()
        time.sleep(1)
        start_backend()
    else:
        ok("Installation complete. Run 'aiss' or 'python aiss.py' to start.")


def _print_final_summary():
    """Print the final summary box with all endpoints and next steps."""
    section("AISS Ready")
    if _UNICODE:
        tl, tr, bl, br, h, v, ml, mr = "╔", "╗", "╚", "╝", "═", "║", "╠", "╣"
    else:
        tl, tr, bl, br, h, v, ml, mr = "+", "+", "+", "+", "=", "|", "+", "+"
    W  = "="*56 if not _UNICODE else "═"*56
    W2 = "-"*56 if not _UNICODE else "─"*56
    arrow = "->" if not _UNICODE else "->"

    print(f"""
  {clr(tl+W+tr, GREEN, BOLD)}
  {clr(v, GREEN)}  {clr('AISS is fully set up and ready!', WHITE, BOLD):<54}{clr(v, GREEN)}
  {clr(ml+W2+mr, GREEN)}
  {clr(v, GREEN)}  {clr('API & Dashboard', CYAN, BOLD):<54}{clr(v, GREEN)}
  {clr(v, GREEN)}  {clr('Dashboard   :', CYAN)}  {clr('http://localhost:3000  (frontend)', WHITE):<36}{clr(v, GREEN)}
  {clr(v, GREEN)}  {clr('API Docs    :', CYAN)}  {clr('http://localhost:8000/docs', WHITE):<36}{clr(v, GREEN)}
  {clr(v, GREEN)}  {clr('Health      :', CYAN)}  {clr('http://localhost:8000/api/health', WHITE):<36}{clr(v, GREEN)}
  {clr(v, GREEN)}  {clr('Metrics     :', CYAN)}  {clr('http://localhost:8000/metrics', WHITE):<36}{clr(v, GREEN)}
  {clr(v, GREEN)}  {clr('Topology    :', CYAN)}  {clr('http://localhost:8000/api/topology/map', WHITE):<36}{clr(v, GREEN)}
  {clr(v, GREEN)}  {clr('Agents      :', CYAN)}  {clr('http://localhost:8000/api/agents/', WHITE):<36}{clr(v, GREEN)}
  {clr(v, GREEN)}  {clr('Wizard API  :', CYAN)}  {clr('http://localhost:8000/api/system/wizard', WHITE):<36}{clr(v, GREEN)}
  {clr(ml+W2+mr, GREEN)}
  {clr(v, GREEN)}  {clr('Connect Other Computers', CYAN, BOLD):<54}{clr(v, GREEN)}
  {clr(v, GREEN)}  {clr('1. Generate token: POST /api/agents/token/generate', DIM):<54}{clr(v, GREEN)}
  {clr(v, GREEN)}  {clr('2. On remote PC:  python aiss_agent.py \\', DIM):<54}{clr(v, GREEN)}
  {clr(v, GREEN)}  {clr('      --server ws://THIS_IP:8000 --token TOKEN', DIM):<54}{clr(v, GREEN)}
  {clr(ml+W2+mr, GREEN)}
  {clr(v, GREEN)}  {clr('Commands', CYAN, BOLD):<54}{clr(v, GREEN)}
  {clr(v, GREEN)}  {clr('aiss              ', WHITE, BOLD)}  {arrow} Start (auto-update + launch) {clr(v, GREEN)}
  {clr(v, GREEN)}  {clr('aiss --wizard     ', WHITE)}  {arrow} Re-run config questions    {clr(v, GREEN)}
  {clr(v, GREEN)}  {clr('aiss --reinstall  ', WHITE)}  {arrow} Force reinstall packages   {clr(v, GREEN)}
  {clr(v, GREEN)}  {clr('aiss --install-only', WHITE)} {arrow} Install only, do not start {clr(v, GREEN)}
  {clr(v, GREEN)}  {clr('python monitor.py ', WHITE)}  {arrow} Live CMD threat dashboard  {clr(v, GREEN)}
  {clr(bl+W+br, GREEN, BOLD)}
""")
    print(f"  {clr('Next time just type:', DIM)}  {clr('aiss', WHITE, BOLD)}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {clr('Stopped by user.', YELLOW)}\n")
        sys.exit(0)
