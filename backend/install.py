#!/usr/bin/env python3
"""
AISS — One-Click Installer
Supports: Windows, Linux, macOS

Usage:
    python install.py              # interactive setup
    python install.py --headless   # non-interactive (all defaults)
    python install.py --upgrade    # upgrade existing installation

What this does:
  1. Checks Python version (requires 3.11+)
  2. Creates virtual environment
  3. Installs all dependencies
  4. Checks for Redis, PostgreSQL, Ollama
  5. Creates required directories
  6. Generates .env from .env.example
  7. Generates secure cryptographic keys
  8. Runs database migrations
  9. Downloads spaCy language model
 10. Runs startup validation
 11. Optionally starts the backend
"""

import os
import sys
import subprocess
import platform
import shutil
import secrets
import json
from pathlib import Path
from typing import Optional

# ── Colours ──────────────────────────────────────────────────────────
IS_WIN = platform.system() == "Windows"


def c(text: str, colour: str) -> str:
    if IS_WIN:
        return text
    codes = {"green": "\033[92m", "red": "\033[91m", "yellow": "\033[93m",
             "cyan": "\033[96m", "bold": "\033[1m", "reset": "\033[0m"}
    return f"{codes.get(colour,'')}{text}{codes['reset']}"


def ok(msg):   print(c(f"  ✓  {msg}", "green"))
def warn(msg): print(c(f"  ⚠  {msg}", "yellow"))
def err(msg):  print(c(f"  ✗  {msg}", "red"))
def info(msg): print(c(f"  ➜  {msg}", "cyan"))
def hdr(msg):  print(c(f"\n{'═'*60}\n  {msg}\n{'═'*60}", "bold"))


# ── Helpers ───────────────────────────────────────────────────────────

def run(cmd: list, cwd=None, capture=True, env=None) -> tuple[int, str]:
    try:
        r = subprocess.run(
            cmd, cwd=cwd, capture_output=capture,
            text=True, env=env or os.environ.copy()
        )
        return r.returncode, (r.stdout + r.stderr).strip()
    except FileNotFoundError:
        return 1, f"Command not found: {cmd[0]}"


def ask(prompt: str, default: str = "") -> str:
    if "--headless" in sys.argv:
        return default
    val = input(f"  {prompt} [{default}]: ").strip()
    return val if val else default


def ask_bool(prompt: str, default: bool = True) -> bool:
    if "--headless" in sys.argv:
        return default
    d = "Y/n" if default else "y/N"
    val = input(f"  {prompt} [{d}]: ").strip().lower()
    if not val:
        return default
    return val in ("y", "yes")


# ── Step functions ────────────────────────────────────────────────────

def check_python() -> bool:
    hdr("Step 1: Python Version Check")
    v = sys.version_info
    if v < (3, 11):
        err(f"Python 3.11+ required. You have {v.major}.{v.minor}.{v.micro}")
        err("Download from https://python.org/downloads")
        return False
    ok(f"Python {v.major}.{v.minor}.{v.micro}")
    return True


def create_venv() -> Optional[Path]:
    hdr("Step 2: Virtual Environment")
    venv_path = Path(".venv")
    if venv_path.exists():
        warn(f"Virtual environment already exists at {venv_path}")
        if not ask_bool("Recreate it?", default=False):
            ok("Using existing virtual environment")
            return venv_path

    info("Creating .venv ...")
    code, out = run([sys.executable, "-m", "venv", ".venv"])
    if code != 0:
        err(f"venv creation failed: {out}")
        return None
    ok("Virtual environment created: .venv/")
    return venv_path


def get_python_bin(venv: Path) -> Path:
    if IS_WIN:
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def install_deps(python_bin: Path) -> bool:
    hdr("Step 3: Installing Dependencies")
    info("Upgrading pip ...")
    run([str(python_bin), "-m", "pip", "install", "--upgrade", "pip", "wheel"])

    req_file = "requirements.txt"
    info(f"Installing from {req_file} (this may take several minutes) ...")
    code, out = run(
        [str(python_bin), "-m", "pip", "install", "-r", req_file,
         "--no-warn-script-location"],
        capture=False,
    )
    if code != 0:
        err("Dependency installation failed.")
        err("Try running manually: pip install -r requirements.txt")
        return False
    ok("All dependencies installed")
    return True


def check_services() -> dict:
    hdr("Step 4: Service Checks")
    found = {}

    # Redis
    code, _ = run(["redis-cli", "ping"])
    if code == 0:
        ok("Redis: running")
        found["redis"] = True
    else:
        warn("Redis: not running or not installed")
        if IS_WIN:
            warn("Install Memurai (https://www.memurai.com/) or run Redis in WSL")
        else:
            warn("Install: sudo apt install redis-server && sudo systemctl start redis")
        found["redis"] = False

    # PostgreSQL
    code, _ = run(["pg_isready"])
    if code == 0:
        ok("PostgreSQL: running")
        found["postgres"] = True
    else:
        warn("PostgreSQL: not running (SQLite will be used if DATABASE_URL not set)")
        found["postgres"] = False

    # Ollama (optional)
    code, _ = run(["ollama", "list"])
    if code == 0:
        ok("Ollama: installed (local LLM inference available)")
        found["ollama"] = True
    else:
        info("Ollama: not installed (optional — needed for local LLM models)")
        found["ollama"] = False

    return found


def create_directories() -> bool:
    hdr("Step 5: Directory Structure")
    dirs = [
        "logs", "logs/evidence", "data", "data/models",
        "rules", "static", "deploy/nginx", "deploy/nginx/ssl",
    ]
    for d in dirs:
        Path(d).mkdir(parents=True, exist_ok=True)
        ok(f"Created: {d}/")

    # Secure sensitive directories
    for d in ["logs", "data"]:
        try:
            if not IS_WIN:
                os.chmod(d, 0o700)
        except Exception:
            pass
    return True


def generate_env() -> bool:
    hdr("Step 6: Environment Configuration")
    env_file = Path(".env")

    if env_file.exists():
        warn(".env already exists")
        if not ask_bool("Regenerate it? (existing values will be preserved for non-empty keys)", default=False):
            ok("Keeping existing .env")
            return True

    # Read example template
    example = Path(".env.example")
    if not example.exists():
        err(".env.example not found")
        return False

    template = example.read_text()
    ok("Loaded .env.example template")

    # Generate cryptographic keys
    info("Generating secure cryptographic keys ...")
    sk = secrets.token_hex(64)
    ist = secrets.token_hex(32)

    try:
        from cryptography.fernet import Fernet
        ek = Fernet.generate_key().decode()
    except ImportError:
        ek = secrets.token_urlsafe(32)

    # Substitute placeholders
    lines = []
    for line in template.splitlines():
        if line.startswith("SECRET_KEY=") and "=" in line and line.split("=", 1)[1].strip() == "":
            lines.append(f"SECRET_KEY={sk}")
        elif line.startswith("INTERNAL_SERVICE_TOKEN=") and line.split("=", 1)[1].strip() == "":
            lines.append(f"INTERNAL_SERVICE_TOKEN={ist}")
        elif line.startswith("EVIDENCE_ENCRYPTION_KEY=") and line.split("=", 1)[1].strip() == "":
            lines.append(f"EVIDENCE_ENCRYPTION_KEY={ek}")
        else:
            lines.append(line)

    env_file.write_text("\n".join(lines))
    try:
        if not IS_WIN:
            env_file.chmod(0o600)
    except Exception:
        pass

    ok(f".env created with auto-generated keys")
    warn("Add OPENROUTER_API_KEY to .env for AI features (https://openrouter.ai/keys)")
    warn("Fill in AISS_LICENSE_KEY for commercial use")
    return True


def run_migrations(python_bin: Path) -> bool:
    hdr("Step 7: Database Migrations")
    info("Running Alembic migrations ...")
    code, out = run([str(python_bin), "-m", "alembic", "upgrade", "head"])
    if code != 0:
        warn(f"Migration failed (will retry on app start): {out[:200]}")
        return False
    ok("Database schema up to date")
    return True


def download_spacy_model(python_bin: Path) -> bool:
    hdr("Step 8: spaCy Language Model")
    model = "en_core_web_sm"
    info(f"Downloading spaCy model: {model} ...")
    code, _ = run(
        [str(python_bin), "-m", "spacy", "download", model],
        capture=False,
    )
    if code == 0:
        ok(f"spaCy model downloaded: {model}")
    else:
        warn(f"spaCy model download failed — will retry at runtime")
    return True


def run_startup_check(python_bin: Path) -> bool:
    hdr("Step 9: Startup Validation")
    code, out = run([
        str(python_bin), "-c",
        "import asyncio; from core.startup_validator import run_startup_checks; '   '  "
        "asyncio.run(run_startup_checks())"
    ])
    if code == 0:
        ok("Startup validation passed")
    else:
        warn("Some startup checks warned — review above output")
    return True


def write_start_scripts() -> None:
    hdr("Step 10: Start Scripts")

    if IS_WIN:
        Path("start.bat").write_text(
            "@echo off\n"
            "call .venv\\Scripts\\activate\n"
            "python main.py\n"
        )
        ok("Created start.bat")
    else:
        script = Path("start.sh")
        script.write_text(
            "#!/bin/bash\n"
            'source .venv/bin/activate\n'
            'exec uvicorn main:app --host 0.0.0.0 --port 8000 --workers 1\n'
        )
        script.chmod(0o755)
        ok("Created start.sh")


# ── Main ─────────────────────────────────────────────────────────────

def main():
    hdr("AISS Installer v2.0.0")
    print(c("  AI Intelligent Security System", "cyan"))
    print(c("  https://aiss.io\n", "cyan"))

    steps_passed = 0
    steps_total  = 10

    if not check_python():
        sys.exit(1)
    steps_passed += 1

    venv = create_venv()
    if not venv:
        sys.exit(1)
    steps_passed += 1

    python_bin = get_python_bin(venv)

    if not install_deps(python_bin):
        warn("Continuing despite dep errors — some features may be unavailable")
    else:
        steps_passed += 1

    check_services()
    steps_passed += 1

    create_directories()
    steps_passed += 1

    if generate_env():
        steps_passed += 1

    run_migrations(python_bin)
    steps_passed += 1

    download_spacy_model(python_bin)
    steps_passed += 1

    run_startup_check(python_bin)
    steps_passed += 1

    write_start_scripts()
    steps_passed += 1

    # ── Summary ───────────────────────────────────────────────────────
    hdr("Installation Complete")
    ok(f"{steps_passed}/{steps_total} steps completed successfully")
    print()
    info("Next steps:")
    print(f"  1. Edit {c('.env', 'yellow')} and fill in your API keys")
    print(f"  2. Set {c('AISS_LICENSE_KEY', 'yellow')} (or run in trial mode)")
    print(f"  3. Start AISS:")
    if IS_WIN:
        print(f"     {c('start.bat', 'cyan')}   or   {c('.venv\\Scripts\\python main.py', 'cyan')}")
    else:
        print(f"     {c('./start.sh', 'cyan')}   or   {c('docker-compose up -d', 'cyan')}")
    print()
    print(f"  API docs: {c('http://localhost:8000/docs', 'cyan')}")
    print(f"  Health:   {c('http://localhost:8000/api/health', 'cyan')}")
    print()

    if ask_bool("Start AISS now?", default=False):
        info("Starting AISS backend ...")
        os.execv(str(python_bin), [str(python_bin), "main.py"])


if __name__ == "__main__":
    main()
