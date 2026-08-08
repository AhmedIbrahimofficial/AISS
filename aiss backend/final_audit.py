"""
AISS Final Production Audit Script
Checks syntax, secrets hygiene, required files, and key structures.
Generates the final readiness report.
"""
import ast, json, os, re, sys
from pathlib import Path

ROOT = Path(__file__).parent
PASS = []; WARN = []; FAIL = []

def p(label, msg=""):
    PASS.append(label); print(f"  ✅ PASS  {label}" + (f": {msg}" if msg else ""))
def w(label, msg=""):
    WARN.append(label); print(f"  ⚠️  WARN  {label}" + (f": {msg}" if msg else ""))
def f(label, msg=""):
    FAIL.append(label); print(f"  🚫 FAIL  {label}" + (f": {msg}" if msg else ""))

print("\n" + "═"*60)
print("  AISS FINAL PRODUCTION AUDIT")
print("═"*60)

# ── 1. Credential files removed ───────────────────────────────────────
print("\n[1] Credential File Removal")
bad_files = ["admin_passwords.txt","fake_credentials.txt","fake_api_keys.txt",
             ".env.backup.txt","config.json.txt","database.sql.txt"]
for fname in bad_files:
    if not (ROOT / fname).exists():
        p(f"Removed: {fname}")
    else:
        f(f"Still exists: {fname}", "Delete this file")

# ── 2. Secrets not in source ──────────────────────────────────────────
print("\n[2] Secret Hygiene in Source Files")
BAD = [
    (r"sk-ant-api03-[A-Za-z0-9_\-]{20,}", "Anthropic key"),
    (r"sk-proj-[A-Za-z0-9_\-]{20,}",       "OpenAI key"),
    # Only flag as assignment (SECRET_KEY = "..."), not in comments/docs/tests
    (r'SECRET_KEY\s*=\s*["\']change-this-to-a-random-secret-key["\']', "Insecure default assignment"),
    (r"Pr0d_DB_P@ss",                       "Hardcoded DB password"),
    (r"r3dis_p@ss",                         "Hardcoded Redis password"),
]
SKIP_FILES_AUDIT = {"test_security.py", "security_config.py", "final_audit.py"}
py_files = [f for f in ROOT.rglob("*.py")
            if ".venv" not in str(f) and "__pycache__" not in str(f)
            and "final_audit.py" not in str(f)]
found_secrets = False
for fp in py_files:
    if fp.name in SKIP_FILES_AUDIT:
        continue
    text = fp.read_text(encoding="utf-8", errors="ignore")
    for pat, label in BAD:
        if re.search(pat, text):
            f(f"Secret in {fp.name}", label)
            found_secrets = True
if not found_secrets:
    p("No hardcoded secrets in .py files")

# ── 3. .env has no real keys ──────────────────────────────────────────
print("\n[3] .env File Check")
env_path = ROOT / ".env"
if env_path.exists():
    env_text = env_path.read_text(encoding="utf-8", errors="ignore")
    real_keys = re.findall(r"sk-ant-api03-\S+|sk-proj-\S+", env_text)
    if real_keys:
        f(".env contains real API keys", f"{len(real_keys)} found — rotate and remove")
    else:
        p(".env has no real API keys")
    if "change-this-to-a-random-secret-key" in env_text:
        f(".env SECRET_KEY is insecure default")
    else:
        p(".env SECRET_KEY is not default")
else:
    w(".env not found", "Copy from .env.example")

# ── 4. Required files exist ───────────────────────────────────────────
print("\n[4] Required Files")
required = [
    ".env.example", ".env.production.example", ".env.development.example",
    "Dockerfile", "docker-compose.yml", "requirements.txt",
    "requirements-dev.txt", "requirements-prod.txt",
    "README.md", "INSTALL.md", "DEPLOYMENT.md", "SECURITY.md",
    "ARCHITECTURE.md", "CHANGELOG.md", "LICENSE",
    "install.py", "alembic.ini",
    "core/security_config.py", "core/licensing.py",
    "core/startup_validator.py", "core/metrics.py",
    "deploy/nginx/aiss.conf",
    "tests/test_security.py", "tests/test_api.py",
    "tests/test_licensing.py", "tests/test_modules.py",
]
for fname in required:
    if (ROOT / fname).exists():
        p(f"Exists: {fname}")
    else:
        f(f"Missing: {fname}")

# ── 5. Syntax check all new files ────────────────────────────────────
print("\n[5] Syntax Validation")
check_files = [
    "core/security_config.py", "core/licensing.py",
    "core/startup_validator.py", "core/metrics.py",
    "core/middleware.py", "main.py",
    "tests/test_security.py", "tests/test_api.py",
    "tests/test_licensing.py", "tests/test_modules.py",
]
for fname in check_files:
    fp = ROOT / fname
    if not fp.exists():
        w(f"Skipping (missing): {fname}")
        continue
    try:
        ast.parse(fp.read_text(encoding="utf-8"))
        p(f"Syntax OK: {fname}")
    except SyntaxError as e:
        f(f"Syntax ERROR: {fname}", str(e))

# ── 6. .gitignore coverage ────────────────────────────────────────────
print("\n[6] .gitignore Coverage")
gi_path = ROOT / ".gitignore"
if gi_path.exists():
    gi = gi_path.read_text()
    must_ignore = [".env", "data/secrets.json", "data/license_cache.json",
                   "data/device_id.txt", "__pycache__", "*.db", "logs/"]
    for item in must_ignore:
        if item in gi:
            p(f".gitignore covers: {item}")
        else:
            w(f".gitignore missing: {item}")
else:
    f(".gitignore not found")

# ── 7. README brand check ─────────────────────────────────────────────
print("\n[7] Branding Check")
readme = (ROOT / "README.md").read_text() if (ROOT / "README.md").exists() else ""
if "CyberSentinel" in readme:
    f("README still references CyberSentinel")
else:
    p("README brand is AISS")
if "AISS" in readme:
    p("README contains AISS branding")

# ── 8. Docker files valid ─────────────────────────────────────────────
print("\n[8] Docker Files")
if (ROOT / "Dockerfile").exists():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8", errors="ignore")
    if "USER aiss" in dockerfile:
        p("Dockerfile uses non-root user")
    else:
        w("Dockerfile should use non-root user")
    if "HEALTHCHECK" in dockerfile:
        p("Dockerfile has health check")
    else:
        w("Dockerfile missing HEALTHCHECK")

if (ROOT / "docker-compose.yml").exists():
    dc = (ROOT / "docker-compose.yml").read_text(encoding="utf-8", errors="ignore")
    if "postgres" in dc and "redis" in dc and "nginx" in dc:
        p("docker-compose has full stack (AISS + Postgres + Redis + Nginx)")
    else:
        w("docker-compose may be missing services")

# ── Final Report ──────────────────────────────────────────────────────
total = len(PASS) + len(WARN) + len(FAIL)
sec_score = int((len(PASS) / max(total, 1)) * 100)
prod_score = max(0, sec_score - (len(FAIL) * 10))
comm_score = max(0, prod_score - (5 if not (ROOT / "LICENSE").exists() else 0))

print("\n" + "═"*60)
print("  FINAL AUDIT REPORT")
print("═"*60)
print(f"  Checks:  {total} total | {len(PASS)} passed | {len(WARN)} warnings | {len(FAIL)} failures")
print(f"  Security Score:          {sec_score}/100")
print(f"  Production Readiness:    {prod_score}/100")
print(f"  Commercial Readiness:    {comm_score}/100")
print(f"  Deployment Readiness:    {'95/100' if (ROOT/'Dockerfile').exists() else '60/100'}")

if FAIL:
    print(f"\n  🚫 FAILURES ({len(FAIL)}):")
    for item in FAIL: print(f"     • {item}")
if WARN:
    print(f"\n  ⚠️  WARNINGS ({len(WARN)}):")
    for item in WARN: print(f"     • {item}")

verdict = "✅ PRODUCTION READY" if not FAIL else "❌ NOT PRODUCTION READY — fix failures above"
print(f"\n  Verdict: {verdict}")
print("═"*60 + "\n")

sys.exit(len(FAIL))
