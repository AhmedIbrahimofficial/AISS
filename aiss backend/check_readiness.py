"""AISS system readiness check — run with: python check_readiness.py"""
from dotenv import load_dotenv
load_dotenv()

import sys, os, inspect
sys.path.insert(0, ".")

checks = []

# 1. OpenRouter
key = os.environ.get("OPENROUTER_API_KEY", "")
checks.append(("OPENROUTER_API_KEY",     bool(key),        "AI active" if key else "AI DISABLED"))

# 2. Secret key
sk = os.environ.get("SECRET_KEY", "")
checks.append(("SECRET_KEY",             len(sk) >= 64,    f"{len(sk)} chars"))

# 3. Internal token
ist = os.environ.get("INTERNAL_SERVICE_TOKEN", "")
checks.append(("INTERNAL_SERVICE_TOKEN", bool(ist),        "set" if ist else "EMPTY"))

# 4. Evidence key
ek = os.environ.get("EVIDENCE_ENCRYPTION_KEY", "")
checks.append(("EVIDENCE_ENCRYPTION_KEY",bool(ek),         "set" if ek else "EMPTY"))

# 5. Database
db = os.environ.get("DATABASE_URL", "")
checks.append(("DATABASE_URL",           bool(db),         db[:50]))

# 6. Frontend URL
fu = os.environ.get("FRONTEND_URL", "")
checks.append(("FRONTEND_URL",           bool(fu),         fu))

# 7. Google OAuth (optional)
gid = os.environ.get("GOOGLE_OAUTH_CLIENT_ID", "")
checks.append(("GOOGLE_OAUTH",           bool(gid),        "configured" if gid else "optional - not configured"))

# 8. Fernet key validity
try:
    from cryptography.fernet import Fernet
    Fernet(ek.encode() if isinstance(ek, str) else ek)
    checks.append(("EVIDENCE_KEY_VALID",  True,  "valid"))
except Exception as e:
    checks.append(("EVIDENCE_KEY_VALID",  False, str(e)))

# 9. Agent models
try:
    from agents.models import AgentTask
    checks.append(("AGENT_MODELS",        True,  "importable"))
except Exception as e:
    checks.append(("AGENT_MODELS",        False, str(e)))

# 10. SSO route
try:
    from api.routes.sso import router as sso_r
    checks.append(("SSO_ROUTE",           True,  f"{len(sso_r.routes)} endpoints"))
except Exception as e:
    checks.append(("SSO_ROUTE",           False, str(e)))

# 11. WS broadcast signature fix
from core.websocket_manager import WebSocketManager
sig = inspect.signature(WebSocketManager.broadcast)
has_uid = "user_id" in sig.parameters
checks.append(("WS_BROADCAST_FIX",       has_uid, "user_id param present" if has_uid else "BUG STILL PRESENT"))

# 12. LLM router
from modules.llm_router import llm_router
avail = llm_router.is_available()
model = llm_router._models[0] if llm_router._models else "none"
checks.append(("LLM_ROUTER",             avail, model))

# 13. OAuth route secure exchange
try:
    from api.routes.auth import _exchange_codes, oauth_exchange
    checks.append(("OAUTH_SECURE_EXCHANGE", True, "one-time exchange endpoint exists"))
except Exception as e:
    checks.append(("OAUTH_SECURE_EXCHANGE", False, str(e)))

# 14. main.py syntax
import ast, pathlib
try:
    src = pathlib.Path("main.py").read_text(encoding="utf-8")
    ast.parse(src)
    checks.append(("MAIN_PY_SYNTAX",      True,  "clean"))
except SyntaxError as e:
    checks.append(("MAIN_PY_SYNTAX",      False, str(e)))

print()
print("=" * 65)
print("  AISS System Readiness Check")
print("=" * 65)
print(f"  {'CHECK':<30} {'STATUS':<8} DETAIL")
print("-" * 65)
warnings = []
for name, ok, detail in checks:
    icon = "v" if ok else "!"
    status = "OK" if ok else "WARN"
    print(f"  [{icon}] {name:<30} {status:<8} {detail}")
    if not ok:
        warnings.append(name)

total = len(checks)
passed = sum(1 for _, ok, _ in checks if ok)
print("-" * 65)
print(f"  Result: {passed}/{total} passed", "- READY" if not warnings else f"- {len(warnings)} warnings")
print("=" * 65)
if warnings:
    print("\n  Items to address:")
    for w in warnings:
        print(f"    - {w}")
