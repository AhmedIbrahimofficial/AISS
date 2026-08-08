#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# AISS — AI Intelligent Security System
# Single-command launcher.  Just type:  aiss  (or ./aiss.sh)
#
# Flags:
#   aiss                 Start normally (check & install updates, then launch)
#   aiss --wizard        Re-run configuration wizard
#   aiss --reinstall     Force reinstall all packages
#   aiss --install-only  Install/update without starting the server
#   aiss --no-wizard     Skip configuration questions
# ═══════════════════════════════════════════════════════════════════

export PYTHONIOENCODING=utf-8
AISS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Find python — prefer venv
if [ -f "$AISS_DIR/.venv/bin/python" ]; then
    PYTHON="$AISS_DIR/.venv/bin/python"
elif [ -f "$AISS_DIR/venv/bin/python" ]; then
    PYTHON="$AISS_DIR/venv/bin/python"
elif command -v python3 &>/dev/null; then
    PYTHON="python3"
elif command -v python &>/dev/null; then
    PYTHON="python"
else
    echo ""
    echo "  [ERROR] Python 3.11+ not found."
    echo "  Install from https://python.org/downloads"
    echo ""
    exit 1
fi

# Verify version
PY_VER=$("$PYTHON" -c "import sys; print(sys.version_info.major*10+sys.version_info.minor)" 2>/dev/null)
if [ -n "$PY_VER" ] && [ "$PY_VER" -lt 311 ]; then
    echo ""
    echo "  [ERROR] Python 3.11+ required. Found: $($PYTHON --version)"
    echo "  Download from https://python.org/downloads"
    echo ""
    exit 1
fi

cd "$AISS_DIR"
exec "$PYTHON" "$AISS_DIR/aiss.py" "$@"
