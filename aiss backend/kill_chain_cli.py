"""
CyberSentinel - Cyber Kill Chain CLI Visualizer
Run: python kill_chain_cli.py
Fetches live threats from backend and shows attack stages in terminal.
"""

import os
import sys
import time
import requests
from datetime import datetime

# ── Colors ────────────────────────────────────────────────────────────
def red(t):     return f"\033[91m{t}\033[0m"
def green(t):   return f"\033[92m{t}\033[0m"
def yellow(t):  return f"\033[93m{t}\033[0m"
def cyan(t):    return f"\033[96m{t}\033[0m"
def magenta(t): return f"\033[95m{t}\033[0m"
def bold(t):    return f"\033[1m{t}\033[0m"
def gray(t):    return f"\033[90m{t}\033[0m"
def white(t):   return f"\033[97m{t}\033[0m"

SEVERITY_COLOR = {
    "critical": red,
    "high":     yellow,
    "medium":   magenta,
    "low":      green,
}

# ── Stage definitions ─────────────────────────────────────────────────
STAGES = [
    {"label": "Reconnaissance",     "icon": "🔍", "id": "reconnaissance"},
    {"label": "Initial Access",     "icon": "🚪", "id": "initial_access"},
    {"label": "Execution",          "icon": "⚡", "id": "execution"},
    {"label": "Privilege Escalation","icon": "🔓", "id": "privilege_escalation"},
    {"label": "Defense Evasion",    "icon": "🥷", "id": "defense_evasion"},
    {"label": "Lateral Movement",   "icon": "↔️", "id": "lateral_movement"},
    {"label": "Command & Control",  "icon": "📡", "id": "command_control"},
    {"label": "Exfiltration",       "icon": "💀", "id": "exfiltration"},
]

API = "http://localhost:8000"


def fetch_kill_chain():
    try:
        r = requests.get(f"{API}/api/kill-chain", timeout=5)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(red(f"  Cannot connect to backend: {e}"))
    return None


def draw_progress_bar(percent: int, width: int = 40) -> str:
    filled = int(width * percent / 100)
    bar    = "█" * filled + "░" * (width - filled)
    color  = red if percent > 60 else yellow if percent > 30 else green
    return color(bar) + f" {percent}%"


def print_kill_chain(data: dict):
    os.system("cls" if os.name == "nt" else "clear")

    # ── Header ────────────────────────────────────────────────────────
    print(cyan("  " + "═" * 65))
    print(cyan("  ") + bold("  🛡️  CyberSentinel — Cyber Kill Chain Analysis"))
    print(cyan("  ") + gray(f"  Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    print(cyan("  " + "═" * 65))
    print()

    # ── Attack progress bar ───────────────────────────────────────────
    progress   = data.get("attack_progress", 0)
    compromised = data.get("stages_compromised", 0)
    total_t    = data.get("total_threats", 0)

    print(f"  {bold('Attack Progress')}  [{draw_progress_bar(progress)}]")
    print()
    print(f"  Threats Detected : {red(str(total_t)) if total_t else green('0')}")
    print(f"  Stages Hit       : {red(str(compromised)) if compromised else green('0')} / {len(STAGES)}")
    print()
    print(cyan("  " + "─" * 65))
    print()

    # ── Stages ────────────────────────────────────────────────────────
    stages = data.get("stages", [])

    for i, stage in enumerate(stages):
        icon        = stage.get("icon", "?")
        label       = stage.get("label", "")
        desc        = stage.get("description", "")
        total       = stage.get("total", 0)
        compromised_stage = stage.get("compromised", False)
        threats     = stage.get("threats", [])

        # Stage header
        status_str = red("● COMPROMISED") if compromised_stage else green("○ CLEAR")
        print(f"  {icon}  {bold(white(label))}  {status_str}")
        print(f"     {gray(desc)}")

        if threats:
            print()
            for t in threats[:3]:   # show max 3 per stage
                sev      = t.get("severity", "low")
                col      = SEVERITY_COLOR.get(sev, white)
                t_type   = t.get("type", "")
                t_desc   = t.get("description", "")[:60]
                t_status = t.get("status", "")
                print(f"     {col('▸')} {col(t_type)}"
                      f"  [{col(sev.upper())}]"
                      f"  {gray(t_status)}")
                print(f"       {gray(t_desc + ('...' if len(t.get('description','')) > 60 else ''))}")
            if len(threats) > 3:
                print(f"     {gray(f'... and {len(threats)-3} more threats')}")

        print()

        # Arrow connector between stages (not after last)
        if i < len(stages) - 1:
            if stages[i + 1].get("compromised"):
                print(f"        {red('▼ Attack progressed')}")
            else:
                print(f"        {gray('▼')}")
            print()

    print(cyan("  " + "═" * 65))
    print(f"  {gray('Press Ctrl+C to exit  |  Auto-refresh every 10s')}")
    print(cyan("  " + "═" * 65))


def run():
    print(cyan("\n  Loading Kill Chain data...\n"))

    try:
        while True:
            data = fetch_kill_chain()
            if data:
                print_kill_chain(data)
            else:
                print(yellow("\n  ⚠  Could not fetch data. Retrying in 10s...\n"))
                print(gray("  Make sure backend is running: python main.py"))
            time.sleep(10)

    except KeyboardInterrupt:
        print(yellow("\n\n  Kill Chain monitor stopped.\n"))
        sys.exit(0)


if __name__ == "__main__":
    run()
