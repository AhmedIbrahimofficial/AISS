#!/usr/bin/env python3
"""
AISS Live Monitor — CMD Dashboard
Shows real-time threats, connected agents, and system metrics.

Usage: python monitor.py   (or: aiss-monitor)
       python monitor.py --url http://localhost:8000 --token YOUR_JWT
"""
import sys, os, asyncio, json, time, platform, argparse
from datetime import datetime

IS_WIN = platform.system() == "Windows"
if IS_WIN:
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(ctypes.windll.kernel32.GetStdHandle(-11), 7)
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
CLEAR  = "\033[2J\033[H"

SEV_COLOR = {
    "critical": RED + BOLD,
    "high":     YELLOW + BOLD,
    "medium":   YELLOW,
    "low":      DIM,
}


def clr(t, *c): return "".join(c) + str(t) + RESET


def _box_line(content: str, width: int = 70) -> str:
    return f"  │ {content:<{width}} │"


def _box_sep(width: int = 70) -> str:
    return f"  ├{'─'*(width+2)}┤"


def _box_top(title: str, width: int = 70) -> str:
    pad = (width - len(title) - 2) // 2
    return f"  ╔{'═'*(width+2)}╗\n  ║ {' '*pad}{clr(title, WHITE, BOLD)}{' '*(width-pad-len(title))} ║"


def _box_bot(width: int = 70) -> str:
    return f"  ╚{'═'*(width+2)}╝"


def _severity_bar(counts: dict) -> str:
    parts = []
    for sev, color in [("critical", RED+BOLD), ("high", YELLOW+BOLD),
                       ("medium", YELLOW), ("low", DIM)]:
        n = counts.get(sev, 0)
        if n:
            parts.append(f"{clr(sev.upper(), color)}: {clr(str(n), BOLD)}")
    return "  ".join(parts) if parts else clr("No active threats", GREEN)


def _bar(val: float, max_val: float = 100, width: int = 20,
         warn: float = 70, crit: float = 90) -> str:
    pct    = min(val / max(max_val, 1), 1.0)
    filled = int(width * pct)
    color  = RED if pct * 100 >= crit else (YELLOW if pct * 100 >= warn else GREEN)
    return f"[{clr('█' * filled, color)}{clr('░' * (width - filled), DIM)}] {clr(f'{val:.1f}%', BOLD)}"


class AissMonitor:
    def __init__(self, base_url: str, token: str = ""):
        self.base_url    = base_url.rstrip("/")
        self.token       = token
        self._threats    = []
        self._agents     = []
        self._health     = {}
        self._lib_status = {}
        self._running    = True
        self._last_update = 0

    async def _fetch(self, path: str) -> dict:
        """Fetch JSON from AISS API."""
        try:
            import httpx
            headers = {}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(f"{self.base_url}{path}", headers=headers)
                if r.status_code == 200:
                    return r.json()
        except Exception:
            pass
        return {}

    async def _refresh(self):
        """Refresh all data from AISS API."""
        import asyncio
        results = await asyncio.gather(
            self._fetch("/api/threats/active"),
            self._fetch("/api/threats/stats"),
            self._fetch("/api/system/health"),
            self._fetch("/api/agents/stats"),
            self._fetch("/api/system/libraries"),
            return_exceptions=True,
        )
        if isinstance(results[0], dict):
            self._threats = results[0].get("threats", [])[:20]
        if isinstance(results[2], dict):
            self._health  = results[2]
        if isinstance(results[3], dict):
            self._agent_stats = results[3]
        else:
            self._agent_stats = {}
        if isinstance(results[4], dict):
            libs = results[4].get("libraries", [])
            self._lib_enabled  = sum(1 for l in libs if l.get("enabled"))
            self._lib_disabled = len(libs) - self._lib_enabled
        else:
            self._lib_enabled = self._lib_disabled = 0
        self._last_update = time.time()

    def _render(self):
        """Render the full dashboard to stdout."""
        h   = self._health
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        W   = 68

        # Severity counts
        sev_counts = {}
        for t in self._threats:
            s = str(t.get("severity", "low")).lower()
            sev_counts[s] = sev_counts.get(s, 0) + 1

        lines = [
            CLEAR,
            _box_top("AISS — AI Intelligent Security System — Live Monitor", W),
            _box_line(f"  {clr(now, DIM):<{W-1}}", W),
            _box_line(f"  {clr('Server: ' + self.base_url, DIM):<{W-1}}", W),
            _box_sep(W),

            # System metrics
            _box_line(f"  {clr('SYSTEM METRICS', CYAN, BOLD)}", W),
            _box_line(f"  CPU    {_bar(h.get('cpu_percent', 0))}", W),
            _box_line(f"  RAM    {_bar(h.get('ram_percent', 0))}  "
                      f"{clr(str(h.get('ram_used_mb',0))+'MB', DIM)}", W),
            _box_line(f"  Disk   {_bar(h.get('disk_percent', 0))}  "
                      f"Procs: {clr(str(h.get('process_count',0)), BOLD)}", W),
            _box_line(f"  Uptime {clr(str(h.get('uptime_secs',0))+'s', BOLD)}  "
                      f"Libs: {clr(str(self._lib_enabled), GREEN, BOLD)} active / "
                      f"{clr(str(self._lib_disabled), DIM)} disabled", W),
            _box_sep(W),

            # Agents
            _box_line(f"  {clr('CONNECTED AGENTS', CYAN, BOLD)}", W),
        ]

        ag = getattr(self, "_agent_stats", {})
        by_net = ag.get("by_network", {})
        lines += [
            _box_line(f"  Total: {clr(str(ag.get('total',0)), BOLD)}  "
                      f"Online: {clr(str(ag.get('connected',0)), GREEN, BOLD)}  "
                      f"Idle: {clr(str(ag.get('disconnected',0)), DIM)}", W),
            _box_line(f"  LAN: {clr(str(by_net.get('lan',0)), CYAN)}  "
                      f"WAN: {clr(str(by_net.get('wan',0)), YELLOW)}  "
                      f"VPN: {clr(str(by_net.get('vpn',0)), BLUE if False else CYAN)}  "
                      f"MAN: {clr(str(by_net.get('man',0)), DIM)}  "
                      f"Threats forwarded: {clr(str(ag.get('total_threats',0)), RED)}", W),
            _box_sep(W),

            # Active threats
            _box_line(f"  {clr('ACTIVE THREATS', CYAN, BOLD)}  "
                      f"{_severity_bar(sev_counts)}", W),
        ]

        if not self._threats:
            lines.append(_box_line(f"  {clr('No active threats detected', GREEN, BOLD)}", W))
        else:
            for t in self._threats[:10]:
                sev   = str(t.get("severity", "low")).lower()
                color = SEV_COLOR.get(sev, "")
                tid   = str(t.get("id",""))[:8]
                ttype = str(t.get("type",""))[:22]
                src   = str(t.get("source",""))[:20]
                desc  = str(t.get("description",""))[:25]
                ts    = str(t.get("detected_at",""))[:16]
                lines.append(_box_line(
                    f"  {clr(sev[:4].upper(), color):<12} "
                    f"{clr(ttype, WHITE):<24} "
                    f"{clr(src, DIM):<22} "
                    f"{clr(ts, DIM)}", W))

        lines += [
            _box_sep(W),
            _box_line(
                f"  {clr('Press Ctrl+C to exit', DIM)}  "
                f"  {clr('Refreshing every 3s', DIM)}"
                f"  Updated: {clr(datetime.utcnow().strftime('%H:%M:%S'), DIM)}", W),
            _box_bot(W),
            "",
        ]
        print("\n".join(lines), flush=True)

    async def run(self, refresh_interval: float = 3.0):
        """Main loop — refresh and render."""
        print(clr("Connecting to AISS...", CYAN))
        while self._running:
            try:
                await self._refresh()
                self._render()
                await asyncio.sleep(refresh_interval)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(clr(f"Error: {e}", YELLOW))
                await asyncio.sleep(refresh_interval)


def main():
    parser = argparse.ArgumentParser(description="AISS Live Monitor")
    parser.add_argument("--url",   default="http://localhost:8000",
                        help="AISS backend URL (default: http://localhost:8000)")
    parser.add_argument("--token", default="",
                        help="JWT token for authenticated endpoints")
    parser.add_argument("--interval", type=float, default=3.0,
                        help="Refresh interval in seconds (default: 3)")
    args = parser.parse_args()

    mon = AissMonitor(args.url, args.token)
    try:
        asyncio.run(mon.run(args.interval))
    except KeyboardInterrupt:
        print(f"\n{clr('Monitor stopped.', YELLOW)}\n")


if __name__ == "__main__":
    main()
