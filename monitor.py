"""
AISS Live Monitor — Real-time terminal dashboard
Run: python monitor.py
"""

from rich.console import Console
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich.live import Live
from rich.text import Text
from rich.columns import Columns
import psutil, os, time, datetime, requests
from pathlib import Path

console = Console()

# ── Suspicious process names ──────────────────────────────────────────
SUSPICIOUS_NAMES = {"xmrig", "mimikatz", "netcat", "nc.exe", "psexec",
                    "meterpreter", "cobalt", "njrat", "darkcomet"}
SUSPICIOUS_PORTS = {4444, 1337, 31337, 9999, 6666, 5555}
SAFE_PORTS       = {80, 443, 8000, 8080, 3000, 3306, 5432}

# ── Cached threat data ────────────────────────────────────────────────
_threat_cache:      list  = []
_threat_last_fetch: float = 0.0


# ══════════════════════════════════════════════════════════════════════
# TOP BAR
# ══════════════════════════════════════════════════════════════════════

def make_top_bar() -> Panel:
    now    = datetime.datetime.now().strftime("%H:%M:%S")
    cpu    = psutil.cpu_percent(interval=None)
    ram    = psutil.virtual_memory().percent
    boot   = datetime.datetime.fromtimestamp(psutil.boot_time())
    up     = datetime.datetime.now() - boot
    hours, remainder = divmod(int(up.total_seconds()), 3600)
    mins  = remainder // 60

    cpu_color = "red" if cpu > 80 else "yellow" if cpu > 50 else "green"
    ram_color = "red" if ram > 90 else "yellow" if ram > 70 else "green"

    line = Text()
    line.append("  🛡️  AISS LIVE MONITOR  ", style="bold cyan")
    line.append(f"  {now}  ", style="bold white")
    line.append(f"CPU:{cpu:.0f}%  ", style=f"bold {cpu_color}")
    line.append(f"RAM:{ram:.0f}%  ", style=f"bold {ram_color}")
    line.append(f"Up:{hours}h{mins}m  ", style="dim cyan")
    line.append("AI Integrated Security System", style="dim white")

    return Panel(line, border_style="cyan", height=3)


# ══════════════════════════════════════════════════════════════════════
# PANEL 1 & 2 — DRIVE FILES
# ══════════════════════════════════════════════════════════════════════

def make_drive_panel(drive: str) -> Panel:
    title = f"DRIVE {drive.upper()} — Files"
    drive_path = f"{drive}:\\" if IS_WINDOWS else f"/{drive}"

    if not os.path.exists(drive_path):
        return Panel(
            Text(f"No {drive.upper()}: Drive found", style="dim white"),
            title=f"[bold cyan]{title}[/bold cyan]",
            border_style="cyan",
        )

    try:
        usage = psutil.disk_usage(drive_path)
        pct   = usage.percent
        used_gb  = usage.used  / 1024**3
        total_gb = usage.total / 1024**3
        free_gb  = usage.free  / 1024**3

        bar_color = "green" if pct < 80 else "yellow" if pct < 90 else "red"
        filled = int(pct / 5)
        bar    = "█" * filled + "░" * (20 - filled)

        t = Table(show_header=True, header_style="bold cyan",
                  show_edge=False, pad_edge=False, box=None)
        t.add_column("File", style="white", no_wrap=True, max_width=28)
        t.add_column("Size", style="dim white", width=8)
        t.add_column("Modified", style="dim white", width=12)

        # Recently modified files
        files = []
        scan_root = os.path.join(drive_path, "Users")
        if not os.path.exists(scan_root):
            scan_root = drive_path
        depth = 0
        for root, dirs, fnames in os.walk(scan_root):
            depth += 1
            if depth > 2:
                break
            dirs[:] = [d for d in dirs if d.lower() not in {
                "appdata", "windows", "program files",
                "program files (x86)", "programdata", "$recycle.bin"
            }]
            for f in fnames:
                try:
                    fp   = os.path.join(root, f)
                    mtime = os.stat(fp).st_mtime
                    files.append((mtime, fp, f))
                except OSError:
                    pass

        files.sort(reverse=True)
        for mtime, fp, fname in files[:10]:
            try:
                size  = os.path.getsize(fp)
                size_str = (f"{size/1024:.0f}KB" if size < 1024**2
                            else f"{size/1024**2:.1f}MB")
                mod = datetime.datetime.fromtimestamp(mtime).strftime("%m/%d %H:%M")
                t.add_row(fname[:28], size_str, mod)
            except OSError:
                pass

        header = Text()
        header.append(f"[{bar}] ", style=bar_color)
        header.append(f"{pct:.0f}% used  ", style=bar_color)
        header.append(f"{used_gb:.1f}/{total_gb:.0f}GB  Free:{free_gb:.1f}GB",
                       style="dim white")
        header.append("\n")

        from rich.console import Group
        content = Group(header, t)

        return Panel(content,
                     title=f"[bold cyan]{title}[/bold cyan]",
                     border_style="cyan")

    except Exception as e:
        return Panel(Text(f"Error: {e}", style="red"),
                     title=f"[bold cyan]{title}[/bold cyan]",
                     border_style="red")


# ══════════════════════════════════════════════════════════════════════
# PANEL 3 — EXTERNAL DEVICES
# ══════════════════════════════════════════════════════════════════════

def make_external_panel() -> Panel:
    t = Table(show_header=True, header_style="bold cyan",
              show_edge=False, pad_edge=False, box=None)
    t.add_column("Drive", width=6)
    t.add_column("Type",  width=8)
    t.add_column("FS",    width=6)
    t.add_column("Total", width=8)
    t.add_column("Free",  width=8)
    t.add_column("Status", width=14)

    found = False
    for part in psutil.disk_partitions(all=False):
        mp = part.mountpoint.upper()
        if mp in ("C:\\", "D:\\", "/"):
            continue
        found = True
        opts  = (part.opts or "").lower()
        label = "[yellow][USB][/yellow]" if "removable" in opts else "[dim]HDD[/dim]"
        try:
            usage  = psutil.disk_usage(part.mountpoint)
            total  = f"{usage.total/1024**3:.1f}G"
            free   = f"{usage.free/1024**3:.1f}G"
        except Exception:
            total = free = "N/A"

        # Check if this drive was recently added (within last 30s)
        status_text = Text("Connected", style="green")
        try:
            # If drive just appeared — show scanning
            if not hasattr(make_external_panel, "_seen"):
                make_external_panel._seen = {}
            first_seen = make_external_panel._seen.get(mp)
            now_ts = time.time()
            if first_seen is None:
                make_external_panel._seen[mp] = now_ts
                status_text = Text("🔍 Scanning...", style="yellow")
            elif now_ts - first_seen < 15:
                status_text = Text("🔍 Scanning...", style="yellow")
        except Exception:
            pass

        t.add_row(part.mountpoint, label, part.fstype or "?",
                  total, free, status_text)

    if not found:
        # Clear seen cache when no drives
        if hasattr(make_external_panel, "_seen"):
            make_external_panel._seen = {}
        return Panel(
            Text("  No external devices connected", style="dim white"),
            title="[bold cyan]EXTERNAL DEVICES[/bold cyan]",
            border_style="cyan",
        )
    return Panel(t, title="[bold cyan]EXTERNAL DEVICES[/bold cyan]",
                 border_style="cyan")


# ══════════════════════════════════════════════════════════════════════
# PANEL 4 — NETWORK CONNECTIONS
# ══════════════════════════════════════════════════════════════════════

def make_network_panel() -> Panel:
    t = Table(show_header=True, header_style="bold cyan",
              show_edge=False, pad_edge=False, box=None)
    t.add_column("PID",     width=6)
    t.add_column("Process", width=16, no_wrap=True)
    t.add_column("LPort",   width=7)
    t.add_column("Remote IP", width=16)
    t.add_column("RPort",   width=7)

    count = 0
    try:
        for c in psutil.net_connections(kind="tcp"):
            if c.status != "ESTABLISHED" or not c.raddr:
                continue
            rip   = c.raddr.ip
            rport = c.raddr.port
            lport = c.laddr.port if c.laddr else 0
            pid   = c.pid or 0

            proc_name = "unknown"
            try:
                if pid:
                    proc_name = psutil.Process(pid).name()[:16]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            if rport in SUSPICIOUS_PORTS:
                ip_style = "bold red"
            elif rport in SAFE_PORTS:
                ip_style = "green"
            else:
                ip_style = "white"

            t.add_row(
                str(pid),
                proc_name,
                str(lport),
                Text(rip, style=ip_style),
                str(rport),
            )
            count += 1
            if count >= 15:
                break
    except Exception:
        pass

    return Panel(t,
                 title="[bold cyan]ACTIVE NETWORK CONNECTIONS[/bold cyan]",
                 border_style="cyan")


# ══════════════════════════════════════════════════════════════════════
# PANEL 5 — WEBSITES / DOWNLOADS
# ══════════════════════════════════════════════════════════════════════

def make_websites_panel() -> Panel:
    from rich.console import Group

    # Web connections table
    wt = Table(show_header=True, header_style="bold cyan",
               show_edge=False, pad_edge=False, box=None)
    wt.add_column("Process", width=16, no_wrap=True)
    wt.add_column("Remote IP", width=16)
    wt.add_column("Port", width=6)

    seen = set()
    try:
        for c in psutil.net_connections(kind="tcp"):
            if not c.raddr:
                continue
            if c.raddr.port not in (80, 443, 8080, 8443):
                continue
            key = (c.pid, c.raddr.ip, c.raddr.port)
            if key in seen:
                continue
            seen.add(key)
            proc_name = "unknown"
            try:
                if c.pid:
                    proc_name = psutil.Process(c.pid).name()[:16]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            port_str  = "HTTPS" if c.raddr.port in (443, 8443) else "HTTP"
            wt.add_row(proc_name, c.raddr.ip, port_str)
    except Exception:
        pass

    # Downloads
    dl_text = Text("\n  Recent Downloads:\n", style="bold cyan")
    now = time.time()
    downloads_dirs = []
    if IS_WINDOWS:
        users_dir = "C:\\Users"
        if os.path.exists(users_dir):
            for user in os.listdir(users_dir):
                dl = os.path.join(users_dir, user, "Downloads")
                if os.path.exists(dl):
                    downloads_dirs.append(dl)
    else:
        dl = os.path.expanduser("~/Downloads")
        if os.path.exists(dl):
            downloads_dirs.append(dl)

    dl_files = []
    for dl_dir in downloads_dirs:
        try:
            for f in os.scandir(dl_dir):
                if f.is_file():
                    try:
                        st = f.stat()
                        dl_files.append((st.st_mtime, f.path, f.name, st.st_size))
                    except OSError:
                        pass
        except Exception:
            pass

    dl_files.sort(reverse=True)
    for mtime, fp, fname, size in dl_files[:5]:
        size_str = f"{size/1024:.0f}KB" if size < 1024**2 else f"{size/1024**2:.1f}MB"
        is_new   = (now - mtime) < 60
        style    = "yellow" if is_new else "dim white"
        label    = " [DOWNLOADING]" if is_new else ""
        dl_text.append(f"  {fname[:24]:<24} {size_str:>8}{label}\n", style=style)

    content = Group(wt, dl_text)
    return Panel(content,
                 title="[bold cyan]WEBSITES / DOWNLOADS[/bold cyan]",
                 border_style="cyan")


# ══════════════════════════════════════════════════════════════════════
# PANEL 6 — RUNNING PROCESSES
# ══════════════════════════════════════════════════════════════════════

def make_processes_panel() -> Panel:
    t = Table(show_header=True, header_style="bold cyan",
              show_edge=False, pad_edge=False, box=None)
    t.add_column("PID",  width=6)
    t.add_column("Name", width=20, no_wrap=True)
    t.add_column("CPU%", width=6)
    t.add_column("RAM%", width=6)

    procs = []
    try:
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                procs.append(p.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception:
        pass

    procs.sort(key=lambda x: x.get('cpu_percent') or 0, reverse=True)
    for info in procs[:12]:
        cpu  = info.get('cpu_percent') or 0.0
        ram  = info.get('memory_percent') or 0.0
        name = info.get('name') or 'unknown'
        pid  = info.get('pid') or 0

        if cpu > 50:
            style = "bold red"
        elif cpu > 20:
            style = "yellow"
        else:
            style = "white"

        name_lower = name.lower()
        susp_flag  = " [bold red][SUSPICIOUS][/bold red]" \
                     if any(s in name_lower for s in SUSPICIOUS_NAMES) else ""

        t.add_row(
            str(pid),
            Text(f"{name}{susp_flag}", style=style),
            Text(f"{cpu:.1f}", style=style),
            f"{ram:.1f}",
        )

    return Panel(t,
                 title="[bold cyan]RUNNING PROCESSES (Top by CPU)[/bold cyan]",
                 border_style="cyan")


# ══════════════════════════════════════════════════════════════════════
# PANEL 7 — AISS THREAT ALERTS (numbered resolve + open location)
# ══════════════════════════════════════════════════════════════════════

_resolve_status: dict = {}   # threat_id → "resolving" | "resolved"


def _open_location(source: str) -> None:
    """Open file explorer at threat source location."""
    try:
        if os.path.exists(source):
            folder = os.path.dirname(source) if os.path.isfile(source) else source
            if IS_WINDOWS:
                os.startfile(folder)
            else:
                os.system(f'xdg-open "{folder}"')
        elif source.startswith("PID:"):
            if IS_WINDOWS:
                os.system("start taskmgr")
    except Exception:
        pass


def _resolve_threat(threat_id: str) -> bool:
    """Call AISS API to resolve a threat."""
    try:
        resp = requests.post(
            f"http://localhost:8000/api/threats/{threat_id}/resolve",
            params={"note": "Resolved via AISS Monitor"},
            timeout=3,
        )
        return resp.status_code == 200
    except Exception:
        return False


def handle_input(cmd: str) -> None:
    """
    Handle user input commands:
      r1  → resolve threat #1
      o1  → open location of threat #1
    """
    cmd = cmd.strip().lower()
    if not cmd or len(cmd) < 2:
        return
    action = cmd[0]
    try:
        num = int(cmd[1:]) - 1
    except ValueError:
        return

    if num < 0 or num >= len(_threat_cache):
        return

    threat = _threat_cache[num]
    tid    = threat.get("id", "")
    source = threat.get("source", "")

    if action == "r":
        _resolve_status[tid] = "resolving"
        ok = _resolve_threat(tid)
        _resolve_status[tid] = "resolved" if ok else "error"
    elif action == "o":
        _open_location(source)


def make_threats_panel() -> Panel:
    global _threat_cache, _threat_last_fetch

    now = time.time()
    if now - _threat_last_fetch >= 5:
        try:
            resp = requests.get(
                "http://localhost:8000/api/threats/active",
                timeout=2
            )
            if resp.status_code == 200:
                _threat_cache = resp.json().get("threats", [])
        except Exception:
            pass
        _threat_last_fetch = now

    if not _threat_cache and (now - _threat_last_fetch < 6):
        return Panel(
            Text("  AISS Backend Offline", style="bold red"),
            title="[bold cyan]AISS THREAT ALERTS[/bold cyan]",
            border_style="red",
        )

    SEV_STYLE = {
        "critical": "bold red",
        "high":     "yellow",
        "medium":   "cyan",
        "low":      "green",
    }

    t = Table(show_header=True, header_style="bold cyan",
              show_edge=False, pad_edge=False, box=None)
    t.add_column("#",        width=3)
    t.add_column("Time",     width=8)
    t.add_column("Type",     width=14, no_wrap=True)
    t.add_column("Sev",      width=9)
    t.add_column("Source",   width=13, no_wrap=True)
    t.add_column("Status",   width=8)
    t.add_column("Action",   width=16)

    for idx, threat in enumerate(_threat_cache[:8], start=1):
        sev      = (threat.get("severity") or "low").lower()
        sev_style= SEV_STYLE.get(sev, "white")
        detected = threat.get("detected_at") or ""
        tid      = threat.get("id", "")
        source   = threat.get("source") or ""
        status   = threat.get("status") or "active"

        try:
            tstr = datetime.datetime.fromisoformat(detected).strftime("%H:%M:%S")
        except Exception:
            tstr = detected[:8]

        # Source display
        src_disp = ("📁 " + source[-10:]) if os.path.exists(source) else source[:13]

        # Action display
        rs = _resolve_status.get(tid)
        if rs == "resolved":
            action = Text("✓ Resolved", style="green")
        elif rs == "resolving":
            action = Text("⟳ Working...", style="yellow")
        elif rs == "error":
            action = Text("✗ Failed", style="red")
        else:
            action = Text(f"r{idx}=Resolve o{idx}=📁", style="bold cyan")

        t.add_row(
            Text(str(idx), style="bold white"),
            tstr,
            (threat.get("type") or "")[:14],
            Text(sev.upper(), style=sev_style),
            src_disp,
            Text(status[:8], style="yellow" if status == "active" else "dim"),
            action,
        )

    if not _threat_cache:
        t.add_row("—", "—", "No active threats", "—", "—", "—", "—")

    # Footer hint
    hint = Text("\n  ", style="")
    hint.append("r", style="bold cyan")
    hint.append("<n>=Resolve  ", style="dim white")
    hint.append("o", style="bold cyan")
    hint.append("<n>=Open Location  ", style="dim white")
    hint.append("e.g. r1  o2", style="dim white")

    from rich.console import Group
    return Panel(Group(t, hint),
                 title="[bold cyan]AISS THREAT ALERTS[/bold cyan]",
                 border_style="cyan")


# ══════════════════════════════════════════════════════════════════════
# LAYOUT BUILDER
# ══════════════════════════════════════════════════════════════════════

IS_WINDOWS = os.name == "nt"


def build_layout() -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="top",  size=3),
        Layout(name="row1", size=12),
        Layout(name="row2", size=12),
        Layout(name="row3", size=14),
    )
    layout["row1"].split_row(
        Layout(name="drive_c", ratio=2),
        Layout(name="drive_d", ratio=2),
        Layout(name="external", ratio=1),
    )
    layout["row2"].split_row(
        Layout(name="network", ratio=3),
        Layout(name="websites", ratio=2),
    )
    layout["row3"].split_row(
        Layout(name="processes", ratio=2),
        Layout(name="threats", ratio=3),
    )
    return layout


def refresh_layout(layout: Layout) -> None:
    layout["top"].update(make_top_bar())
    layout["drive_c"].update(make_drive_panel("C"))
    layout["drive_d"].update(make_drive_panel("D"))
    layout["external"].update(make_external_panel())
    layout["network"].update(make_network_panel())
    layout["websites"].update(make_websites_panel())
    layout["processes"].update(make_processes_panel())
    layout["threats"].update(make_threats_panel())


# ══════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    try:
        import rich
    except ImportError:
        print("Installing required packages...")
        os.system("pip install rich psutil -q")
        import rich

    print("Starting AISS Live Monitor...")
    print("Commands: r<n>=Resolve threat  o<n>=Open location  (e.g. r1, o2)")
    time.sleep(0.5)

    layout = build_layout()

    import threading

    def input_loop():
        while True:
            try:
                cmd = input()
                handle_input(cmd)
            except Exception:
                break

    t = threading.Thread(target=input_loop, daemon=True)
    t.start()

    try:
        with Live(layout, refresh_per_second=1, screen=False):
            while True:
                refresh_layout(layout)
                time.sleep(1)
    except KeyboardInterrupt:
        print("\nMonitor stopped.")
