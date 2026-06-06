"""
CyberSentinel - Standalone CLI Monitor
Runs completely offline - no server needed
Just run: python monitor.py
"""

import os
import sys
import time
import json
import psutil
import socket
from datetime import datetime, timedelta
from pathlib import Path

DOWNLOAD_PATH  = str(Path.home() / "Downloads")
SUSPICIOUS_EXT = {".bat", ".cmd", ".ps1", ".vbs", ".scr", ".pif"}

WHITELIST_PROCESSES = {
    "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe",
    "brave.exe", "iexplore.exe", "explorer.exe", "svchost.exe", "dwm.exe",
    "lsass.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
    "dllhost.exe", "conhost.exe", "taskhostw.exe", "sihost.exe", "ctfmon.exe",
    "searchhost.exe", "spoolsv.exe", "audiodg.exe", "fontdrvhost.exe",
    "runtimebroker.exe", "smartscreen.exe", "backgroundtaskhost.exe",
    "unsecapp.exe", "wmiprvse.exe", "searchindexer.exe", "dashost.exe",
    "lockapp.exe", "shellexperiencehost.exe", "startmenuexperiencehost.exe",
    "textinputhost.exe", "systemsettings.exe", "securityhealthsystray.exe",
    "applicationframehost.exe", "msiexec.exe", "trustedinstaller.exe",
    "wuauclt.exe", "filecoauth.exe", "onedrive.exe",
    "python.exe", "pythonw.exe", "code.exe", "git.exe",
    "node.exe", "npm.exe", "java.exe", "notepad.exe",
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "teams.exe", "discord.exe", "zoom.exe", "slack.exe",
    "spotify.exe", "vlc.exe", "7zfm.exe", "winrar.exe",
    "msmpeng.exe", "nissrv.exe", "taskmgr.exe", "cmd.exe",
    "powershell.exe", "gamebarpresencewriter.exe", "msedgewebview2.exe",
}

SUSPICIOUS_BEHAVIOR = {
    "keylogger", "mimikatz", "metasploit", "netcat",
    "nmap", "pwdump", "fgdump", "procdump", "cobaltstrike",
    "meterpreter", "payload", "exploit", "backdoor",
    "rootkit", "ransomware", "cryptominer",
}

BEHAVIOR_FILE = "behavior_data.json"


def load_behavior():
    try:
        with open(BEHAVIOR_FILE, "r") as f:
            return json.load(f)
    except:
        return {"normal_processes": {}, "normal_connections": {}}


def save_behavior(data):
    try:
        with open(BEHAVIOR_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except:
        pass


def is_anomaly(name, behavior_data):
    name   = name.lower()
    normal = behavior_data.get("normal_processes", {})
    if name in normal:
        normal[name]["count"] += 1
        return False
    else:
        for bad in SUSPICIOUS_BEHAVIOR:
            if bad in name:
                return True
        normal[name] = {"count": 1}
        return False


def now():
    return datetime.now().strftime("%H:%M:%S")

def green(t):   return f"\033[92m{t}\033[0m"
def red(t):     return f"\033[91m{t}\033[0m"
def yellow(t):  return f"\033[93m{t}\033[0m"
def cyan(t):    return f"\033[96m{t}\033[0m"
def bold(t):    return f"\033[1m{t}\033[0m"
def gray(t):    return f"\033[90m{t}\033[0m"


def log(icon, msg, color_fn=None):
    line = f"  [{now()}] {icon}  {msg}"
    print(color_fn(line) if color_fn else line, flush=True)


def print_header():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(cyan("  " + "═" * 65))
    print(cyan("  ") + bold("      🛡️  CyberSentinel — Offline CLI Monitor"))
    print(cyan("  ") + gray(f"      Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    print(cyan("  " + "═" * 65))
    print()


def check_processes(seen_pids):
    for proc in psutil.process_iter(["pid", "name", "exe", "memory_info"]):
        try:
            pid  = proc.info["pid"]
            name = proc.info["name"] or "unknown"
            exe  = proc.info["exe"] or ""
            mem  = proc.info["memory_info"].rss // (1024 * 1024) if proc.info["memory_info"] else 0

            if pid not in seen_pids:
                seen_pids.add(pid)
                ext        = Path(exe).suffix.lower() if exe else ""
                name_lower = name.lower()

                # Check suspicious behavior keywords in name or exe path
                behavior_match = next(
                    (kw for kw in SUSPICIOUS_BEHAVIOR if kw in name_lower or kw in exe.lower()),
                    None
                )

                if behavior_match:
                    log("🚨", f"SUSPICIOUS PROCESS: {red(name)} | PID:{pid} | Reason: contains '{behavior_match}' | Path: {exe[:50]}", red)
                elif name_lower in WHITELIST_PROCESSES:
                    pass
                elif ext in SUSPICIOUS_EXT:
                    log("🚨", f"SUSPICIOUS PROCESS: {red(name)} | PID:{pid} | Reason: suspicious extension '{ext}' | Path: {exe[:50]}", red)
                else:
                    log("⚙️ ", gray(f"New process: {name} PID:{pid} RAM:{mem}MB"))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return seen_pids


def check_network(seen_conns):
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status == "ESTABLISHED" and c.raddr:
                key = (c.laddr.port, c.raddr.ip, c.raddr.port)
                if key not in seen_conns:
                    seen_conns.add(key)
                    try:
                        host = socket.gethostbyaddr(c.raddr.ip)[0]
                    except Exception:
                        host = c.raddr.ip
                    log("🌐", f"Connection: {cyan(host)} ({c.raddr.ip}:{c.raddr.port})")
    except Exception:
        pass
    return seen_conns


def check_usb(seen_devices):
    try:
        partitions = psutil.disk_partitions()
        current = set()
        for d in partitions:
            if "removable" in d.opts or "usb" in d.device.lower():
                current.add(d.device)
                if d.device not in seen_devices:
                    try:
                        usage = psutil.disk_usage(d.mountpoint)
                        log("🔌", f"USB Connected: {yellow(d.device)} | Size:{usage.total // (1024**3)}GB | Used:{usage.percent}%", yellow)
                        log("🔍", f"Scanning {d.device} for threats...", cyan)
                        scan_usb(d.mountpoint)
                    except Exception:
                        log("🔌", f"USB Connected: {yellow(d.device)}", yellow)

        for d in seen_devices - current:
            log("🔌", f"USB Removed: {yellow(d)}", yellow)
        return current
    except Exception:
        return seen_devices


def scan_usb(mountpoint):
    try:
        found = False
        for f in Path(mountpoint).rglob("*"):
            if f.is_file():
                ext = f.suffix.lower()
                if ext in SUSPICIOUS_EXT:
                    log("🚨", f"SUSPICIOUS FILE ON USB: {red(f.name)} [{ext}]", red)
                    found = True
        if not found:
            log("✅", green(f"USB scan complete — No threats found"))
    except:
        pass


def check_downloads(seen_files):
    try:
        for f in Path(DOWNLOAD_PATH).iterdir():
            if not f.is_file() or str(f) in seen_files:
                continue
            mtime = datetime.fromtimestamp(f.stat().st_mtime)
            if datetime.now() - mtime > timedelta(minutes=2):
                seen_files.add(str(f))
                continue
            seen_files.add(str(f))
            ext  = f.suffix.lower()
            size = f.stat().st_size // 1024
            if ext in SUSPICIOUS_EXT:
                log("🚨", f"SUSPICIOUS DOWNLOAD: {red(f.name)} [{ext}] {size}KB", red)
            else:
                log("📥", f"New download: {cyan(f.name)} {size}KB")
    except Exception:
        pass
    return seen_files


def system_stats():
    cpu = psutil.cpu_percent(interval=0.5)
    ram = psutil.virtual_memory()
    print()
    print(cyan("  " + "─" * 65))
    log("💻", f"CPU: {yellow(str(cpu) + '%')} | RAM: {yellow(str(ram.percent) + '%')} | Used:{ram.used // (1024**2)}MB / {ram.total // (1024**2)}MB")
    print(cyan("  ") + bold("  🔥 Top Processes by CPU & RAM:"))
    procs = []
    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info"]):
        try:
            mem   = proc.info["memory_info"].rss // (1024 * 1024) if proc.info["memory_info"] else 0
            cpu_p = proc.cpu_percent(interval=0)
            procs.append((proc.info["name"], proc.info["pid"], cpu_p, mem))
        except:
            pass
    procs.sort(key=lambda x: x[2], reverse=True)
    for name, pid, cpu_p, mem in procs[:5]:
        print(f"    {cyan(name[:25])} PID:{pid} CPU:{yellow(str(cpu_p) + '%')} RAM:{yellow(str(mem) + 'MB')}")
    print(cyan("  " + "─" * 65))
    print()


def run():
    seen_pids    = set()
    seen_conns   = set()
    seen_devices = set()
    seen_files   = set()
    cycle        = 0

    print_header()

    # Pre-fill existing processes so we don't spam on startup
    for proc in psutil.process_iter(["pid"]):
        try:
            seen_pids.add(proc.info["pid"])
        except Exception:
            pass

    log("✅", green("CyberSentinel Monitor Active — Watching your system"))
    log("📁", f"Download folder: {DOWNLOAD_PATH}")
    log("🔌", "Watching for USB devices...")
    print()

    while True:
        try:
            seen_conns   = check_network(seen_conns)
            seen_devices = check_usb(seen_devices)
            seen_files   = check_downloads(seen_files)
            seen_pids    = check_processes(seen_pids)

            if cycle % 15 == 0:
                system_stats()

            cycle += 1
            time.sleep(2)

        except KeyboardInterrupt:
            print(yellow("\n\n  CyberSentinel Monitor stopped.\n"))
            sys.exit(0)


if __name__ == "__main__":
    run()
