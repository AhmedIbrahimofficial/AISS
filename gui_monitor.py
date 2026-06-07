"""
AISS GUI Monitor — Tkinter-based threat dashboard
Run: python gui_monitor.py
Features:
  - Live threat list with Resolve + Open Location buttons
  - Auto-refresh every 5 seconds
  - Dark theme matching AISS style
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import requests
import os
import time
import subprocess
import sys
from datetime import datetime

API = "http://localhost:8000"

# ── Dark theme colors ─────────────────────────────────────────────────
BG          = "#0a0a0f"
BG2         = "#111118"
FG          = "#e0e0e0"
CYAN        = "#00d4ff"
GREEN       = "#00ff88"
YELLOW      = "#ffd166"
RED         = "#ff4444"
DIM         = "#555566"
BTN_RESOLVE = "#1a3a2a"
BTN_OPEN    = "#1a2a3a"


# ══════════════════════════════════════════════════════════════════════
# Helper functions
# ══════════════════════════════════════════════════════════════════════

def get_threats():
    try:
        r = requests.get(f"{API}/api/threats/active", timeout=3)
        if r.status_code == 200:
            return r.json().get("threats", [])
    except Exception:
        pass
    return None  # None = offline


def resolve_threat(threat_id: str) -> bool:
    try:
        r = requests.post(
            f"{API}/api/threats/{threat_id}/resolve",
            params={"note": "Resolved via AISS GUI Monitor"},
            timeout=3,
        )
        return r.status_code == 200
    except Exception:
        return False


def open_location(source: str):
    try:
        if os.path.exists(source):
            folder = os.path.dirname(source) if os.path.isfile(source) else source
            if sys.platform == "win32":
                os.startfile(folder)
            else:
                subprocess.Popen(["xdg-open", folder])
        elif source.startswith("PID:"):
            if sys.platform == "win32":
                subprocess.Popen(["taskmgr"])
        else:
            messagebox.showinfo("Location", f"Source: {source}\n(Cannot open directly)")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def sev_color(sev: str) -> str:
    return {
        "critical": RED,
        "high":     YELLOW,
        "medium":   CYAN,
        "low":      GREEN,
    }.get(sev.lower(), FG)


# ══════════════════════════════════════════════════════════════════════
# Main App
# ══════════════════════════════════════════════════════════════════════

class AISSDashboard(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("AISS — Threat Monitor")
        self.configure(bg=BG)
        self.geometry("1100x600")
        self.minsize(900, 400)

        self._build_ui()
        self._refresh()

    def _build_ui(self):
        # ── Header ────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=BG2, pady=8)
        hdr.pack(fill="x")

        tk.Label(
            hdr, text="🛡️  AISS THREAT MONITOR",
            font=("Consolas", 16, "bold"),
            bg=BG2, fg=CYAN,
        ).pack(side="left", padx=16)

        self._status_lbl = tk.Label(
            hdr, text="● Connecting...",
            font=("Consolas", 10),
            bg=BG2, fg=YELLOW,
        )
        self._status_lbl.pack(side="right", padx=16)

        self._time_lbl = tk.Label(
            hdr, text="",
            font=("Consolas", 10),
            bg=BG2, fg=DIM,
        )
        self._time_lbl.pack(side="right", padx=8)

        # ── Threat count bar ──────────────────────────────────────────
        self._count_lbl = tk.Label(
            self, text="Active Threats: —",
            font=("Consolas", 11),
            bg=BG, fg=YELLOW, pady=6,
        )
        self._count_lbl.pack(fill="x", padx=16)

        # ── Scrollable threat list ────────────────────────────────────
        container = tk.Frame(self, bg=BG)
        container.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        canvas = tk.Canvas(container, bg=BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical",
                                   command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        self._list_frame = tk.Frame(canvas, bg=BG)
        self._canvas_window = canvas.create_window(
            (0, 0), window=self._list_frame, anchor="nw"
        )

        self._list_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.bind(
            "<Configure>",
            lambda e: canvas.itemconfig(
                self._canvas_window, width=e.width
            )
        )

        self._canvas = canvas

        # ── Column headers ────────────────────────────────────────────
        self._build_header()

    def _build_header(self):
        cols = [
            ("Time",     8),
            ("Type",     18),
            ("Severity", 10),
            ("Source",   20),
            ("Module",   14),
            ("Status",   10),
            ("",         28),  # buttons
        ]
        hdr_row = tk.Frame(self._list_frame, bg=BG2)
        hdr_row.pack(fill="x", padx=4, pady=(0, 2))

        for col_name, width in cols:
            tk.Label(
                hdr_row, text=col_name,
                width=width, anchor="w",
                font=("Consolas", 9, "bold"),
                bg=BG2, fg=CYAN,
            ).pack(side="left", padx=2)

    def _clear_list(self):
        for widget in self._list_frame.winfo_children():
            if isinstance(widget, tk.Frame) and widget.cget("bg") != BG2:
                widget.destroy()

    def _build_threat_row(self, threat: dict, idx: int):
        tid    = threat.get("id", "")
        sev    = (threat.get("severity") or "low").lower()
        color  = sev_color(sev)
        status = threat.get("status") or "active"
        source = threat.get("source") or "—"
        module = threat.get("module") or "—"
        ttype  = (threat.get("type") or "Unknown")

        # Time
        detected = threat.get("detected_at") or ""
        try:
            dt   = datetime.fromisoformat(detected)
            tstr = dt.strftime("%H:%M:%S")
        except Exception:
            tstr = detected[:8]

        row_bg = "#0d0d15" if idx % 2 == 0 else "#0f0f18"

        row = tk.Frame(self._list_frame, bg=row_bg, pady=3)
        row.pack(fill="x", padx=4, pady=1)

        # ── Data columns ──────────────────────────────────────────────
        def lbl(text, width, fg=FG, bold=False):
            font = ("Consolas", 9, "bold") if bold else ("Consolas", 9)
            tk.Label(
                row, text=text, width=width, anchor="w",
                font=font, bg=row_bg, fg=fg,
            ).pack(side="left", padx=2)

        lbl(tstr,          8)
        lbl(ttype[:18],   18, fg=color, bold=True)
        lbl(sev.upper(),  10, fg=color, bold=True)
        lbl(source[:20],  20, fg=FG)
        lbl(module[:14],  14, fg=DIM)
        lbl(status[:10],  10, fg=YELLOW if status == "active" else GREEN)

        # ── Buttons ───────────────────────────────────────────────────
        btn_frame = tk.Frame(row, bg=row_bg)
        btn_frame.pack(side="left", padx=4)

        # Resolve button
        resolve_btn = tk.Button(
            btn_frame,
            text="✓ Resolve",
            font=("Consolas", 8, "bold"),
            bg=BTN_RESOLVE, fg=GREEN,
            activebackground="#2a5a3a", activeforeground=GREEN,
            relief="flat", padx=6, pady=2, cursor="hand2",
            command=lambda t=tid, r=row, b=None: self._on_resolve(t, row),
        )
        resolve_btn.pack(side="left", padx=2)

        # Open Location button
        open_btn = tk.Button(
            btn_frame,
            text="📁 Location",
            font=("Consolas", 8),
            bg=BTN_OPEN, fg=CYAN,
            activebackground="#2a3a5a", activeforeground=CYAN,
            relief="flat", padx=6, pady=2, cursor="hand2",
            command=lambda s=source: open_location(s),
        )
        open_btn.pack(side="left", padx=2)

    def _on_resolve(self, threat_id: str, row: tk.Frame):
        """Resolve a threat in background thread."""
        def _do():
            ok = resolve_threat(threat_id)
            if ok:
                self.after(0, lambda: self._refresh())
            else:
                self.after(0, lambda: messagebox.showerror(
                    "Error", "Could not resolve threat.\nCheck if AISS backend is running."
                ))
        threading.Thread(target=_do, daemon=True).start()

    def _refresh(self):
        """Fetch threats and rebuild list."""
        now_str = datetime.now().strftime("%H:%M:%S")
        self._time_lbl.config(text=now_str)

        threats = get_threats()

        if threats is None:
            self._status_lbl.config(text="● Backend Offline", fg=RED)
            self._count_lbl.config(text="AISS Backend not running — start with start.bat", fg=RED)
            self._clear_list()
        else:
            count = len(threats)
            self._status_lbl.config(text="● Live", fg=GREEN)
            self._count_lbl.config(
                text=f"Active Threats: {count}  {'⚠ ACTION REQUIRED' if count > 0 else '✓ System Clean'}",
                fg=RED if count > 0 else GREEN,
            )
            self._clear_list()
            if not threats:
                no_threat = tk.Frame(self._list_frame, bg=BG, pady=20)
                no_threat.pack(fill="x")
                tk.Label(
                    no_threat,
                    text="✓  No active threats detected",
                    font=("Consolas", 12),
                    bg=BG, fg=GREEN,
                ).pack()
            else:
                for idx, threat in enumerate(threats):
                    self._build_threat_row(threat, idx)

        # Schedule next refresh
        self.after(5000, self._refresh)


# ══════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = AISSDashboard()
    app.mainloop()
