"""
AISS Setup EXE Creator — Fast version
Creates AISS_Setup.exe (the installer GUI only, ~15MB)
The installer downloads/extracts AISS from the ZIP on the same server,
OR can be bundled with a separate ZIP file for offline install.

Run: python create_setup_exe.py
"""
import os, sys, subprocess
from pathlib import Path

BASE   = Path(__file__).parent
OUTDIR = BASE / "installer" / "output"
VENV   = BASE / "aiss backend" / ".venv" / "Scripts"
PYINST = VENV / "pyinstaller.exe"

# The installer GUI script — standalone, no zip embedded
INSTALLER_STUB = OUTDIR / "_aiss_installer.py"

STUB = r'''
import os, sys, zipfile, threading, subprocess, winreg, urllib.request, json
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

VERSION   = "2.0.0"
APP_NAME  = "AISS"
APP_FULL  = "AISS — AI Integrated Security System"
ZIP_NAME  = "AISS_v2.0_Windows_Portable.zip"
REPO_URL  = "https://github.com/AhmedIbrahimofficial/AISS/releases/latest"

# ── Paths ────────────────────────────────────────────────────────────
EXE_DIR  = Path(sys.executable).parent if getattr(sys,"frozen",False) else Path(__file__).parent
ZIP_PATH = EXE_DIR / ZIP_NAME   # bundled alongside .exe

BG    = "#070d0b"
CARD  = "#0d1a15"
GREEN = "#10b981"
MUTED = "#7c8c85"
RED   = "#dc2626"
WARN  = "#f59e0b"
FG    = "#e6edea"

def make_btn(parent, text, cmd, color=GREEN, **kw):
    return tk.Button(parent, text=text, command=cmd, bg=color, fg="white",
                     font=("Segoe UI", 10, "bold"), relief="flat",
                     padx=18, pady=7, cursor="hand2", **kw)

def make_label(parent, text, size=9, color=FG, bold=False, **kw):
    return tk.Label(parent, text=text, bg=CARD, fg=color,
                    font=("Segoe UI", size, "bold" if bold else "normal"),
                    wraplength=440, justify="left", **kw)

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_FULL} — Setup v{VERSION}")
        self.geometry("540x460")
        self.resizable(False, False)
        self.configure(bg=BG)
        self.protocol("WM_DELETE_WINDOW", self._confirm_cancel)

        self.install_dir = tk.StringVar(value=str(
            Path(os.environ.get("PROGRAMFILES","C:/Program Files")) / "AISS"
        ))
        self.shortcut  = tk.BooleanVar(value=True)
        self.autostart = tk.BooleanVar(value=False)
        self.launch    = tk.BooleanVar(value=True)

        self._page_welcome()

    def _confirm_cancel(self):
        if messagebox.askyesno("Cancel Setup", "Cancel AISS installation?"):
            self.destroy()

    def _clear(self):
        for w in self.winfo_children(): w.destroy()

    def _header(self, title, sub=""):
        h = tk.Frame(self, bg="#060e0b", height=70)
        h.pack(fill="x")
        h.pack_propagate(False)
        f = tk.Frame(h, bg="#060e0b")
        f.place(relx=.5, rely=.5, anchor="center")
        tk.Label(f, text=f"🛡  {title}", bg="#060e0b", fg=GREEN,
                 font=("Segoe UI", 14, "bold")).pack()
        if sub:
            tk.Label(f, text=sub, bg="#060e0b", fg=MUTED,
                     font=("Segoe UI", 8)).pack()

    def _footer(self, btns):
        """btns = [(text, cmd, color), ...]"""
        f = tk.Frame(self, bg="#060e0b", height=52)
        f.pack(fill="x", side="bottom")
        f.pack_propagate(False)
        for text, cmd, color in reversed(btns):
            make_btn(f, text, cmd, color).pack(side="right", padx=6, pady=8)

    def _page_welcome(self):
        self._clear()
        self._header("AISS Setup", f"Version {VERSION}")

        body = tk.Frame(self, bg=CARD)
        body.pack(fill="both", expand=True, padx=18, pady=12)

        make_label(body, f"Welcome to {APP_FULL}", 13, FG, True).pack(anchor="w", pady=(0,8))
        for line in [
            "This wizard will install AISS on your computer.",
            "",
            "✓  AI-powered threat detection & response",
            "✓  Real-time network & process monitoring",
            "✓  SOC dashboard — 30+ security modules",
            "✓  Multi-computer remote agent support",
            "✓  YARA / Sigma detection rules",
            "✓  Phishing, malware & IOC analysis",
            "",
            "Click Next to choose install location.",
        ]:
            c = GREEN if line.startswith("✓") else (MUTED if not line else FG)
            make_label(body, line, 9, c).pack(anchor="w")

        self._footer([
            ("Next →",  self._page_options, GREEN),
            ("Cancel",  self._confirm_cancel, RED),
        ])

    def _page_options(self):
        self._clear()
        self._header("Installation Options")

        body = tk.Frame(self, bg=CARD)
        body.pack(fill="both", expand=True, padx=18, pady=10)

        make_label(body, "Install Location:", 9, MUTED).pack(anchor="w")
        row = tk.Frame(body, bg=CARD)
        row.pack(fill="x", pady=(2,10))
        tk.Entry(row, textvariable=self.install_dir, bg="#0a1410", fg=FG,
                 font=("Courier New", 9), relief="flat", insertbackground=GREEN,
                 width=46).pack(side="left", ipady=6, padx=(0,6))
        tk.Button(row, text="Browse…", command=self._browse,
                  bg="#1a2e25", fg=GREEN, font=("Segoe UI",9),
                  relief="flat", padx=8, pady=4).pack(side="left")

        tk.Frame(body, bg="#1a2e25", height=1).pack(fill="x", pady=8)

        for var, txt in [(self.shortcut, "Create Desktop Shortcut"),
                         (self.autostart, "Launch AISS when Windows starts")]:
            cb = tk.Checkbutton(body, text=f"  {txt}", variable=var,
                                bg=CARD, fg=FG, selectcolor="#0a1410",
                                activebackground=CARD, font=("Segoe UI",9),
                                cursor="hand2")
            cb.pack(anchor="w", pady=2)

        tk.Frame(body, bg="#1a2e25", height=1).pack(fill="x", pady=8)
        make_label(body, "Required space:  ~500 MB", 8, MUTED).pack(anchor="w")
        make_label(body, "Default login:  admin@aiss.local  /  Admin123!", 8, GREEN).pack(anchor="w")

        zip_ok = ZIP_PATH.exists()
        status = f"✓  Installer archive found ({round(ZIP_PATH.stat().st_size/1024/1024,0):.0f} MB)" if zip_ok \
                 else f"⚠  Archive not found: {ZIP_NAME} — place it next to this exe"
        make_label(body, status, 8, GREEN if zip_ok else WARN).pack(anchor="w", pady=(6,0))

        self._footer([
            ("Install →", self._start_install if zip_ok else lambda: messagebox.showerror("Missing File", f"{ZIP_NAME} must be in the same folder as this setup exe."), GREEN),
            ("← Back",   self._page_welcome, "#1a2e25"),
        ])

    def _browse(self):
        d = filedialog.askdirectory(initialdir=self.install_dir.get(), title="Choose Install Folder")
        if d: self.install_dir.set(d)

    def _start_install(self):
        self._clear()
        self._header("Installing…", "Please wait")

        body = tk.Frame(self, bg=CARD)
        body.pack(fill="both", expand=True, padx=18, pady=14)

        self._status = tk.StringVar(value="Starting…")
        self._detail = tk.StringVar(value="")

        make_label(body, "", 2, MUTED).pack()
        tk.Label(body, textvariable=self._status, bg=CARD, fg=FG,
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("G.Horizontal.TProgressbar", troughcolor="#0a1410",
                         bordercolor="#0a1410", background=GREEN, lightcolor=GREEN, darkcolor=GREEN)
        self._prog = ttk.Progressbar(body, style="G.Horizontal.TProgressbar",
                                     mode="determinate", length=480)
        self._prog.pack(pady=10)

        tk.Label(body, textvariable=self._detail, bg=CARD, fg=MUTED,
                 font=("Courier New", 8), wraplength=480).pack(anchor="w")

        threading.Thread(target=self._do_install, daemon=True).start()

    def _set(self, msg, pct, detail=""):
        self.after(0, lambda: (
            self._status.set(msg),
            self._prog.configure(value=pct),
            self._detail.set(detail[:80]),
        ))

    def _do_install(self):
        try:
            dest = Path(self.install_dir.get())
            dest.mkdir(parents=True, exist_ok=True)

            self._set("Extracting files…", 5, "Opening archive…")
            with zipfile.ZipFile(ZIP_PATH) as zf:
                names = zf.namelist()
                n = len(names)
                for i, name in enumerate(names):
                    zf.extract(name, dest)
                    self._set("Extracting files…", 5 + int(i/n*80), name)

            self._set("Creating shortcuts…", 87)
            self._make_shortcuts(dest)

            if self.autostart.get():
                self._set("Configuring autostart…", 93)
                self._add_autostart(dest)

            (dest / "logs").mkdir(exist_ok=True)
            (dest / "data").mkdir(exist_ok=True)

            self._set("Complete!", 100, "AISS installed successfully")
            self.after(400, lambda: self._page_done(dest))

        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Install Error", str(e)))

    def _make_shortcuts(self, dest: Path):
        bat = dest / "Launch AISS.bat"
        bat.write_text(f'@echo off\ncd /d "{dest}"\nstart "" "AISS.exe"\n', encoding="ascii", errors="replace")

        if self.shortcut.get():
            desktop = Path(os.path.expanduser("~")) / "Desktop"
            if not desktop.exists():
                desktop = Path(os.environ.get("USERPROFILE","~")) / "Desktop"
            lnk_bat = desktop / "AISS.bat"
            lnk_bat.write_text(f'@echo off\ncd /d "{dest}"\nstart "" "AISS.exe"\n',
                               encoding="ascii", errors="replace")

    def _add_autostart(self, dest: Path):
        try:
            exe = dest / "AISS.exe"
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(k, "AISS", 0, winreg.REG_SZ, str(exe))
            winreg.CloseKey(k)
        except Exception: pass

    def _page_done(self, dest: Path):
        self._clear()
        self._header("✓ Installation Complete", "AISS is ready to use")

        body = tk.Frame(self, bg=CARD)
        body.pack(fill="both", expand=True, padx=18, pady=12)

        make_label(body, "AISS has been installed successfully!", 12, GREEN, True).pack(anchor="w", pady=(0,10))
        make_label(body, f"Location:  {dest}", 9, MUTED).pack(anchor="w")
        make_label(body, "", 4).pack()
        make_label(body, "How to start:", 9, FG, True).pack(anchor="w")
        make_label(body, f"  • Double-click  AISS.exe  in the install folder", 9).pack(anchor="w")
        make_label(body, f"  • Or use the  Launch AISS.bat  shortcut on Desktop", 9).pack(anchor="w")
        make_label(body, "", 4).pack()
        make_label(body, "Default Login Credentials:", 9, FG, True).pack(anchor="w")
        make_label(body, "  Email:     admin@aiss.local", 10, GREEN).pack(anchor="w")
        make_label(body, "  Password:  Admin123!", 10, GREEN).pack(anchor="w")
        make_label(body, "", 4).pack()
        make_label(body, "⚠  Change your password after first login!", 8, WARN).pack(anchor="w")

        tk.Checkbutton(body, text="  Launch AISS now", variable=self.launch,
                       bg=CARD, fg=FG, selectcolor="#0a1410",
                       font=("Segoe UI",9), cursor="hand2").pack(anchor="w", pady=8)

        self._footer([("Finish", lambda: self._finish(dest), GREEN)])

    def _finish(self, dest: Path):
        if self.launch.get():
            exe = dest / "AISS.exe"
            if exe.exists():
                subprocess.Popen([str(exe)], cwd=str(dest))
        self.destroy()


App().mainloop()
'''

def build():
    print("\n═══════════════════════════════════════════")
    print("  AISS Setup EXE Builder")
    print("═══════════════════════════════════════════\n")

    OUTDIR.mkdir(parents=True, exist_ok=True)

    # Write stub
    INSTALLER_STUB.write_text(STUB, encoding="utf-8")
    print(f"✓ Installer stub written: {INSTALLER_STUB}")

    zip_path = OUTDIR / "AISS_v2.0_Windows_Portable.zip"
    if not zip_path.exists():
        print(f"✗ ZIP not found: {zip_path}")
        print("  Run build_portable.ps1 first.")
        return False

    print(f"✓ Archive found: {round(zip_path.stat().st_size/1024/1024, 1)} MB")
    print("\nBuilding AISS_Setup.exe (small installer, ~15 MB)...")

    cmd = [
        str(PYINST),
        "--noconfirm", "--clean", "--onefile", "--windowed",
        "--name", "AISS_Setup",
        "--distpath", str(OUTDIR),
        "--workpath", str(OUTDIR / "_build"),
        "--specpath", str(OUTDIR),
        str(INSTALLER_STUB),
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(OUTDIR))

    out_exe = OUTDIR / "AISS_Setup.exe"
    if out_exe.exists():
        mb = round(out_exe.stat().st_size / 1024 / 1024, 1)
        print(f"\n✅ AISS_Setup.exe created: {mb} MB")
        print(f"   {out_exe}")
        print("\nDistribute BOTH files together:")
        print(f"   AISS_Setup.exe             ({mb} MB)  ← user runs this")
        print(f"   AISS_v2.0_Windows_Portable.zip  ({round(zip_path.stat().st_size/1024/1024,1)} MB)  ← in same folder")
        print("\nOR use the ZIP alone — user extracts and runs AISS.exe directly.")
        return True
    else:
        print("✗ Build failed:")
        print(result.stderr[-3000:] if result.stderr else result.stdout[-3000:])
        return False


if __name__ == "__main__":
    build()
