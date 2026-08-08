"""
AISS Professional Installer
Full standalone Windows installer — no external tools needed.
Packages: Python + Node.js + all deps + app
Screens: License → Path → Install → Done
"""
import os, sys, subprocess, threading, zipfile, shutil, winreg, ctypes
import urllib.request, json, time
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ── Constants ──────────────────────────────────────────────────────────
VERSION   = "2.0.0"
APP_NAME  = "AISS"
APP_FULL  = "AISS — AI Integrated Security System"
PUBLISHER = "Ahmed Ibrahim"
YEAR      = "2026"
EXE_DIR   = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).parent
ICON_PATH = EXE_DIR / "aiss.ico"
DEFAULT_INSTALL = Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "AISS"

# Magic marker used when ZIP is embedded inside the EXE
_MAGIC = b"AISS_ZIP_START_MARKER_8675309"

def _get_zip_path():
    """Return Path to ZIP — either embedded in EXE or alongside it."""
    import struct, io

    # 1. Check if ZIP is embedded in our own exe
    exe = Path(sys.executable) if getattr(sys, "frozen", False) else Path(__file__)
    try:
        data = exe.read_bytes()
        idx  = data.rfind(_MAGIC)
        if idx != -1:
            size_start = idx + len(_MAGIC)
            zip_size   = struct.unpack("<Q", data[size_start:size_start + 8])[0]
            zip_start  = size_start + 8
            zip_bytes  = data[zip_start:zip_start + zip_size]
            # Write to temp file so zipfile can use it
            import tempfile
            tmp = Path(tempfile.mkdtemp()) / "aiss_bundle.zip"
            tmp.write_bytes(zip_bytes)
            return tmp
    except Exception:
        pass

    # 2. Look for ZIP file alongside the exe
    for candidate in [
        EXE_DIR / "AISS_v2.0_Windows_Portable.zip",
        EXE_DIR / "aiss_bundle.zip",
    ]:
        if candidate.exists():
            return candidate

    return None

ZIP_PATH = _get_zip_path() or (EXE_DIR / "AISS_v2.0_Windows_Portable.zip")

# ── Colors ─────────────────────────────────────────────────────────────
BG     = "#070d0b"
CARD   = "#0d1a15"
DARK   = "#060e0b"
GREEN  = "#10b981"
MUTED  = "#7c8c85"
RED    = "#dc2626"
WARN   = "#f59e0b"
FG     = "#e6edea"
BORDER = "#1a2e25"

LICENSE_TEXT = """AISS END-USER LICENSE AGREEMENT
Version 2.0 — Effective August 2026
Copyright (c) 2026 AISS Technologies. All Rights Reserved.

IMPORTANT: READ THIS AGREEMENT CAREFULLY BEFORE INSTALLING.

By clicking "I Agree" and installing AISS, you agree to all terms below.

1. GRANT OF LICENSE
   You are granted a non-exclusive license to install and use AISS on
   your own computers for personal or organizational security monitoring.

2. PERMITTED USE
   - Monitor your own networks, endpoints, and systems
   - Detect and respond to threats on systems you own or administer
   - Use all AI, network scanning, and analysis features included

3. RESTRICTIONS
   You may NOT:
   - Redistribute or resell this software without written permission
   - Use AISS to attack, scan, or monitor systems you do not own
   - Reverse engineer or remove license enforcement mechanisms
   - Use AISS for illegal surveillance or unauthorized access

4. PRIVACY & DATA
   - AISS runs entirely locally — no data is sent to external servers
   - All threat logs, credentials, and analysis stay on your machine
   - AI features require optional API keys (OpenAI, Anthropic, etc.)

5. DISCLAIMER
   AISS is provided for defensive security purposes. The authors are not
   responsible for misuse. Use responsibly and within the law.

6. UPDATES
   Future updates may be downloaded from the official GitHub repository.
   Update terms may change — review the license with each major release.

BY CLICKING "I AGREE" YOU ACCEPT ALL TERMS ABOVE.
"""


# ── Base Window ────────────────────────────────────────────────────────
class InstallerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_FULL} — Setup v{VERSION}")
        self.geometry("620x500")
        self.minsize(620, 500)
        self.resizable(False, False)
        self.configure(bg=BG)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # State
        self.install_dir  = tk.StringVar(value=str(DEFAULT_INSTALL))
        self.desktop_sc   = tk.BooleanVar(value=True)
        self.startmenu_sc = tk.BooleanVar(value=True)
        self.autostart    = tk.BooleanVar(value=False)
        self.launch_after = tk.BooleanVar(value=True)
        self._install_dest = None

        self._show_license()
        self.mainloop()

    def _on_close(self):
        if messagebox.askyesno("Cancel Setup", "Are you sure you want to cancel the installation?", parent=self):
            self.destroy()

    # ── Layout helpers ─────────────────────────────────────────────────
    def _clear(self):
        for w in self.winfo_children():
            w.destroy()

    def _header(self, title, subtitle=""):
        h = tk.Frame(self, bg=DARK, height=80)
        h.pack(fill="x")
        h.pack_propagate(False)
        inner = tk.Frame(h, bg=DARK)
        inner.place(relx=0.5, rely=0.5, anchor="center")
        tk.Label(inner, text=f"🛡  {title}", bg=DARK, fg=GREEN,
                 font=("Segoe UI", 15, "bold")).pack()
        if subtitle:
            tk.Label(inner, text=subtitle, bg=DARK, fg=MUTED,
                     font=("Segoe UI", 8)).pack(pady=(2,0))

    def _divider(self, parent):
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", pady=8)

    def _label(self, parent, text, size=9, color=FG, bold=False, pady=3, padx=0):
        lbl = tk.Label(parent, text=text, bg=CARD, fg=color, anchor="w",
                       font=("Segoe UI", size, "bold" if bold else "normal"),
                       wraplength=550, justify="left")
        lbl.pack(anchor="w", pady=pady, padx=padx)
        return lbl

    def _footer(self, buttons):
        """buttons = [(text, cmd, color), ...]  right-to-left order"""
        f = tk.Frame(self, bg=DARK, height=55)
        f.pack(fill="x", side="bottom")
        f.pack_propagate(False)
        sep = tk.Frame(f, bg=BORDER, height=1)
        sep.pack(fill="x")
        inner = tk.Frame(f, bg=DARK)
        inner.pack(side="right", padx=12, pady=8)
        for text, cmd, color in buttons:
            tk.Button(inner, text=text, command=cmd,
                      bg=color, fg="white", relief="flat",
                      font=("Segoe UI", 9, "bold"),
                      padx=20, pady=6, cursor="hand2").pack(side="left", padx=4)

    def _body(self):
        f = tk.Frame(self, bg=CARD)
        f.pack(fill="both", expand=True)
        return f

    def _progress_bar(self, parent):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("AISS.Horizontal.TProgressbar",
                        troughcolor="#0a1410", bordercolor="#0a1410",
                        background=GREEN, lightcolor=GREEN, darkcolor=GREEN)
        pb = ttk.Progressbar(parent, style="AISS.Horizontal.TProgressbar",
                             mode="determinate", length=560)
        pb.pack(pady=6, padx=20)
        return pb

    # ══════════════════════════════════════════════════════════════════
    # PAGE 1 — LICENSE AGREEMENT
    # ══════════════════════════════════════════════════════════════════
    def _show_license(self):
        self._clear()
        self._header("License Agreement", "Please read and accept the license before continuing")

        body = self._body()
        body.pack_propagate(False)

        # Step indicator
        self._step_bar(body, 1)

        info = tk.Frame(body, bg=CARD)
        info.pack(fill="x", padx=20, pady=(8,4))
        tk.Label(info, text="AISS End-User License Agreement",
                 bg=CARD, fg=FG, font=("Segoe UI", 10, "bold")).pack(anchor="w")
        tk.Label(info, text="Read the full agreement below. You must accept to continue.",
                 bg=CARD, fg=MUTED, font=("Segoe UI", 8)).pack(anchor="w")

        # Scrollable license text
        txt_frame = tk.Frame(body, bg="#0a1410", bd=1, relief="solid")
        txt_frame.pack(fill="both", expand=True, padx=20, pady=4)
        scrollbar = tk.Scrollbar(txt_frame)
        scrollbar.pack(side="right", fill="y")
        txt = tk.Text(txt_frame, bg="#0a1410", fg=MUTED, font=("Courier New", 8),
                      relief="flat", wrap="word", yscrollcommand=scrollbar.set,
                      state="normal", padx=10, pady=8)
        txt.insert("1.0", LICENSE_TEXT)
        txt.config(state="disabled")
        txt.pack(fill="both", expand=True)
        scrollbar.config(command=txt.yview)

        # Agreement checkbox
        chk_frame = tk.Frame(body, bg=CARD)
        chk_frame.pack(fill="x", padx=20, pady=6)
        self._agreed = tk.BooleanVar(value=False)
        tk.Checkbutton(chk_frame, text="  I have read and agree to the License Agreement",
                       variable=self._agreed, bg=CARD, fg=FG,
                       selectcolor="#0a1410", activebackground=CARD,
                       font=("Segoe UI", 9, "bold"), cursor="hand2").pack(anchor="w")

        self._footer([
            ("I Agree — Next →", self._on_agree, GREEN),
            ("Decline",          self._on_close, RED),
        ])

    def _on_agree(self):
        if not self._agreed.get():
            messagebox.showwarning("License Required",
                "You must check the box to agree to the License Agreement before continuing.",
                parent=self)
            return
        self._show_options()

    # ══════════════════════════════════════════════════════════════════
    # PAGE 2 — CHOOSE PATH & OPTIONS
    # ══════════════════════════════════════════════════════════════════
    def _show_options(self):
        self._clear()
        self._header("Installation Options", "Choose where to install AISS")

        body = self._body()
        self._step_bar(body, 2)

        content = tk.Frame(body, bg=CARD)
        content.pack(fill="both", expand=True, padx=20, pady=8)

        # Install path
        self._label(content, "Installation Folder:", 9, MUTED, pady=2)
        path_row = tk.Frame(content, bg=CARD)
        path_row.pack(fill="x", pady=(2, 10))
        path_entry = tk.Entry(path_row, textvariable=self.install_dir,
                              bg="#0a1410", fg=FG, insertbackground=GREEN,
                              font=("Courier New", 9), relief="flat", bd=0)
        path_entry.pack(side="left", fill="x", expand=True, ipady=8, padx=(0,8))
        tk.Button(path_row, text="Browse…", command=self._browse_dir,
                  bg=BORDER, fg=GREEN, font=("Segoe UI", 9), relief="flat",
                  padx=12, pady=5, cursor="hand2").pack(side="left")

        self._divider(content)

        # Shortcuts
        self._label(content, "Shortcut Options:", 9, FG, True, pady=2)
        for var, txt, hint in [
            (self.desktop_sc,   "Create Desktop Shortcut",                "One-click launch from your Desktop"),
            (self.startmenu_sc, "Add to Start Menu",                      "Find AISS in Windows Start Menu"),
            (self.autostart,    "Launch AISS when Windows starts",         "AISS monitors from startup (recommended)"),
        ]:
            row = tk.Frame(content, bg=CARD)
            row.pack(fill="x", pady=2)
            tk.Checkbutton(row, text=f"  {txt}", variable=var,
                           bg=CARD, fg=FG, selectcolor="#0a1410",
                           font=("Segoe UI", 9), cursor="hand2",
                           activebackground=CARD).pack(side="left")
            tk.Label(row, text=hint, bg=CARD, fg=MUTED,
                     font=("Segoe UI", 8)).pack(side="left", padx=8)

        self._divider(content)

        # Space info
        zip_ok = ZIP_PATH.exists()
        size_str = f"{ZIP_PATH.stat().st_size / 1024 / 1024:.0f} MB" if zip_ok else "N/A"
        info_rows = [
            ("Required disk space:", "~600 MB (includes all dependencies)"),
            ("Archive size:",        size_str),
            ("Default login:",       "admin@aiss.local  /  Admin123!"),
        ]
        for k, v in info_rows:
            row = tk.Frame(content, bg=CARD)
            row.pack(fill="x", pady=1)
            tk.Label(row, text=k, bg=CARD, fg=MUTED, font=("Segoe UI", 8), width=20, anchor="w").pack(side="left")
            tk.Label(row, text=v, bg=CARD, fg=GREEN, font=("Segoe UI", 8, "bold")).pack(side="left")

        if not zip_ok:
            self._label(content, f"⚠  Archive not found: {ZIP_PATH.name} — place it in the same folder as this installer", 8, WARN)

        self._footer([
            ("Install →",  (self._start_install if zip_ok else self._warn_no_zip), GREEN),
            ("← Back",     self._show_license, BORDER),
            ("Cancel",     self._on_close, RED),
        ])

    def _browse_dir(self):
        d = filedialog.askdirectory(initialdir=self.install_dir.get(),
                                    title="Choose Installation Folder", parent=self)
        if d:
            self.install_dir.set(d)

    def _warn_no_zip(self):
        messagebox.showerror("Archive Missing",
            f"{ZIP_PATH.name} must be in the same folder as this installer.\n\n"
            f"Expected: {ZIP_PATH}", parent=self)

    # ══════════════════════════════════════════════════════════════════
    # PAGE 3 — INSTALLING
    # ══════════════════════════════════════════════════════════════════
    def _start_install(self):
        self._clear()
        self._header("Installing AISS", "Please wait while AISS is being installed...")

        body = self._body()
        self._step_bar(body, 3)

        content = tk.Frame(body, bg=CARD)
        content.pack(fill="both", expand=True, padx=20, pady=10)

        self._status_var = tk.StringVar(value="Preparing installation...")
        self._detail_var = tk.StringVar(value="")
        self._pct_var    = tk.StringVar(value="0%")

        tk.Label(content, textvariable=self._status_var, bg=CARD, fg=FG,
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(10,2))

        self._pb = self._progress_bar(content)

        pct_row = tk.Frame(content, bg=CARD)
        pct_row.pack(fill="x", padx=20)
        tk.Label(pct_row, textvariable=self._pct_var, bg=CARD, fg=GREEN,
                 font=("Courier New", 9, "bold")).pack(side="right")
        tk.Label(pct_row, textvariable=self._detail_var, bg=CARD, fg=MUTED,
                 font=("Courier New", 8)).pack(side="left")

        # Log box
        log_frame = tk.Frame(content, bg="#0a1410", bd=1, relief="flat")
        log_frame.pack(fill="both", expand=True, pady=(10,0))
        self._log = tk.Text(log_frame, bg="#0a1410", fg="#4a7c6f",
                            font=("Courier New", 8), relief="flat",
                            state="disabled", height=8, padx=8, pady=6)
        sb = tk.Scrollbar(log_frame, command=self._log.yview)
        self._log.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._log.pack(fill="both", expand=True)

        threading.Thread(target=self._do_install, daemon=True).start()

    def _log_line(self, msg):
        def _do():
            self._log.configure(state="normal")
            self._log.insert("end", f"  {msg}\n")
            self._log.see("end")
            self._log.configure(state="disabled")
        self.after(0, _do)

    def _set_progress(self, status, pct, detail=""):
        def _do():
            self._status_var.set(status)
            self._pb.configure(value=pct)
            self._pct_var.set(f"{pct}%")
            if detail:
                self._detail_var.set(detail[:70])
        self.after(0, _do)

    def _do_install(self):
        try:
            dest = Path(self.install_dir.get())
            dest.mkdir(parents=True, exist_ok=True)
            self._install_dest = dest

            # ── Step 1: Extract archive ──────────────────────────────
            self._set_progress("Extracting files...", 2, "Opening archive")
            self._log_line(f"Installing to: {dest}")
            self._log_line(f"Archive: {ZIP_PATH} ({ZIP_PATH.stat().st_size // 1024 // 1024} MB)")

            with zipfile.ZipFile(ZIP_PATH) as zf:
                members = zf.namelist()
                total   = len(members)
                self._log_line(f"Files to extract: {total}")
                for i, name in enumerate(members):
                    zf.extract(name, dest)
                    pct = 2 + int(i / total * 68)
                    if i % 20 == 0:
                        self._set_progress("Extracting files...", pct, name)
                        self._log_line(f"Extracted: {name}")

            self._log_line("Extraction complete.")

            # ── Step 2: Create .env if missing ───────────────────────
            self._set_progress("Configuring application...", 72)
            env_dest = dest / ".env"
            env_tmpl = dest / ".env.example"
            if not env_dest.exists() and env_tmpl.exists():
                shutil.copy(env_tmpl, env_dest)
                self._log_line("Created .env configuration file")

            # Create required directories
            for d in ["logs", "data", "data/models"]:
                (dest / d).mkdir(parents=True, exist_ok=True)
            self._log_line("Created application directories")

            # ── Step 3: Create shortcuts ──────────────────────────────
            self._set_progress("Creating shortcuts...", 80)
            self._log_line("Creating shortcuts...")
            self._create_all_shortcuts(dest)

            # ── Step 4: Register in Windows ───────────────────────────
            self._set_progress("Registering application...", 88)
            self._register_app(dest)
            self._log_line("Registered in Windows")

            # ── Step 5: Autostart ─────────────────────────────────────
            if self.autostart.get():
                self._set_progress("Configuring autostart...", 94)
                self._add_autostart(dest)
                self._log_line("Autostart configured")

            # ── Done ──────────────────────────────────────────────────
            self._set_progress("Installation complete!", 100, "All done")
            self._log_line("=" * 40)
            self._log_line("AISS installed successfully!")
            self._log_line(f"Location: {dest}")
            self._log_line("Login: admin@aiss.local / Admin123!")
            time.sleep(0.6)
            self.after(0, lambda: self._show_done(dest))

        except Exception as e:
            self._log_line(f"ERROR: {e}")
            self.after(0, lambda: messagebox.showerror(
                "Installation Failed", f"An error occurred:\n\n{e}\n\nCheck the log above.",
                parent=self))

    def _create_all_shortcuts(self, dest: Path):
        exe = dest / "AISS.exe"

        # ── Desktop shortcut ──────────────────────────────────────────
        if self.desktop_sc.get():
            desktop = Path(os.path.expanduser("~")) / "Desktop"
            if not desktop.exists():
                desktop = Path(os.environ.get("USERPROFILE", "~")) / "Desktop"
            self._make_vbs_shortcut(
                lnk=desktop / "AISS.lnk",
                target=str(exe),
                workdir=str(dest),
                desc="AISS — AI Integrated Security System",
                icon=str(exe),
            )
            self._log_line(f"Desktop shortcut: {desktop / 'AISS.lnk'}")

        # ── Start Menu ────────────────────────────────────────────────
        if self.startmenu_sc.get():
            try:
                appdata = Path(os.environ.get("APPDATA", ""))
                sm_dir  = appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "AISS"
                sm_dir.mkdir(parents=True, exist_ok=True)
                self._make_vbs_shortcut(
                    lnk=sm_dir / "AISS.lnk",
                    target=str(exe),
                    workdir=str(dest),
                    desc="AISS Security System",
                    icon=str(exe),
                )
                self._make_vbs_shortcut(
                    lnk=sm_dir / "Uninstall AISS.lnk",
                    target=str(dest / "Uninstall.exe"),
                    workdir=str(dest),
                    desc="Uninstall AISS",
                )
                self._log_line(f"Start Menu: {sm_dir}")
            except Exception as e:
                self._log_line(f"Start Menu skipped: {e}")

        # ── Uninstaller script ────────────────────────────────────────
        self._create_uninstaller(dest)

    def _make_vbs_shortcut(self, lnk, target, workdir="", desc="", icon=""):
        """Use VBScript to create a proper .lnk shortcut."""
        vbs = f"""
Set oWS = WScript.CreateObject("WScript.Shell")
Set oLink = oWS.CreateShortcut("{lnk}")
oLink.TargetPath = "{target}"
oLink.WorkingDirectory = "{workdir}"
oLink.Description = "{desc}"
oLink.IconLocation = "{icon if icon else target}"
oLink.Save
"""
        vbs_path = Path(os.environ.get("TEMP", "C:/Temp")) / "_aiss_sc.vbs"
        vbs_path.write_text(vbs, encoding="utf-8")
        try:
            subprocess.run(["cscript", "//nologo", str(vbs_path)],
                           capture_output=True, timeout=10)
        finally:
            vbs_path.unlink(missing_ok=True)

    def _create_uninstaller(self, dest: Path):
        script = f'''@echo off
title Uninstall AISS
echo Uninstalling AISS...
taskkill /F /IM AISS.exe /T >nul 2>&1
taskkill /F /IM node.exe /T >nul 2>&1
timeout /t 2 /nobreak >nul
rmdir /s /q "{dest}"
reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v AISS /f >nul 2>&1
reg delete "HKLM\\Software\\AISS" /f >nul 2>&1
del "%USERPROFILE%\\Desktop\\AISS.lnk" >nul 2>&1
rmdir /s /q "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\AISS" >nul 2>&1
echo AISS has been uninstalled.
pause
'''
        (dest / "Uninstall.bat").write_text(script, encoding="ascii", errors="replace")

    def _register_app(self, dest: Path):
        try:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"Software\AISS")
            winreg.SetValueEx(key, "InstallPath", 0, winreg.REG_SZ, str(dest))
            winreg.SetValueEx(key, "Version",     0, winreg.REG_SZ, VERSION)
            winreg.SetValueEx(key, "Publisher",   0, winreg.REG_SZ, PUBLISHER)
            winreg.CloseKey(key)
        except PermissionError:
            try:
                key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\AISS")
                winreg.SetValueEx(key, "InstallPath", 0, winreg.REG_SZ, str(dest))
                winreg.SetValueEx(key, "Version",     0, winreg.REG_SZ, VERSION)
                winreg.CloseKey(key)
            except Exception:
                pass

    def _add_autostart(self, dest: Path):
        try:
            exe = dest / "AISS.exe"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\Microsoft\Windows\CurrentVersion\Run",
                                 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "AISS", 0, winreg.REG_SZ, str(exe))
            winreg.CloseKey(key)
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════════════
    # PAGE 4 — DONE
    # ══════════════════════════════════════════════════════════════════
    def _show_done(self, dest: Path):
        self._clear()
        self._header("✓  Installation Complete!", "AISS is ready to use")

        body = self._body()
        self._step_bar(body, 4)

        content = tk.Frame(body, bg=CARD)
        content.pack(fill="both", expand=True, padx=24, pady=12)

        # Success icon area
        icon_row = tk.Frame(content, bg=CARD)
        icon_row.pack(fill="x", pady=(0, 10))
        tk.Label(icon_row, text="🛡", bg=CARD, fg=GREEN,
                 font=("Segoe UI", 32)).pack(side="left", padx=(0,14))
        info = tk.Frame(icon_row, bg=CARD)
        info.pack(side="left")
        tk.Label(info, text=f"{APP_FULL}", bg=CARD, fg=FG,
                 font=("Segoe UI", 12, "bold")).pack(anchor="w")
        tk.Label(info, text=f"Version {VERSION}  •  {PUBLISHER}  •  {YEAR}",
                 bg=CARD, fg=MUTED, font=("Segoe UI", 8)).pack(anchor="w")
        tk.Label(info, text=f"Installed to:  {dest}",
                 bg=CARD, fg=MUTED, font=("Segoe UI", 8)).pack(anchor="w")

        self._divider(content)

        # Login credentials
        tk.Label(content, text="Default Login Credentials:", bg=CARD, fg=FG,
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        cred_box = tk.Frame(content, bg="#0a1410", bd=0)
        cred_box.pack(fill="x", pady=6)
        for label, val in [("Email", "admin@aiss.local"), ("Password", "Admin123!")]:
            row = tk.Frame(cred_box, bg="#0a1410")
            row.pack(fill="x", padx=12, pady=3)
            tk.Label(row, text=f"{label}:", bg="#0a1410", fg=MUTED,
                     font=("Segoe UI", 9), width=10, anchor="w").pack(side="left")
            tk.Label(row, text=val, bg="#0a1410", fg=GREEN,
                     font=("Courier New", 10, "bold")).pack(side="left")

        tk.Label(content, text="⚠  Change your password after first login!",
                 bg=CARD, fg=WARN, font=("Segoe UI", 8)).pack(anchor="w", pady=(4,0))

        self._divider(content)

        # How to start
        tk.Label(content, text="How to start AISS:", bg=CARD, fg=FG,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        for line in [
            "•  Double-click the AISS icon on your Desktop",
            "•  Or run  AISS.exe  from the install folder",
            "•  The dashboard will open in your browser automatically",
        ]:
            tk.Label(content, text=line, bg=CARD, fg=MUTED,
                     font=("Segoe UI", 8)).pack(anchor="w", padx=6)

        # Launch checkbox
        cb_row = tk.Frame(content, bg=CARD)
        cb_row.pack(fill="x", pady=(10,0))
        tk.Checkbutton(cb_row, text="  Launch AISS now",
                       variable=self.launch_after, bg=CARD, fg=FG,
                       selectcolor="#0a1410", font=("Segoe UI", 9, "bold"),
                       cursor="hand2", activebackground=CARD).pack(anchor="w")

        self._footer([("Finish", lambda: self._finish(dest), GREEN)])

    def _finish(self, dest: Path):
        if self.launch_after.get():
            exe = dest / "AISS.exe"
            if exe.exists():
                subprocess.Popen([str(exe)], cwd=str(dest),
                                 creationflags=subprocess.DETACHED_PROCESS)
                time.sleep(0.5)
        self.destroy()

    # ══════════════════════════════════════════════════════════════════
    # STEP INDICATOR BAR
    # ══════════════════════════════════════════════════════════════════
    def _step_bar(self, parent, current: int):
        steps = ["License", "Options", "Installing", "Done"]
        bar = tk.Frame(parent, bg=DARK, height=36)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        inner = tk.Frame(bar, bg=DARK)
        inner.pack(expand=True, fill="both")
        for i, name in enumerate(steps, 1):
            col = GREEN if i == current else (FG if i < current else MUTED)
            weight = "bold" if i == current else "normal"
            dot = "●" if i == current else ("✓" if i < current else "○")
            tk.Label(inner, text=f"{dot} {i}. {name}", bg=DARK, fg=col,
                     font=("Segoe UI", 8, weight)).pack(side="left", padx=18, pady=8)
            if i < len(steps):
                tk.Label(inner, text="──", bg=DARK, fg=BORDER,
                         font=("Segoe UI", 8)).pack(side="left")


# ── Entry point ────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Request admin if not already (for writing to Program Files)
    if sys.platform == "win32" and not ctypes.windll.shell32.IsUserAnAdmin():
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        except Exception:
            pass
        sys.exit(0)
    InstallerApp()
