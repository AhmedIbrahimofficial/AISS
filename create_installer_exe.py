"""
AISS Self-Extracting Installer Creator
Creates a single AISS_Setup.exe that:
1. Shows a GUI install wizard
2. Extracts all files to chosen directory
3. Creates desktop shortcut
4. Launches AISS after install

Run: python create_installer_exe.py
"""

import os
import sys
import zipfile
import struct
import shutil
from pathlib import Path

BASE    = Path(__file__).parent
DIST    = BASE / "aiss backend" / "dist" / "AISS"
ZIP_SRC = BASE / "installer" / "output" / "AISS_v2.0_Windows_Portable.zip"
OUTPUT  = BASE / "installer" / "output"

STUB_CODE = '''
import os, sys, zipfile, shutil, threading, tempfile, subprocess, winreg
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

INSTALL_DIR_DEFAULT = Path(os.environ.get("PROGRAMFILES", "C:\\\\Program Files")) / "AISS"
VERSION = "2.0.0"
APP_NAME = "AISS - AI Integrated Security System"

class InstallerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title(f"{APP_NAME} Setup")
        self.root.geometry("520x420")
        self.root.resizable(False, False)
        self.root.configure(bg="#0d1a15")
        try:
            self.root.iconbitmap(default="")
        except Exception:
            pass

        self.install_dir = tk.StringVar(value=str(INSTALL_DIR_DEFAULT))
        self.desktop_sc  = tk.BooleanVar(value=True)
        self.autostart   = tk.BooleanVar(value=False)
        self.page = 0
        self._build_welcome()
        self.root.mainloop()

    def _clear(self):
        for w in self.root.winfo_children():
            w.destroy()

    def _label(self, parent, text, size=10, color="#e6edea", bold=False, pady=4):
        font = ("Courier New" if bold else "Segoe UI", size, "bold" if bold else "normal")
        tk.Label(parent, text=text, bg="#0d1a15", fg=color,
                 font=font, wraplength=460, justify="left").pack(anchor="w", pady=pady, padx=20)

    def _btn(self, parent, text, cmd, color="#10b981", side="right"):
        tk.Button(parent, text=text, command=cmd, bg=color, fg="white",
                  font=("Segoe UI", 10, "bold"), relief="flat",
                  padx=20, pady=8, cursor="hand2").pack(side=side, padx=8, pady=8)

    def _build_welcome(self):
        self._clear()
        # Header
        hdr = tk.Frame(self.root, bg="#0a1410", height=90)
        hdr.pack(fill="x")
        tk.Label(hdr, text="🛡  AISS", bg="#0a1410", fg="#10b981",
                 font=("Courier New", 22, "bold")).pack(pady=(15,2))
        tk.Label(hdr, text="AI Integrated Security System", bg="#0a1410", fg="#7c8c85",
                 font=("Segoe UI", 9)).pack()

        body = tk.Frame(self.root, bg="#0d1a15")
        body.pack(fill="both", expand=True, padx=20, pady=10)

        self._label(body, f"Welcome to {APP_NAME} v{VERSION} Setup", 12, "#e6edea", True)
        self._label(body, "This will install AISS on your computer.", 9, "#7c8c85")
        self._label(body, "\\n• AI-powered threat detection and response", 9)
        self._label(body, "• Real-time network monitoring", 9)
        self._label(body, "• SOC dashboard with 30+ security features", 9)
        self._label(body, "• Remote agent support (multi-computer)", 9)
        self._label(body, "\\nClick Next to continue.", 9, "#7c8c85")

        footer = tk.Frame(self.root, bg="#060e0b", height=50)
        footer.pack(fill="x", side="bottom")
        self._btn(footer, "Next →", self._build_options)
        self._btn(footer, "Cancel", self.root.destroy, "#dc2626")

    def _build_options(self):
        self._clear()
        hdr = tk.Frame(self.root, bg="#0a1410", height=60)
        hdr.pack(fill="x")
        tk.Label(hdr, text="Installation Options", bg="#0a1410", fg="#e6edea",
                 font=("Segoe UI", 13, "bold")).pack(pady=15)

        body = tk.Frame(self.root, bg="#0d1a15")
        body.pack(fill="both", expand=True, padx=20, pady=10)

        self._label(body, "Install location:", 9, "#7c8c85")
        dir_frame = tk.Frame(body, bg="#0d1a15")
        dir_frame.pack(fill="x", pady=(0,10))
        tk.Entry(dir_frame, textvariable=self.install_dir, bg="#0a1410", fg="#e6edea",
                 font=("Courier New", 9), relief="flat", bd=1,
                 insertbackground="#10b981", width=44).pack(side="left", padx=(0,6), ipady=6)
        tk.Button(dir_frame, text="Browse", command=self._browse,
                  bg="#1a2e25", fg="#10b981", relief="flat", padx=8, pady=4).pack(side="left")

        tk.Checkbutton(body, text=" Create Desktop Shortcut",
                       variable=self.desktop_sc, bg="#0d1a15", fg="#e6edea",
                       selectcolor="#0a1410", activebackground="#0d1a15",
                       font=("Segoe UI", 9)).pack(anchor="w", pady=2)
        tk.Checkbutton(body, text=" Start AISS automatically with Windows",
                       variable=self.autostart, bg="#0d1a15", fg="#e6edea",
                       selectcolor="#0a1410", activebackground="#0d1a15",
                       font=("Segoe UI", 9)).pack(anchor="w", pady=2)

        req_space = "~500 MB"
        self._label(body, f"Required disk space: {req_space}", 8, "#7c8c85")
        self._label(body, "Default login: admin@aiss.local / Admin123!", 8, "#10b981")

        footer = tk.Frame(self.root, bg="#060e0b", height=50)
        footer.pack(fill="x", side="bottom")
        self._btn(footer, "Install", self._start_install)
        self._btn(footer, "← Back", self._build_welcome, "#1a2e25")

    def _browse(self):
        d = filedialog.askdirectory(initialdir=self.install_dir.get())
        if d:
            self.install_dir.set(d)

    def _start_install(self):
        self._clear()
        hdr = tk.Frame(self.root, bg="#0a1410", height=60)
        hdr.pack(fill="x")
        tk.Label(hdr, text="Installing AISS...", bg="#0a1410", fg="#e6edea",
                 font=("Segoe UI", 13, "bold")).pack(pady=15)

        body = tk.Frame(self.root, bg="#0d1a15")
        body.pack(fill="both", expand=True, padx=20, pady=20)

        self.status_var = tk.StringVar(value="Preparing...")
        tk.Label(body, textvariable=self.status_var, bg="#0d1a15", fg="#7c8c85",
                 font=("Segoe UI", 9)).pack(anchor="w")

        self.progress = ttk.Progressbar(body, mode="determinate", length=440)
        self.progress.pack(pady=10)

        self.detail_var = tk.StringVar(value="")
        tk.Label(body, textvariable=self.detail_var, bg="#0d1a15", fg="#7c8c85",
                 font=("Courier New", 8), wraplength=440).pack(anchor="w")

        threading.Thread(target=self._do_install, daemon=True).start()

    def _do_install(self):
        try:
            dest = Path(self.install_dir.get())
            dest.mkdir(parents=True, exist_ok=True)

            # Find embedded zip
            exe_path = Path(sys.executable if getattr(sys,"frozen",False) else __file__)
            zip_data = None

            # If frozen, zip is appended to exe
            if getattr(sys, "frozen", False):
                with open(exe_path, "rb") as f:
                    data = f.read()
                # Find ZIP signature
                zip_sig = b"PK\\x03\\x04"
                idx = data.rfind(zip_sig)
                if idx >= 0:
                    import io
                    zip_data = io.BytesIO(data[idx:])

            if zip_data is None:
                # Fallback: look for zip next to exe
                for candidate in [
                    exe_path.parent / "AISS_v2.0_Windows_Portable.zip",
                    Path("installer/output/AISS_v2.0_Windows_Portable.zip"),
                ]:
                    if candidate.exists():
                        zip_data = open(candidate, "rb")
                        break

            if zip_data is None:
                self._update("ERROR: Installation archive not found", 0)
                return

            self._update("Extracting files...", 10)
            with zipfile.ZipFile(zip_data) as zf:
                names = zf.namelist()
                total = len(names)
                for i, name in enumerate(names):
                    zf.extract(name, dest)
                    pct = 10 + int((i / total) * 75)
                    self._update(f"Extracting: {Path(name).name}", pct)

            self._update("Creating shortcuts...", 87)
            self._create_shortcuts(dest)

            if self.autostart.get():
                self._update("Setting up autostart...", 93)
                self._add_autostart(dest)

            self._update("Finalizing...", 97)
            # Create logs dir
            (dest / "logs").mkdir(exist_ok=True)

            self._update("Complete!", 100)
            self.root.after(500, lambda: self._build_done(dest))

        except Exception as e:
            self._update(f"ERROR: {e}", 0)
            messagebox.showerror("Install Error", str(e))

    def _update(self, msg: str, pct: int):
        self.root.after(0, lambda: (
            self.status_var.set(msg),
            self.detail_var.set(msg),
            self.progress.configure(value=pct),
        ))

    def _create_shortcuts(self, dest: Path):
        try:
            import winshell  # type: ignore
            exe = dest / "AISS.exe"
            if self.desktop_sc.get():
                desktop = Path(winshell.desktop())
                lnk = desktop / "AISS.lnk"
                with winshell.shortcut(str(lnk)) as s:
                    s.path = str(exe)
                    s.working_directory = str(dest)
                    s.description = "AI Integrated Security System"
        except ImportError:
            # Fallback: create .bat shortcut on desktop
            if self.desktop_sc.get():
                import ctypes
                buf = ctypes.create_unicode_buffer(300)
                ctypes.windll.shell32.SHGetFolderPathW(0, 0, 0, 0, buf)
                desktop = Path(buf.value) / "Desktop"
                bat = desktop / "Launch AISS.bat"
                bat.write_text(f'@echo off\\ncd /d "{dest}"\\nstart "" "AISS.exe"\\n')
        except Exception:
            pass

    def _add_autostart(self, dest: Path):
        try:
            exe = dest / "AISS.exe"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                                 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "AISS", 0, winreg.REG_SZ, str(exe))
            winreg.CloseKey(key)
        except Exception:
            pass

    def _build_done(self, dest: Path):
        self._clear()
        hdr = tk.Frame(self.root, bg="#0a1410", height=60)
        hdr.pack(fill="x")
        tk.Label(hdr, text="✓ Installation Complete!", bg="#0a1410", fg="#10b981",
                 font=("Segoe UI", 13, "bold")).pack(pady=15)

        body = tk.Frame(self.root, bg="#0d1a15")
        body.pack(fill="both", expand=True, padx=20, pady=10)
        self._label(body, f"AISS has been installed to:\\n{dest}", 9)
        self._label(body, "\\nTo start AISS:", 9, "#7c8c85")
        self._label(body, f"  • Double-click AISS.exe in the install folder", 9)
        self._label(body, f"  • Or use the Desktop shortcut", 9)
        self._label(body, "\\nDefault login:", 9, "#7c8c85")
        self._label(body, "  Email:    admin@aiss.local", 9, "#10b981")
        self._label(body, "  Password: Admin123!", 9, "#10b981")
        self._label(body, "\\n⚠ Change your password after first login!", 8, "#f59e0b")

        self.launch_var = tk.BooleanVar(value=True)
        tk.Checkbutton(body, text=" Launch AISS now",
                       variable=self.launch_var, bg="#0d1a15", fg="#e6edea",
                       selectcolor="#0a1410", font=("Segoe UI", 9)).pack(anchor="w", pady=6)

        footer = tk.Frame(self.root, bg="#060e0b", height=50)
        footer.pack(fill="x", side="bottom")
        self._btn(footer, "Finish", lambda: self._finish(dest))

    def _finish(self, dest: Path):
        if self.launch_var.get():
            exe = dest / "AISS.exe"
            if exe.exists():
                subprocess.Popen([str(exe)], cwd=str(dest))
        self.root.destroy()

InstallerGUI()
'''

def create_installer_exe():
    print("Creating AISS_Setup.exe installer...")
    
    # Build the stub script into an exe using PyInstaller
    stub_file = OUTPUT / "_installer_stub.py"
    stub_file.write_text(STUB_CODE, encoding="utf-8")
    
    python = str(BASE / "aiss backend" / ".venv" / "Scripts" / "python.exe")
    pyinst  = str(BASE / "aiss backend" / ".venv" / "Scripts" / "pyinstaller.exe")
    
    # Build the installer stub
    import subprocess
    result = subprocess.run([
        pyinst,
        "--noconfirm", "--clean", "--onefile",
        "--name", "AISS_Setup",
        "--windowed",  # No console window for installer
        "--distpath", str(OUTPUT),
        "--workpath", str(OUTPUT / "_build"),
        "--specpath", str(OUTPUT),
        "--add-data", f"{ZIP_SRC};.",  # Embed the zip
        str(stub_file),
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        print("PyInstaller error:", result.stderr[-2000:])
        return False
    
    setup_exe = OUTPUT / "AISS_Setup.exe"
    if setup_exe.exists():
        size_mb = round(setup_exe.stat().st_size / 1024 / 1024, 1)
        print(f"\n✅ AISS_Setup.exe created: {size_mb} MB")
        print(f"   Location: {setup_exe}")
        return True
    return False


if __name__ == "__main__":
    OUTPUT.mkdir(parents=True, exist_ok=True)
    
    if not DIST.exists():
        print("ERROR: dist folder not found. Run build first.")
        print(f"Expected: {DIST}")
        sys.exit(1)
    
    if not ZIP_SRC.exists():
        print("ERROR: ZIP not found. Run build_portable.ps1 first.")
        sys.exit(1)
    
    success = create_installer_exe()
    if success:
        print("\n🎉 Done! Upload installer/output/AISS_Setup.exe to your website.")
    else:
        print("\n⚠  Falling back to ZIP distribution.")
        print(f"   ZIP: {ZIP_SRC}")
