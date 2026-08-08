# AISS Windows Installer Builder

## Quick Build (Portable ZIP)

```powershell
# From d:\aiss directory:
.\build_portable.ps1
```

Output: `installer\output\AISS_v2.0_Windows_Portable.zip`

## Full Installer (.exe Setup)

1. Install [Inno Setup 6](https://jrsoftware.org/isdl.php)
2. Run `build_installer.bat`

Output: `installer\output\AISS_Setup_v2.0.0_Windows.exe`

## What gets bundled

| Component | Description |
|---|---|
| `AISS.exe` | Python backend (FastAPI + all modules) |
| `frontend/.output/` | React dashboard (pre-built) |
| `node/node.exe` | Node.js runtime for frontend |
| `rules/` | YARA + Sigma detection rules |
| `data/` | ML model patterns |
| `static/` | Static assets |
| `.env` | Configuration file |

## User Instructions (after install)

1. Run `AISS.exe` or double-click `Launch AISS.bat`
2. Browser opens automatically at `http://localhost:8081`
3. Login: `admin@aiss.local` / `Admin123!`
4. Change password in Settings

## Website Download Button

Upload `AISS_Setup_v2.0.0_Windows.exe` to your hosting.
Link your download button to the file URL.
