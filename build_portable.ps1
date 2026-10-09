# AISS Portable Build Script (PowerShell)
# Creates a portable ZIP that runs without installation
# Usage: .\build_portable.ps1

$ErrorActionPreference = "Stop"
$ROOT     = $PSScriptRoot
$BACKEND  = "$ROOT\backend"
$FRONTEND = "$ROOT\frontend"
$OUTPUT   = "$ROOT\installer\output"
$PYTHON   = "$BACKEND\.venv\Scripts\python.exe"
$PIP      = "$BACKEND\.venv\Scripts\pip.exe"
$PYINST   = "$BACKEND\.venv\Scripts\pyinstaller.exe"

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  AISS Portable Builder                               ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""

# ── Step 1: Build frontend ────────────────────────────────────────────
Write-Host "[1/5] Building frontend..." -ForegroundColor Cyan
Set-Location $FRONTEND
npm run build
Write-Host "  ✓ Frontend built" -ForegroundColor Green

# ── Step 2: Install PyInstaller ───────────────────────────────────────
Write-Host "[2/5] Installing PyInstaller..." -ForegroundColor Cyan
& $PIP install pyinstaller --quiet
Write-Host "  ✓ PyInstaller ready" -ForegroundColor Green

# ── Step 3: Build backend exe ─────────────────────────────────────────
Write-Host "[3/5] Building backend exe (this takes 5-10 min)..." -ForegroundColor Cyan
Set-Location $BACKEND

$pyinstallerArgs = @(
    "--noconfirm", "--clean",
    "--distpath", "$BACKEND\dist",
    "--workpath", "$BACKEND\build",
    "--name", "AISS",
    "--console",
    "--add-data", "rules;rules",
    "--add-data", "static;static",
    "--add-data", "alembic;alembic",
    "--add-data", "alembic.ini;.",
    "--add-data", "data;data",
    "--hidden-import", "uvicorn.logging",
    "--hidden-import", "uvicorn.loops.auto",
    "--hidden-import", "uvicorn.protocols.http.auto",
    "--hidden-import", "uvicorn.protocols.websockets.auto",
    "--hidden-import", "uvicorn.lifespan.on",
    "--hidden-import", "sqlalchemy.dialects.sqlite",
    "--hidden-import", "aiosqlite",
    "--hidden-import", "passlib.handlers.bcrypt",
    "--hidden-import", "passlib.handlers.argon2",
    "--hidden-import", "jose.jwt",
    "--hidden-import", "anyio._backends._asyncio",
    "--hidden-import", "psutil",
    "--exclude-module", "torch",
    "--exclude-module", "transformers",
    "--exclude-module", "matplotlib",
    "aiss_launcher.py"
)

& $PYINST @pyinstallerArgs
Write-Host "  ✓ Backend exe built → dist\AISS\" -ForegroundColor Green

# ── Step 4: Bundle frontend + node into dist ──────────────────────────
Write-Host "[4/5] Bundling frontend + Node.js..." -ForegroundColor Cyan

$distDir = "$BACKEND\dist\AISS"
New-Item -ItemType Directory -Force -Path "$distDir\frontend\.output" | Out-Null
Copy-Item -Recurse -Force "$FRONTEND\.output\*" "$distDir\frontend\.output\"

# Copy node.exe
$nodeExe = (Get-Command node -ErrorAction SilentlyContinue)?.Source
if ($nodeExe -and (Test-Path $nodeExe)) {
    New-Item -ItemType Directory -Force -Path "$distDir\node" | Out-Null
    Copy-Item $nodeExe "$distDir\node\node.exe"
    Write-Host "  ✓ node.exe bundled from $nodeExe" -ForegroundColor Green
} else {
    Write-Host "  ⚠ node.exe not found — frontend will not start in portable mode" -ForegroundColor Yellow
}

# Copy .env template
if (Test-Path "$BACKEND\.env.example") {
    Copy-Item "$BACKEND\.env.example" "$distDir\.env.example"
}
if (Test-Path "$BACKEND\.env") {
    Copy-Item "$BACKEND\.env" "$distDir\.env"
}

# Create launch script in dist
@"
@echo off
title AISS - AI Security System
cd /d "%~dp0"
AISS.exe
"@ | Out-File -FilePath "$distDir\Launch AISS.bat" -Encoding ASCII

Write-Host "  ✓ Bundle ready at: dist\AISS\" -ForegroundColor Green

# ── Step 5: Create ZIP ────────────────────────────────────────────────
Write-Host "[5/5] Creating portable ZIP..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $OUTPUT | Out-Null

$zipPath = "$OUTPUT\AISS_v2.0_Windows_Portable.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath }

Compress-Archive -Path "$distDir\*" -DestinationPath $zipPath
$sizeMB = [math]::Round((Get-Item $zipPath).Length / 1MB, 1)

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  BUILD COMPLETE!                                     ║" -ForegroundColor Green
Write-Host "╠══════════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "║  ZIP: installer\output\AISS_v2.0_Windows_Portable.zip" -ForegroundColor White
Write-Host "║  Size: $sizeMB MB" -ForegroundColor White
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "To create a proper .exe installer:" -ForegroundColor Yellow
Write-Host "  1. Install Inno Setup: https://jrsoftware.org/isdl.php" -ForegroundColor White
Write-Host "  2. Run: build_installer.bat" -ForegroundColor White
Write-Host ""
