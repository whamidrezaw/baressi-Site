#!/usr/bin/env bash
# Make a complete distributable tarball of the current project.
set -euo pipefail

APP_DIR="/opt/monitor"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="/tmp/monitor-full-$STAMP.tar"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Recreate run_windows.bat (not on the server)
cat > "$TMP/run_windows.bat" << 'BAT_EOF'
@echo off
rem Windows helper: creates the virtual environment on first use, then runs monitor_system.py.
rem   run_windows.bat                 start monitoring
rem   run_windows.bat inspect URL     analyse a page
rem   run_windows.bat once --dry-run  check everything once, print instead of sending
chcp 65001 >nul
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo Creating the Python virtual environment...
    py -3 -m venv .venv 2>nul || python -m venv .venv
    if errorlevel 1 (
        echo Python 3.10+ is required: https://www.python.org/downloads/
        pause
        exit /b 1
    )
    ".venv\Scripts\python.exe" -m pip install --upgrade pip
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt
)
".venv\Scripts\python.exe" monitor_system.py %*
if "%~1"=="" pause
BAT_EOF

# Build an UNCOMPRESSED tar first
tar -cf "$OUT" \
  -C "$APP_DIR" \
  --exclude='data' \
  --exclude='venv' \
  --exclude='.cache' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --exclude='*.log' \
  --exclude='.venv' \
  --transform 's,^,monitor/,' \
  webmonitor monitor_system.py requirements.txt README.md tests deploy monitor-config.json

# Add run_windows.bat to the same uncompressed tar
tar -rf "$OUT" -C "$TMP" --transform 's,^,monitor/,' run_windows.bat

# Now gzip
gzip -f "$OUT"
OUT="${OUT}.gz"

echo "==> Bundle: $OUT"
echo "==> Size:   $(du -h "$OUT" | cut -f1)"
echo ""
echo "==> Contents:"
tar -tzf "$OUT" | sort
