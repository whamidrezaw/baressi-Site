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
