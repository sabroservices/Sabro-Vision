@echo off
title SABRO VISION 24/7 Server
color 0B
echo =======================================================
echo              SABRO VISION SERVER LAUNCHER              
echo       Powered by Sabro Networks Fiber Internet          
echo =======================================================
echo.

cd /d "%~dp0"

:: ---------------------------------------------------------
:: CONFIGURATION: Change PORT here if needed (e.g. 8080, 8000, 5050)
set PORT=8080
:: ---------------------------------------------------------

:: Check if Python is installed
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python 3 was not detected in system PATH.
    echo Please install Python 3.10+ from python.org and check 'Add Python to PATH'.
    pause
    exit /b 1
)

echo [+] Checking environment dependencies...
python -m pip install -r requirements.txt --quiet

echo.
echo [+] Starting Sabro Vision Server on Port %PORT%...
echo [+] Local Web Player: http://127.0.0.1:%PORT%
echo [+] Admin Control:    http://127.0.0.1:%PORT%/admin
echo.

python run.py --port %PORT% --open

pause
