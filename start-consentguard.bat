@echo off
setlocal enabledelayedexpansion

title ConsentGuard - Offline Server Launcher
color 0A

:: ------------------------------------------------------------
:: 1. Force 100%% Offline Local Mode (Blocks any cloud database)
:: ------------------------------------------------------------
set LOCAL_MODE=1
set OFFLINE_MODE=1
set DATABASE_URL=
set POSTGRES_URL=
set NEON_DATABASE_URL=
set ADMIN_KEY=cg_admin_offline_key_2026
set FLASK_ENV=production

cd /d "%~dp0"

echo ============================================================================
echo   CONSENTGUARD - PRIVACY-FIRST ENTERPRISE CONSENT ENGINE
echo   Hackathon Offline 1-Click Startup Launcher
echo ============================================================================
echo [*] Mode: 100%% Local Offline Sandbox (Zero Cloud Dependencies)
echo [*] Database: Local SQLite with Cryptographic Immutability Triggers
echo.

:: ------------------------------------------------------------
:: 2. Python Environment Detection & Virtual Environment Activation
:: ------------------------------------------------------------
if exist ".venv\Scripts\activate.bat" (
    echo [*] Activating virtual environment (.venv)...
    call ".venv\Scripts\activate.bat"
) else if exist "backend\.venv\Scripts\activate.bat" (
    echo [*] Activating virtual environment (backend\.venv)...
    call "backend\.venv\Scripts\activate.bat"
) else if exist "venv\Scripts\activate.bat" (
    echo [*] Activating virtual environment (venv)...
    call "venv\Scripts\activate.bat"
)

where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] Python is not installed or not found in system PATH!
    echo ============================================================================
    echo Please install Python 3.10+ from https://www.python.org/
    echo Make sure to check the option "Add Python to PATH" during installation.
    echo ============================================================================
    echo.
    pause
    exit /b 1
)

:: ------------------------------------------------------------
:: 3. Dependency Validation with Understandable Error Messages
:: ------------------------------------------------------------
echo [*] Validating required Python packages...
python -c "import flask, flask_cors, itsdangerous, sqlite3" >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] Required Python dependencies are missing!
    echo ============================================================================
    echo Missing one or more required libraries: Flask, flask-cors, itsdangerous.
    echo.
    echo To install all required dependencies offline/online, run:
    echo     pip install -r requirements.txt
    echo.
    echo Or if using an existing virtual environment:
    echo     call .venv\Scripts\activate.bat
    echo ============================================================================
    echo.
    pause
    exit /b 1
)
echo [+] All core dependencies validated successfully.

:: ------------------------------------------------------------
:: 4. Initialize Local Database and Seed Synthetic Demo Data
:: ------------------------------------------------------------
echo.
echo [*] Initializing local database and seeding synthetic data...
python seed.py
if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] Failed to initialize local SQLite database.
    pause
    exit /b 1
)

:: ------------------------------------------------------------
:: 5. Display Local Server Address & Operating Credentials
:: ------------------------------------------------------------
echo.
echo ============================================================================
echo   CONSENTGUARD IS RUNNING AND READY FOR EVALUATION
echo ============================================================================
echo   Local Server Address:   http://localhost:5001
echo   Web Application / UI:   http://localhost:5001/
echo   Dashboard UI:           http://localhost:5001/dashboard
echo   Health Diagnostics:     http://localhost:5001/api/health
echo   Live Demo Script:       python run_demo.py
echo.
echo   DEMO CREDENTIALS:
echo   - Regular User:         demo@consentguard.local   (Password: demo123)
echo   - Security Admin:       admin@consentguard.local  (Password: AdminPass123!)
echo   - Secondary User:       user@consentguard.local   (Password: UserPass123!)
echo.
echo   DOWNSTREAM CONSUMER API KEYS:
echo   - Partner-All:          key_partner_all_enterprise
echo   - Partner-Limited:      key_partner_limited_research
echo.
echo   SHUTDOWN INSTRUCTIONS:
echo   - Press CTRL+C in this console window to gracefully stop the server.
echo ============================================================================
echo.

:: ------------------------------------------------------------
:: 6. Launch Flask Server
:: ------------------------------------------------------------
python app.py

pause
endlocal
