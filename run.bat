@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo   CONSENTGUARD: ENTERPRISE PURPOSE-BASED CONSENT ENGINE
echo   Local Hackathon Execution and Server Launcher
echo ============================================================

:: 1. Verify Python Installation
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [!] Error: Python is not detected in PATH.
    echo     Please install Python 3.10+ and re-run.
    exit /b 1
)

:: 2. Initialize and Seed Database
echo [*] Initializing database schema, immutability triggers, and seeds...
python seed.py
if %ERRORLEVEL% neq 0 (
    echo [!] Error: Failed to seed database.
    exit /b 1
)

:: 3. Run Self-Diagnostic Smoke Test
echo [*] Running automated verification test suite...
python -m pytest tests/test_enterprise_suite.py -q
if %ERRORLEVEL% neq 0 (
    echo [!] Warning: Some automated tests encountered issues. Review test logs.
) else (
    echo [+] All enterprise integrity and authorization tests passed successfully.
)

:: 4. Launch Backend API Server
echo ============================================================
echo   ConsentGuard Backend is running at: http://localhost:5001
echo   Dashboard available at: http://localhost:5001/
echo   Press CTRL+C to terminate the server.
echo ============================================================
python backend/api.py

endlocal
