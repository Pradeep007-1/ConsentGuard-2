@echo off
set LOCAL_MODE=1
set OFFLINE_MODE=1
cd /d "%~dp0"
if exist ".venv\Scripts\activate.bat" (
    call ".venv\Scripts\activate.bat"
) else if exist "backend\.venv\Scripts\activate.bat" (
    call "backend\.venv\Scripts\activate.bat"
)
python app.py
pause
