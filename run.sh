#!/usr/bin/env bash
set -e

# ------------------------------------------------------------
# 1. Force 100% Offline Local Mode (Blocks any cloud database)
# ------------------------------------------------------------
export LOCAL_MODE=1
export OFFLINE_MODE=1
unset DATABASE_URL
unset POSTGRES_URL
unset NEON_DATABASE_URL
export ADMIN_KEY="cg_admin_offline_key_2026"
export FLASK_ENV="production"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================================================"
echo "  CONSENTGUARD - PRIVACY-FIRST ENTERPRISE CONSENT ENGINE"
echo "  Hackathon Offline Startup Launcher"
echo "============================================================================"
echo "[*] Mode: 100% Local Offline Sandbox (Zero Cloud Dependencies)"
echo "[*] Database: Local SQLite with Cryptographic Immutability Triggers"
echo ""

# ------------------------------------------------------------
# 2. Python Environment Detection & Virtual Environment Activation
# ------------------------------------------------------------
if [ -f ".venv/bin/activate" ]; then
    echo "[*] Activating virtual environment (.venv)..."
    source ".venv/bin/activate"
elif [ -f "backend/.venv/bin/activate" ]; then
    echo "[*] Activating virtual environment (backend/.venv)..."
    source "backend/.venv/bin/activate"
elif [ -f "venv/bin/activate" ]; then
    echo "[*] Activating virtual environment (venv)..."
    source "venv/bin/activate"
fi

PYTHON_CMD="python3"
if ! command -v python3 &> /dev/null; then
    if command -v python &> /dev/null; then
        PYTHON_CMD="python"
    else
        echo ""
        echo "[ERROR] Python 3 is not installed or not found in system PATH!"
        echo "============================================================================"
        echo "Please install Python 3.10+ from https://www.python.org/"
        echo "============================================================================"
        echo ""
        exit 1
    fi
fi

# ------------------------------------------------------------
# 3. Dependency Validation with Understandable Error Messages
# ------------------------------------------------------------
echo "[*] Validating required Python packages..."
if ! $PYTHON_CMD -c "import flask, flask_cors, itsdangerous, sqlite3" &> /dev/null; then
    echo ""
    echo "[ERROR] Required Python dependencies are missing!"
    echo "============================================================================"
    echo "Missing one or more required libraries: Flask, flask-cors, itsdangerous."
    echo ""
    echo "To install all required dependencies offline/online, run:"
    echo "    pip install -r requirements.txt"
    echo "============================================================================"
    echo ""
    exit 1
fi
echo "[+] All core dependencies validated successfully."

# ------------------------------------------------------------
# 4. Initialize Local Database and Seed Synthetic Demo Data
# ------------------------------------------------------------
echo ""
echo "[*] Initializing local database and seeding synthetic data..."
$PYTHON_CMD seed.py

# ------------------------------------------------------------
# 5. Display Local Server Address & Operating Credentials
# ------------------------------------------------------------
echo ""
echo "============================================================================"
echo "  CONSENTGUARD IS RUNNING AND READY FOR EVALUATION"
echo "============================================================================"
echo "  Local Server Address:   http://localhost:5001"
echo "  Web Application / UI:   http://localhost:5001/"
echo "  Dashboard UI:           http://localhost:5001/dashboard"
echo "  Health Diagnostics:     http://localhost:5001/api/health"
echo "  Live Demo Script:       $PYTHON_CMD run_demo.py"
echo ""
echo "  DEMO CREDENTIALS:"
echo "  - Regular User:         demo@consentguard.local   (Password: demo123)"
echo "  - Security Admin:       admin@consentguard.local  (Password: AdminPass123!)"
echo "  - Secondary User:       user@consentguard.local   (Password: UserPass123!)"
echo ""
echo "  DOWNSTREAM CONSUMER API KEYS:"
echo "  - Partner-All:          key_partner_all_enterprise"
echo "  - Partner-Limited:      key_partner_limited_research"
echo ""
echo "  SHUTDOWN INSTRUCTIONS:"
echo "  - Press CTRL+C in this console window to gracefully stop the server."
echo "============================================================================"
echo ""

# ------------------------------------------------------------
# 6. Launch Flask Server
# ------------------------------------------------------------
$PYTHON_CMD app.py
