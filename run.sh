#!/usr/bin/env bash
set -e

echo "============================================================"
echo "  CONSENTGUARD: ENTERPRISE PURPOSE-BASED CONSENT ENGINE"
echo "  Local Hackathon Execution and Server Launcher"
echo "============================================================"

# 1. Verify Python Installation
if ! command -v python3 &> /dev/null; then
    echo "[!] Error: python3 is not detected in PATH."
    exit 1
fi

# 2. Initialize and Seed Database
echo "[*] Initializing database schema, immutability triggers, and seeds..."
python3 seed.py

# 3. Run Self-Diagnostic Smoke Test
echo "[*] Running automated verification test suite..."
if python3 -m pytest tests/test_enterprise_suite.py -q; then
    echo "[+] All enterprise integrity and authorization tests passed successfully."
else
    echo "[!] Warning: Some tests reported issues."
fi

# 4. Launch Backend API Server
echo "============================================================"
echo "  ConsentGuard Backend running at: http://localhost:5001"
echo "  Dashboard available at: http://localhost:5001/"
echo "  Press CTRL+C to stop."
echo "============================================================"
python3 backend/api.py
