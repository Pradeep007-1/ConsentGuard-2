#!/usr/bin/env python3
"""
ConsentGuard - Root Live Demonstration Forwarder
Runs the full multi-stage demonstration runner located in backend/run_demo.py.
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from run_demo import run_live_demonstration

if __name__ == "__main__":
    run_live_demonstration()

