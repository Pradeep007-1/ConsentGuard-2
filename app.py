import os
import sys
from pathlib import Path

# Ensure backend directory is in python search path
ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# Default to LOCAL_MODE=1 if not in Vercel or production cloud environment
if not os.environ.get("VERCEL") and not os.environ.get("PRODUCTION"):
    os.environ.setdefault("LOCAL_MODE", "1")

from api import app, initialize_database, load_active_notice
from database import is_local_mode

if __name__ == "__main__":
    initialize_database()
    load_active_notice()
    mode_label = "LOCAL OFFLINE (SQLite)" if is_local_mode() else "CLOUD (PostgreSQL)"
    print("=" * 60)
    print(f" ConsentGuard Backend running in {mode_label} mode")
    print(" URL: http://127.0.0.1:5001")
    if is_local_mode():
        print(" External cloud dependencies: NONE (100% offline operational)")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5001, debug=False, threaded=True)
