import sys
from pathlib import Path

# Ensure backend directory is in python search path
ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from api import app, initialize_database, load_active_notice

if __name__ == "__main__":
    initialize_database()
    load_active_notice()
    print("ConsentGuard backend running on http://127.0.0.1:5001")
    app.run(host="0.0.0.0", port=5001, debug=False, threaded=True)
