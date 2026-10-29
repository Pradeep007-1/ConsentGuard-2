import os
import sys
from pathlib import Path

# Vercel runs this file as a Python serverless function.
ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

import database
if not os.environ.get("DATABASE_URL"):
    database.DATABASE_PATH = Path("/tmp/consentguard.db")
database.initialize_database()

import api as consent_api
consent_api.load_active_notice()
app = consent_api.app
