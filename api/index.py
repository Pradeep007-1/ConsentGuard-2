import sys
from pathlib import Path

# Vercel runs this file as a Python serverless function.
ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

import database
database.DATABASE_PATH = Path("/tmp/consentguard.db")
database.initialize_database()

import api as consent_api
app = consent_api.app
