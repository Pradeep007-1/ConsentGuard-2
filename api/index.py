import os
import sys
from pathlib import Path

# Vercel runs this file as a Python serverless function.
ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

import database
import shutil

if not database.is_postgres():
    tmp_db = Path("/tmp/consentguard.db")
    bundled_db = BACKEND / "consentguard.db"
    if not tmp_db.exists() and bundled_db.exists():
        try:
            shutil.copyfile(bundled_db, tmp_db)
        except Exception:
            pass
    database.DATABASE_PATH = tmp_db

database.initialize_database()

import api as consent_api
consent_api.load_active_notice()
app = consent_api.app
