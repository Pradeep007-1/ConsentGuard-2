#!/usr/bin/env python3
"""
ConsentGuard - Enterprise Database Seeder
Safely and idempotently initializes the database, demo users, default notices,
database-driven purposes, and downstream partner consumer credentials.
"""

import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from database import (
    DEFAULT_NOTICE_HASH,
    DEFAULT_NOTICE_TEXT,
    DEFAULT_NOTICE_VERSION,
    DEFAULT_PARTNER_ALL_KEY,
    DEFAULT_PARTNER_LIMITED_KEY,
    get_connection,
    initialize_database,
    is_postgres,
    verify_audit_chain,
)


def seed():
    print("=" * 60)
    print("ConsentGuard - Database Initialization & Seeding")
    print("=" * 60)

    db_target = "Neon PostgreSQL" if is_postgres() else "Local SQLite"
    print(f"[*] Target Database Engine: {db_target}")

    # 1. Initialize schema, triggers, and seed records
    initialize_database()
    print("[+] Database schema, cryptographic triggers, and tables verified.")

    with get_connection() as conn:
        # Verify Notice
        notice_row = conn.execute(
            "SELECT version, hash, is_active FROM notice_versions WHERE is_active = 1 ORDER BY id DESC LIMIT 1"
        ).fetchone()
        active_ver = notice_row["version"] if notice_row else DEFAULT_NOTICE_VERSION
        print(f"[+] Active Privacy Notice: v{active_ver}")

        # Verify Users
        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        print(f"[+] Demo & Registered Accounts: {user_count} accounts present.")

        # Verify Purposes
        purposes = conn.execute("SELECT id, name FROM purposes").fetchall()
        print(f"[+] Database-Driven Purposes: {[p['id'] for p in purposes]}")

        # Verify Consumers
        consumers = conn.execute("SELECT consumer_id, name, is_active FROM consumers").fetchall()
        print(f"[+] Downstream Consumers:")
        for c in consumers:
            status = "ACTIVE" if c["is_active"] else "INACTIVE"
            print(f"    - {c['consumer_id']} ({c['name']}) [{status}]")

        # Verify Audit Chain
        audit_res = verify_audit_chain(conn, strict_linear=False)
        print(f"[+] Cryptographic Audit Ledger: {audit_res['status'].upper()} ({audit_res['verified_count']} events verified)")

    print("=" * 60)
    print("Seeding completed successfully. Ready for offline or live operation.")
    print("=" * 60)


if __name__ == "__main__":
    seed()

