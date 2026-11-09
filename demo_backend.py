#!/usr/bin/env python3
"""
ConsentGuard - Enterprise Backend Hackathon Demonstration Script
Executes the full 9-step purpose-based consent lifecycle, downstream PEP enforcement,
and cryptographic Merkle DAG audit verification using an isolated temporary sandbox.
Guarantees zero risk to production data.
"""

import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import api
import database
from database import (
    DEFAULT_NOTICE_HASH,
    DEFAULT_NOTICE_VERSION,
    DEFAULT_PARTNER_ALL_KEY,
    DEFAULT_PARTNER_LIMITED_KEY,
    initialize_database,
    verify_audit_chain,
)


def log_step(step_num: int, title: str, description: str):
    print("\n" + "=" * 70)
    print(f" STEP {step_num}: {title.upper()}")
    print("=" * 70)
    print(f"[*] {description}\n")


def log_result(status: str, message: str, payload: dict = None):
    badge = "[PASS]" if status.upper() in ("ALLOW", "VALID", "SUCCESS", "PASS") else "[BLOCK]"
    print(f" {badge} {status.upper()} - {message}")
    if payload:
        print("     Payload:", json.dumps(payload, indent=2).replace("\n", "\n     "))


def run_demo():
    print("\n" + "#" * 70)
    print("#  CONSENTGUARD: PURPOSE-BASED CONSENT & AUDIT DAG DEMONSTRATION     #")
    print("#  Offline Regional Hackathon Evaluation Sandbox                     #")
    print("#" * 70)

    # Use an isolated temporary SQLite database
    temp_dir = tempfile.mkdtemp()
    temp_db_path = Path(temp_dir) / "demo_sandbox.db"

    with patch.object(database, "DATABASE_PATH", temp_db_path):
        with patch.dict(os.environ, {"DATABASE_URL": ""}):
            database.initialize_database()
            api.load_active_notice()

            api.app.config["TESTING"] = True
            client = api.app.test_client()

            # Create synthetic test subject
            user_res = client.post("/api/auth/signup", json={
                "name": "Dr. Sarah Chen",
                "email": "sarah.chen@regional-hospital.org",
                "password": "Password123!",
            })
            user_id = user_res.get_json()["user"]["id"]
            auth_headers = {"Authorization": f"Bearer {user_id}"}

            # -------------------------------------------------------------
            # STEP 1: Grant Consent
            # -------------------------------------------------------------
            log_step(1, "Grant Consent", f"User '{user_id}' opts into Analytics under active Notice v1.0.")
            res1 = client.post("/api/consents", headers=auth_headers, json={
                "purpose": "Analytics",
                "action": "grant",
            })
            log_result("SUCCESS", "Consent decision recorded with active notice hash.", res1.get_json())
            assert res1.status_code == 201

            # -------------------------------------------------------------
            # STEP 2: Partner Requests Data -> ALLOW
            # -------------------------------------------------------------
            log_step(2, "Downstream Data Share", "Authorized partner-all requests telemetry for Analytics.")
            res2 = client.post("/api/share/request", json={
                "api_key": DEFAULT_PARTNER_ALL_KEY,
                "user_id": user_id,
                "purpose": "Analytics",
                "requested_fields": ["page_views"],
            })
            log_result("ALLOW", "Policy Enforcement Point (PEP) permitted data release.", res2.get_json())
            assert res2.status_code == 200
            assert res2.get_json()["allowed"] is True

            # -------------------------------------------------------------
            # STEP 3: Withdraw Consent
            # -------------------------------------------------------------
            log_step(3, "Withdraw Consent", f"User '{user_id}' withdraws Analytics consent.")
            res3 = client.post("/api/consents", headers=auth_headers, json={
                "purpose": "Analytics",
                "action": "withdraw",
            })
            log_result("SUCCESS", "Consent status updated to WITHDRAWN (granted=0).", res3.get_json())
            assert res3.status_code == 201

            # -------------------------------------------------------------
            # STEP 4: Partner Requests Data -> DENY
            # -------------------------------------------------------------
            log_step(4, "Downstream Data Share Blocked", "Partner requests Analytics data after consent withdrawal.")
            res4 = client.post("/api/share/request", json={
                "api_key": DEFAULT_PARTNER_ALL_KEY,
                "user_id": user_id,
                "purpose": "Analytics",
            })
            log_result("DENY", "PEP immediately blocked data access (HTTP 403 WITHDRAWN).", res4.get_json())
            assert res4.status_code == 403
            assert res4.get_json()["reason_code"] == "WITHDRAWN"

            # -------------------------------------------------------------
            # STEP 5: Publish New Notice (v2.0)
            # -------------------------------------------------------------
            log_step(5, "Notice Version Upgrade", "Privacy Administrator publishes Notice v2.0.")
            res5 = client.post("/api/notice/update", headers=auth_headers, json={
                "notice_version": "2.0",
                "notice_text": "ConsentGuard Privacy Notice v2.0: Mandatory downstream re-consent protocols.",
            })
            log_result("SUCCESS", "Notice v2.0 atomically published. Prior notices marked inactive.", res5.get_json())
            assert res5.status_code == 200

            # -------------------------------------------------------------
            # STEP 6: Old Consent -> DENY
            # -------------------------------------------------------------
            log_step(6, "Outdated Consent Blocked", "Re-evaluating downstream access against outdated notice version.")
            # Grant Marketing under v1.0 directly in DB to simulate pre-existing v1.0 consent
            with database.get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO consents (user_id, purpose, granted, notice_version, notice_hash, last_action, updated_at)
                    VALUES (?, 'Marketing', 1, '1.0', ?, 'grant', '2026-11-09T00:00:00.000000Z')
                    ON CONFLICT(user_id, purpose) DO UPDATE SET granted = 1, notice_version = '1.0'
                    """,
                    (user_id, DEFAULT_NOTICE_HASH),
                )

            res6 = client.post("/api/share/request", json={
                "api_key": DEFAULT_PARTNER_ALL_KEY,
                "user_id": user_id,
                "purpose": "Marketing",
            })
            log_result("DENY", "PEP blocked stale v1.0 consent (HTTP 403 NOTICE_MISMATCH).", res6.get_json())
            assert res6.status_code == 403
            assert res6.get_json()["reason_code"] == "NOTICE_MISMATCH"

            # -------------------------------------------------------------
            # STEP 7: Re-Consent -> ALLOW
            # -------------------------------------------------------------
            log_step(7, "Re-Consent Under v2.0", f"User '{user_id}' grants re-consent under active Notice v2.0.")
            res7 = client.post("/api/consents", headers=auth_headers, json={
                "purpose": "Marketing",
                "action": "grant",
            })
            assert res7.status_code == 201

            res7_share = client.post("/api/share/request", json={
                "api_key": DEFAULT_PARTNER_ALL_KEY,
                "user_id": user_id,
                "purpose": "Marketing",
                "requested_fields": ["email_preferences"],
            })
            log_result("ALLOW", "Downstream access restored under Notice v2.0.", res7_share.get_json())
            assert res7_share.status_code == 200
            assert res7_share.get_json()["allowed"] is True

            # -------------------------------------------------------------
            # STEP 8: Verify Audit Integrity -> VALID
            # -------------------------------------------------------------
            log_step(8, "Cryptographic Ledger Verification", "Verifying SHA-256 Merkle DAG hash chain.")
            res8 = client.get("/api/audit/verify")
            log_result("VALID", "Audit hash chain is cryptographically intact.", res8.get_json())
            assert res8.status_code == 200
            assert res8.get_json()["status"] == "intact"

            # -------------------------------------------------------------
            # STEP 9: Tamper with Disposable Database -> INVALID
            # -------------------------------------------------------------
            log_step(9, "Forensic Tamper Detection", "Directly altering a record in disposable sandbox database.")
            # We temporarily bypass SQLite trigger for demonstration of verification algorithm detection
            conn_tamper = sqlite3.connect(str(temp_db_path))
            conn_tamper.row_factory = sqlite3.Row
            conn_tamper.execute("DROP TRIGGER IF EXISTS trg_prevent_audit_update")
            conn_tamper.execute("UPDATE audit_events SET action = 'forged_grant' WHERE id = 2")
            conn_tamper.commit()

            tamper_res = verify_audit_chain(conn_tamper)
            conn_tamper.close()

            log_result("BROKEN", f"Forensic scanner detected unauthorized payload tampering at ID {tamper_res.get('broken_at_id')}.", tamper_res)
            assert tamper_res["status"] == "broken"
            assert tamper_res["broken_at_id"] == 2
            assert tamper_res["reason_code"] == "ROW_HASH_TAMPERED"

    print("\n" + "=" * 70)
    print(" [✓] COMPLETE DEMONSTRATION FINISHED: ALL 9 STAGES PASSED")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    run_demo()
