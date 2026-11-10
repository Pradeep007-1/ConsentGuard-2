#!/usr/bin/env python3
"""
ConsentGuard - Part 9 Live Cybersecurity Demonstration Script
Demonstrates all 6 required cybersecurity and purpose-based governance scenarios:
  Scenario 1: Unauthorized Access (Authentication & Authorization rejection)
  Scenario 2: Purpose Violation (Partner-Limited restricted to authorized scope)
  Scenario 3: Consent Withdrawal (Immediate revocation of data sharing)
  Scenario 4: Notice Version Change (Mandatory re-consent protocol)
  Scenario 5: Audit Tampering Detection (Merkle DAG forensic verification on isolated copy)
  Scenario 6: API-Key Revocation (Instant revocation of partner API keys)

Guarantees 100% offline execution and strictly preserves original production audit history.
"""

import json
import os
import shutil
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

# ANSI Color formatting
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def header(title: str):
    print("\n" + CYAN + "=" * 76 + RESET)
    print(CYAN + BOLD + f"  {title}" + RESET)
    print(CYAN + "=" * 76 + RESET)


def step(scenario_num: int, title: str, description: str):
    print("\n" + BOLD + f"--- [SCENARIO {scenario_num}] {title.upper()} ---" + RESET)
    print(f"[*] Description: {description}")


def report(status: str, detail: str, payload: dict = None):
    badge = f"{GREEN}[PASSED - {status}]{RESET}"
    print(f" {badge} {detail}")
    if payload:
        snippet = json.dumps(payload, indent=2)
        indented = "\n       ".join(snippet.splitlines()[:12])
        print(f"     Payload snippet:\n       {indented}")


def run_live_demonstration():
    header("CONSENTGUARD LIVE CYBERSECURITY & GOVERNANCE DEMONSTRATION")
    print(f"Mode: {BOLD}100% Offline Local Sandbox{RESET}")
    print(f"Isolation: {BOLD}Zero modifications to production database or records{RESET}\n")

    # 1. Create isolated temporary database sandbox
    temp_dir = tempfile.mkdtemp(prefix="consentguard_demo_")
    sandbox_db = Path(temp_dir) / "demo_sandbox.db"

    try:
        with patch.object(database, "DATABASE_PATH", sandbox_db):
            with patch.dict(os.environ, {"DATABASE_URL": "", "LOCAL_MODE": "1"}):
                database.initialize_database()
                api.load_active_notice()
                api.app.config["TESTING"] = False  # Enforce real authentication requirements

                # Unauthenticated client for Scenario 1
                anon_client = api.app.test_client()

                # =========================================================
                # SCENARIO 1: Unauthorized Access
                # =========================================================
                step(
                    1,
                    "Unauthorized Access Attempt",
                    "Attempting to access protected endpoints without credentials, with invalid tokens, and without admin rights.",
                )
                # 1a. Unauthenticated access to protected user consents endpoint
                res_consents_unauth = anon_client.get("/api/consents")
                assert res_consents_unauth.status_code == 401
                assert res_consents_unauth.get_json()["reason_code"] == "UNAUTHENTICATED"
                report("401 UNAUTHORIZED", "Unauthenticated request to protected endpoint /api/consents rejected with HTTP 401.", res_consents_unauth.get_json())

                # 1b. Forged bearer token
                res_forged = anon_client.get(
                    "/api/auth/me",
                    headers={"Authorization": "Bearer cg_tok_forged_malicious_token_signature"},
                )
                assert res_forged.status_code == 401
                assert res_forged.get_json()["reason_code"] == "INVALID_TOKEN"
                report("401 UNAUTHORIZED", "Cryptographic signature validation rejected forged token.", res_forged.get_json())

                # 1c. Setup registered user and attempt admin-only operation
                user_client = api.app.test_client()
                user_res = user_client.post("/api/auth/signup", json={
                    "name": "Dr. Sarah Chen",
                    "email": "sarah.chen@regional-health.org",
                    "password": "Password123!",
                })
                assert user_res.status_code == 201
                user_id = user_res.get_json()["user"]["id"]
                user_token = user_res.get_json()["token"]
                user_auth = {"Authorization": f"Bearer {user_token}"}

                res_admin_denied = user_client.post(
                    "/api/notice/update",
                    headers=user_auth,  # Ordinary user credentials
                    json={"notice_version": "2.0", "notice_text": "Malicious notice change"},
                )
                assert res_admin_denied.status_code == 403
                assert res_admin_denied.get_json()["reason_code"] == "ADMIN_PRIVILEGES_REQUIRED"
                report("403 FORBIDDEN", "Ordinary user strictly blocked from administrative notice mutation.", res_admin_denied.get_json())

                # =========================================================
                # SCENARIO 2: Purpose Violation
                # =========================================================
                step(
                    2,
                    "Purpose Scope Violation",
                    "Partner-Limited (scoped strictly to 'Analytics') requests 'Marketing' data.",
                )
                # Grant consent for Analytics and Marketing to user
                user_client.post("/api/consents", headers=user_auth, json={"purpose": "Analytics", "action": "grant"})
                user_client.post("/api/consents", headers=user_auth, json={"purpose": "Marketing", "action": "grant"})

                # Partner-Limited attempts to request Marketing data
                res_purpose_violation = user_client.post(
                    "/api/share/request",
                    headers={"X-API-Key": DEFAULT_PARTNER_LIMITED_KEY},
                    json={"user_id": user_id, "purpose": "Marketing"},
                )
                assert res_purpose_violation.status_code == 403
                assert res_purpose_violation.get_json()["reason_code"] == "CONSUMER_NOT_AUTHORIZED"
                assert res_purpose_violation.get_json()["error_code"] == "CONSUMER_PURPOSE_UNAUTHORIZED"
                report(
                    "403 FORBIDDEN",
                    "Policy Enforcement Point (PEP) blocked Partner-Limited from accessing out-of-scope Marketing data.",
                    res_purpose_violation.get_json(),
                )

                # =========================================================
                # SCENARIO 3: Consent Withdrawal Lifecycle
                # =========================================================
                step(
                    3,
                    "Consent Withdrawal Lifecycle",
                    "User grants consent -> Consumer accesses data -> User withdraws -> Consumer repeated request is blocked.",
                )
                # 3.1: User grants consent for Service Improvement
                user_client.post("/api/consents", headers=user_auth, json={"purpose": "Service Improvement", "action": "grant"})

                # 3.2: Partner-All requests authorized data
                share_allowed = user_client.post(
                    "/api/share/request",
                    headers={"X-API-Key": DEFAULT_PARTNER_ALL_KEY},
                    json={"user_id": user_id, "purpose": "Service Improvement"},
                )
                assert share_allowed.status_code == 200
                assert share_allowed.get_json()["allowed"] is True
                report("200 OK", "Data access permitted under active user consent.", share_allowed.get_json())

                # 3.3: User withdraws consent
                withdraw_res = user_client.post(
                    "/api/consents",
                    headers=user_auth,
                    json={"purpose": "Service Improvement", "action": "withdraw"},
                )
                assert withdraw_res.status_code == 201
                report("SUCCESS", "Consent status transitioned to WITHDRAWN (granted=0).", withdraw_res.get_json())

                # 3.4: Partner-All repeats the same request -> Blocked
                share_blocked = user_client.post(
                    "/api/share/request",
                    headers={"X-API-Key": DEFAULT_PARTNER_ALL_KEY},
                    json={"user_id": user_id, "purpose": "Service Improvement"},
                )
                assert share_blocked.status_code == 403
                assert share_blocked.get_json()["reason_code"] in ("WITHDRAWN", "CONSENT_WITHDRAWN")
                report("403 FORBIDDEN", "PEP immediately blocked data sharing following user withdrawal.", share_blocked.get_json())

                # =========================================================
                # SCENARIO 4: Notice Version Change & Mandatory Re-Consent
                # =========================================================
                step(
                    4,
                    "Notice Version Change Protocol",
                    "Administrator publishes Notice v2.0 -> Pre-existing v1.0 consent triggers re-consent requirement.",
                )
                admin_client = api.app.test_client()
                admin_login = admin_client.post("/api/auth/demo-login", json={"user_id": "admin-user"})
                assert admin_login.status_code == 200
                admin_token = admin_login.get_json()["token"]
                admin_auth = {"Authorization": f"Bearer {admin_token}"}

                # 4.1: Ensure user has valid consent under current Notice v1.0
                user_client.post("/api/consents", headers=user_auth, json={"purpose": "Analytics", "action": "grant"})

                # 4.2: Administrator bumps notice to v2.0
                notice_bump = admin_client.post(
                    "/api/notice/update",
                    headers=admin_auth,
                    json={
                        "notice_version": "2.0",
                        "notice_text": "ConsentGuard Privacy Notice v2.0: Revised data processing terms and partner disclosures.",
                    },
                )
                assert notice_bump.status_code == 200
                report("SUCCESS", "Notice v2.0 published atomically by Security Administrator.", notice_bump.get_json())

                # 4.3: Partner attempts to access data using pre-existing v1.0 consent
                stale_check = user_client.post(
                    "/api/share/request",
                    headers={"X-API-Key": DEFAULT_PARTNER_ALL_KEY},
                    json={"user_id": user_id, "purpose": "Analytics"},
                )
                assert stale_check.status_code == 403
                assert stale_check.get_json()["reason_code"] == "NOTICE_MISMATCH"
                assert stale_check.get_json()["error_code"] == "NOTICE_OUTDATED_RECONSENT_REQUIRED"
                report(
                    "403 FORBIDDEN",
                    "Stale consent identified. Downstream access blocked until fresh consent under Notice v2.0 is granted.",
                    stale_check.get_json(),
                )

                # =========================================================
                # SCENARIO 5: Merkle DAG Audit Tampering Detection
                # =========================================================
                step(
                    5,
                    "Merkle DAG Tamper-Evidence Detection",
                    "Verifying cryptographic DAG -> Cloning isolated copy -> Modifying record in copy -> Proving tamper detection.",
                )
                # 5.1: Verify original sandbox ledger is cryptographically intact
                with database.get_connection() as conn:
                    orig_verify = verify_audit_chain(conn)
                    assert orig_verify["status"] == "intact"
                    report("VALID", f"Original sandbox ledger verified intact across {orig_verify['total_records']} audit events.", orig_verify)

                # 5.2: Create an isolated test copy of database file (Strictly preserving original)
                isolated_copy_path = Path(temp_dir) / "isolated_tamper_test.db"
                shutil.copyfile(sandbox_db, isolated_copy_path)

                # 5.3: Modify a record in the isolated copy (tamper simulation)
                conn_tamper = sqlite3.connect(str(isolated_copy_path))
                conn_tamper.row_factory = sqlite3.Row
                conn_tamper.execute("DROP TRIGGER IF EXISTS trg_prevent_audit_update")
                conn_tamper.execute("UPDATE audit_events SET action = 'tampered_malicious_action' WHERE id = 2")
                conn_tamper.commit()

                # 5.4: Run verification scanner on the tampered copy
                tamper_result = verify_audit_chain(conn_tamper)
                conn_tamper.close()

                assert tamper_result["status"] == "broken"
                assert tamper_result["detected_tampering"] is True
                assert tamper_result["broken_at_id"] == 2
                assert tamper_result["reason_code"] == "ROW_HASH_TAMPERED"
                report(
                    "DETECTED",
                    f"Forensic verification successfully detected hash tampering at record ID {tamper_result['broken_at_id']}.",
                    tamper_result,
                )

                # 5.5: Double check original sandbox was NEVER modified
                with database.get_connection() as conn:
                    clean_verify = verify_audit_chain(conn)
                    assert clean_verify["status"] == "intact"
                    report("SUCCESS", "Original demonstration ledger confirmed 100% untouched and authentic.")

                # =========================================================
                # SCENARIO 6: API-Key Generation & Revocation
                # =========================================================
                step(
                    6,
                    "Consumer API-Key Generation & Revocation",
                    "Administrator registers new consumer -> Access granted -> Key revoked -> Repeated access rejected.",
                )
                # 6.1: Administrator registers new consumer client
                create_consumer = admin_client.post(
                    "/api/consumers/create",
                    headers=admin_auth,
                    json={
                        "consumer_id": "partner-demonstration",
                        "name": "Live Demonstration Research Partner",
                        "allowed_purposes": ["Analytics"],
                    },
                )
                assert create_consumer.status_code == 201
                demo_api_key = create_consumer.get_json()["api_key"]
                report("SUCCESS", f"Registered consumer 'partner-demonstration' with new API key: {demo_api_key[:16]}...", create_consumer.get_json())

                # Re-consent user under Notice v2.0 for Analytics
                user_client.post("/api/consents", headers=user_auth, json={"purpose": "Analytics", "action": "grant"})

                # 6.2: Authorized data access with active key
                active_res = user_client.post(
                    "/api/share/request",
                    headers={"X-API-Key": demo_api_key},
                    json={"user_id": user_id, "purpose": "Analytics"},
                )
                assert active_res.status_code == 200
                assert active_res.get_json()["allowed"] is True
                report("200 OK", "Downstream consumer successfully accessed data with valid active API key.", active_res.get_json())

                # 6.3: Administrator revokes the consumer key
                revoke_res = admin_client.post(
                    "/api/consumers/revoke",
                    headers=admin_auth,
                    json={"consumer_id": "partner-demonstration"},
                )
                assert revoke_res.status_code == 200
                assert revoke_res.get_json()["is_active"] is False
                report("SUCCESS", "Administrator revoked API key for 'partner-demonstration'.", revoke_res.get_json())

                # 6.4: Repeated request with revoked key -> Blocked
                revoked_res = user_client.post(
                    "/api/share/request",
                    headers={"X-API-Key": demo_api_key},
                    json={"user_id": user_id, "purpose": "Analytics"},
                )
                assert revoked_res.status_code == 401
                assert revoked_res.get_json()["reason_code"] == "API_KEY_REVOKED"
                report("401 UNAUTHORIZED", "Access immediately denied following API key revocation.", revoked_res.get_json())

        header("ALL 6 CYBERSECURITY DEMONSTRATION SCENARIOS COMPLETED SUCCESSFULLY")
        print(GREEN + BOLD + " [✓] Scenario 1: Unauthorized Access -> DENIED (HTTP 401/403)" + RESET)
        print(GREEN + BOLD + " [✓] Scenario 2: Purpose Violation -> BLOCKED (HTTP 403 CONSUMER_NOT_AUTHORIZED)" + RESET)
        print(GREEN + BOLD + " [✓] Scenario 3: Consent Withdrawal -> ACCESS DENIED (HTTP 403 WITHDRAWN)" + RESET)
        print(GREEN + BOLD + " [✓] Scenario 4: Notice Version Change -> STALE CONSENT DETECTED (HTTP 403 NOTICE_MISMATCH)" + RESET)
        print(GREEN + BOLD + " [✓] Scenario 5: Audit Tampering -> DETECTED (Merkle DAG flag ROW_HASH_TAMPERED)" + RESET)
        print(GREEN + BOLD + " [✓] Scenario 6: API-Key Revocation -> REJECTED (HTTP 401 API_KEY_REVOKED)" + RESET)
        print(CYAN + "=" * 76 + RESET + "\n")
        return 0

    finally:
        # Clean up temporary sandbox directory
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(run_live_demonstration())
