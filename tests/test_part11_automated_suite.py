"""
ConsentGuard Enterprise Automated Test Suite — Part 11
Comprehensive automated test suite covering:
  - Authentication (5 tests)
  - Administration (4 tests)
  - Consent Lifecycle (7 tests)
  - Merkle DAG Audit System (6 tests)
  - Purpose-Based Data Sharing (8 tests)
  - Cybersecurity Protections (5 tests)
  - 100% Offline Resilience (6 tests)
Total: 41 automated tests
"""

import concurrent.futures
import gc
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure repository paths are on sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import api
import database
from database import (
    DEFAULT_NOTICE_HASH,
    DEFAULT_NOTICE_TEXT,
    DEFAULT_NOTICE_VERSION,
    DEFAULT_PARTNER_ALL_KEY,
    DEFAULT_PARTNER_LIMITED_KEY,
    GENESIS_PREV_HASH,
    append_audit_event,
    compute_canonical_audit_hash,
    get_connection,
    hash_api_key,
    initialize_database,
    seed_demo_users,
    seed_purposes_and_consumers,
    verify_audit_chain,
)


@pytest.fixture
def part11_app():
    """Provides an isolated Flask test client with a fresh temporary SQLite database."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
        test_db = Path(temp_dir) / "part11_test.db"
        with patch.object(database, "DATABASE_PATH", test_db):
            with patch.dict(os.environ, {"DATABASE_URL": ""}):
                database.initialize_database()
                api.load_active_notice()

                api.app.config["TESTING"] = True
                client = api.app.test_client()
                yield client, test_db


# ============================================================================
# 1. AUTHENTICATION TESTS (5 TESTS)
# ============================================================================

def test_01_auth_valid_login(part11_app):
    """Auth 1: Valid login succeeds and returns 200, JWT token, and user profile."""
    client, _ = part11_app
    # Signup
    signup_res = client.post(
        "/api/auth/signup",
        json={"name": "Alice Tester", "email": "alice.auth@example.com", "password": "SecurePassword123!"},
    )
    assert signup_res.status_code == 201

    # Login
    login_res = client.post(
        "/api/auth/login",
        json={"email": "alice.auth@example.com", "password": "SecurePassword123!"},
    )
    assert login_res.status_code == 200
    data = login_res.get_json()
    assert data["success"] is True
    assert "token" in data
    assert data["user"]["email"] == "alice.auth@example.com"


def test_02_auth_invalid_login(part11_app):
    """Auth 2: Invalid password or non-existent user rejected with 401 INVALID_CREDENTIALS."""
    client, _ = part11_app
    client.post(
        "/api/auth/signup",
        json={"name": "Bob Tester", "email": "bob.auth@example.com", "password": "SecurePassword123!"},
    )

    bad_login = client.post(
        "/api/auth/login",
        json={"email": "bob.auth@example.com", "password": "WrongPassword999!"},
    )
    assert bad_login.status_code == 401
    assert bad_login.get_json()["reason_code"] == "INVALID_CREDENTIALS"


def test_03_auth_invalid_token(part11_app):
    """Auth 3: Malformed or forged Bearer token rejected with 401 INVALID_TOKEN."""
    client, _ = part11_app
    # Bearer tokens prefixed with cg_tok_ are cryptographically validated
    forged_token = "cg_tok_eyJhbGciOiJIUzI1NiJ9.forged_signature_tampered_payload_12345"
    res = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {forged_token}"},
    )
    assert res.status_code == 401
    assert res.get_json()["reason_code"] == "INVALID_TOKEN"


def test_04_auth_protected_endpoint_access(part11_app):
    """Auth 4: Protected endpoint accessible when authenticated with valid Bearer token."""
    client, _ = part11_app
    reg_res = client.post(
        "/api/auth/signup",
        json={"name": "Carol Protected", "email": "carol.protected@example.com", "password": "SecurePassword123!"},
    )
    token = reg_res.get_json()["token"]

    # Access protected consent list
    consents_res = client.get(
        "/api/consents",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert consents_res.status_code == 200
    assert isinstance(consents_res.get_json(), list)


def test_05_auth_unauthorized_access(part11_app):
    """Auth 5: Protected endpoints reject requests lacking authentication credentials with 401."""
    client, _ = part11_app
    prev_testing = api.app.config.get("TESTING", True)
    try:
        api.app.config["TESTING"] = False
        unauth_client = api.app.test_client()
        res = unauth_client.get("/api/consents")
        assert res.status_code == 401
        assert res.get_json()["reason_code"] == "UNAUTHENTICATED"
    finally:
        api.app.config["TESTING"] = prev_testing


# ============================================================================
# 2. ADMINISTRATION TESTS (4 TESTS)
# ============================================================================

def test_06_admin_authorized_operation(part11_app):
    """Admin 1: Authorized administrator updates privacy notice with valid X-Admin-Key."""
    client, _ = part11_app
    admin_key = api.ADMIN_KEY
    res = client.post(
        "/api/notice/update",
        headers={"X-Admin-Key": admin_key},
        json={
            "notice_version": "2.0",
            "notice_text": "ConsentGuard Privacy Notice v2.0: Revised data processing disclosures.",
            "source": "admin_portal",
        },
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["notice_version"] == "2.0"
    assert "notice_hash" in data


def test_07_admin_unauthorized_operation(part11_app):
    """Admin 2: Unauthorized request to admin endpoints rejected with 403 ADMIN_PRIVILEGES_REQUIRED."""
    client, _ = part11_app
    # Login as synthetic non-admin regular user
    reg_login = client.post("/api/auth/demo-login", json={"user_id": "user-regular"})
    assert reg_login.status_code == 200
    reg_token = reg_login.get_json()["token"]

    res = client.post(
        "/api/notice/update",
        headers={"Authorization": f"Bearer {reg_token}"},
        json={"notice_version": "3.0", "notice_text": "Malicious notice change"},
    )
    assert res.status_code == 403
    assert res.get_json()["reason_code"] == "ADMIN_PRIVILEGES_REQUIRED"


def test_08_admin_notice_bump(part11_app):
    """Admin 3: Notice bump activates new version, deactivates old version, and computes deterministic SHA-256."""
    client, test_db = part11_app
    admin_key = api.ADMIN_KEY
    bump_text = "Notice Version 2.0 with enhanced analytics protections."
    res = client.post(
        "/api/notice/update",
        headers={"X-Admin-Key": admin_key},
        json={"notice_version": "2.0", "notice_text": bump_text},
    )
    assert res.status_code == 200
    expected_hash = hashlib.sha256(bump_text.encode("utf-8")).hexdigest()
    assert res.get_json()["notice_hash"] == expected_hash

    # Check database state
    with get_connection() as conn:
        active_row = conn.execute("SELECT * FROM notice_versions WHERE is_active = 1").fetchone()
        old_row = conn.execute("SELECT * FROM notice_versions WHERE version = '1.0'").fetchone()

    assert active_row["version"] == "2.0"
    assert old_row["is_active"] == 0


def test_09_admin_notice_reset(part11_app):
    """Admin 4: Notice reset restores default 1.0 active notice and logs an audit event."""
    client, test_db = part11_app
    admin_key = api.ADMIN_KEY

    # Bump first
    client.post(
        "/api/notice/update",
        headers={"X-Admin-Key": admin_key},
        json={"notice_version": "2.5", "notice_text": "Temporary notice 2.5"},
    )
    # Reset
    reset_res = client.post(
        "/api/notice/reset",
        headers={"X-Admin-Key": admin_key},
        json={"source": "admin_reset_test"},
    )
    assert reset_res.status_code == 200
    assert reset_res.get_json()["notice_version"] == DEFAULT_NOTICE_VERSION
    assert reset_res.get_json()["notice_hash"] == DEFAULT_NOTICE_HASH


# ============================================================================
# 3. CONSENT LIFECYCLE TESTS (7 TESTS)
# ============================================================================

def test_10_consent_creation(part11_app):
    """Consent 1: Authenticated user successfully creates consent with granted=True."""
    client, _ = part11_app
    reg = client.post(
        "/api/auth/signup",
        json={"name": "Eve Consent", "email": "eve.consent@example.com", "password": "SecurePassword123!"},
    )
    token = reg.get_json()["token"]

    grant_res = client.post(
        "/api/consents",
        headers={"Authorization": f"Bearer {token}"},
        json={"purpose": "Analytics", "action": "grant"},
    )
    assert grant_res.status_code == 201
    data = grant_res.get_json()
    assert data["granted"] is True
    assert data["purpose"] == "Analytics"
    assert data["notice_version"] == DEFAULT_NOTICE_VERSION
    assert "created_at" in data


def test_11_consent_retrieval(part11_app):
    """Consent 2: Authenticated user retrieves active consent state."""
    client, _ = part11_app
    reg = client.post(
        "/api/auth/signup",
        json={"name": "Frank Retrieval", "email": "frank.retrieval@example.com", "password": "SecurePassword123!"},
    )
    token = reg.get_json()["token"]

    client.post(
        "/api/consents",
        headers={"Authorization": f"Bearer {token}"},
        json={"purpose": "Marketing", "action": "grant"},
    )

    get_res = client.get(
        "/api/consents",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert get_res.status_code == 200
    consents_list = get_res.get_json()
    assert any(c["purpose"] == "Marketing" and c["granted"] == 1 for c in consents_list)


def test_12_consent_unauthorized_retrieval(part11_app):
    """Consent 3: Unauthenticated request to retrieve consents rejected with 401."""
    client, _ = part11_app
    prev_testing = api.app.config.get("TESTING", True)
    try:
        api.app.config["TESTING"] = False
        unauth_client = api.app.test_client()
        res = unauth_client.get("/api/consents")
        assert res.status_code == 401
        assert res.get_json()["reason_code"] == "UNAUTHENTICATED"
    finally:
        api.app.config["TESTING"] = prev_testing


def test_13_consent_withdrawal(part11_app):
    """Consent 4: User successfully withdraws consent, setting granted=False and withdrawn_at."""
    client, _ = part11_app
    reg = client.post(
        "/api/auth/signup",
        json={"name": "Grace Withdraw", "email": "grace.withdraw@example.com", "password": "SecurePassword123!"},
    )
    token = reg.get_json()["token"]

    # Grant then withdraw
    client.post(
        "/api/consents",
        headers={"Authorization": f"Bearer {token}"},
        json={"purpose": "Analytics", "action": "grant"},
    )
    withdraw_res = client.post(
        "/api/consents",
        headers={"Authorization": f"Bearer {token}"},
        json={"purpose": "Analytics", "action": "withdraw"},
    )
    assert withdraw_res.status_code == 201
    data = withdraw_res.get_json()
    assert data["granted"] is False
    assert data["action"] == "withdraw"
    assert data["withdrawn_at"] is not None


def test_14_consent_repeated_withdrawal(part11_app):
    """Consent 5: Repeated withdrawal is idempotent and maintains withdrawn state."""
    client, _ = part11_app
    reg = client.post(
        "/api/auth/signup",
        json={"name": "Heidi Repeated", "email": "heidi.repeated@example.com", "password": "SecurePassword123!"},
    )
    token = reg.get_json()["token"]

    client.post("/api/consents", headers={"Authorization": f"Bearer {token}"}, json={"purpose": "Analytics", "action": "withdraw"})
    # Repeat withdrawal
    repeat_res = client.post("/api/consents", headers={"Authorization": f"Bearer {token}"}, json={"purpose": "Analytics", "action": "withdraw"})
    assert repeat_res.status_code in (200, 201)
    assert repeat_res.get_json()["granted"] is False


def test_15_consent_stale_notice(part11_app):
    """Consent 6: Stale notice triggers NOTICE_OUTDATED_RECONSENT_REQUIRED on downstream access."""
    client, _ = part11_app
    admin_key = api.ADMIN_KEY
    reg = client.post(
        "/api/auth/signup",
        json={"name": "Ivan Stale", "email": "ivan.stale@example.com", "password": "SecurePassword123!"},
    )
    user_id = reg.get_json()["user"]["id"]
    token = reg.get_json()["token"]

    # Grant under v1.0
    client.post(
        "/api/consents",
        headers={"Authorization": f"Bearer {token}"},
        json={"purpose": "Analytics", "action": "grant"},
    )

    # Admin bumps notice to v2.0
    update_res = client.post(
        "/api/notice/update",
        headers={"X-Admin-Key": admin_key},
        json={"notice_version": "2.0", "notice_text": "Updated notice v2.0"},
    )
    assert update_res.status_code == 200

    # Downstream data sharing request should fail due to outdated notice
    share_res = client.post(
        "/api/share/request",
        headers={"X-API-Key": DEFAULT_PARTNER_ALL_KEY},
        json={"user_id": user_id, "purpose": "Analytics", "requested_fields": ["page_views"]},
    )
    assert share_res.status_code == 403
    data = share_res.get_json()
    assert data["error_code"] == "NOTICE_OUTDATED_RECONSENT_REQUIRED"


def test_16_consent_notice_hash_verification(part11_app):
    """Consent 7: Deterministic SHA-256 verification of notice content and rejection of stale hash."""
    client, _ = part11_app
    reg = client.post(
        "/api/auth/signup",
        json={"name": "Judy Hash", "email": "judy.hash@example.com", "password": "SecurePassword123!"},
    )
    token = reg.get_json()["token"]

    # Attempt to grant with an invalid/mismatched notice hash
    bad_hash_res = client.post(
        "/api/consents",
        headers={"Authorization": f"Bearer {token}"},
        json={"purpose": "Analytics", "action": "grant", "notice_hash": "00000000deadbeef00000000deadbeef"},
    )
    assert bad_hash_res.status_code == 409
    assert bad_hash_res.get_json()["reason_code"] == "STALE_NOTICE"


# ============================================================================
# 4. MERKLE DAG AUDIT SYSTEM TESTS (6 TESTS)
# ============================================================================

def test_17_audit_valid_dag_verification(part11_app):
    """Audit 1: Valid Merkle DAG verifies intact with zero broken references or tampered records."""
    _, test_db = part11_app
    with get_connection() as conn:
        h1 = append_audit_event(conn, "u1", "Analytics", "test_action_1", 200, "OK", "1.0", "h")
        h2 = append_audit_event(conn, "u1", "Analytics", "test_action_2", 200, "OK", "1.0", "h")
        assert len(h1) == 64 and len(h2) == 64

        verification = verify_audit_chain(conn)
        assert verification["status"] == "intact"
        assert verification["detected_tampering"] is False
        assert verification["invalid_records"] == 0
        assert verification["broken_references"] == 0
        assert verification["valid_records"] == verification["total_records"]


def test_18_audit_invalid_hash(part11_app):
    """Audit 2: Tampering with a record's action or details causes verification to flag ROW_HASH_TAMPERED."""
    _, test_db = part11_app
    with get_connection() as conn:
        append_audit_event(conn, "u2", "Analytics", "original_action", 200, "OK", "1.0", "h")

    # Tamper directly in SQLite
    conn = sqlite3.connect(str(test_db))
    conn.execute("DROP TRIGGER IF EXISTS trg_prevent_audit_update")
    conn.execute("UPDATE audit_events SET action = 'tampered_action' WHERE action = 'original_action'")
    conn.commit()
    conn.close()

    with get_connection() as conn:
        verification = verify_audit_chain(conn)
        assert verification["status"] == "broken"
        assert verification["detected_tampering"] is True
        assert verification["reason_code"] == "ROW_HASH_TAMPERED"


def test_19_audit_missing_parent(part11_app):
    """Audit 3: Pointing an audit record's prev_hash to a missing parent flags BROKEN_REFERENCE."""
    _, test_db = part11_app
    with get_connection() as conn:
        append_audit_event(conn, "u1", "Analytics", "valid_event_1", 200, "OK", "1.0", "h")

    # Insert a record with a fake non-existent parent hash
    fake_parent_hash = "f" * 64
    conn = sqlite3.connect(str(test_db))
    conn.row_factory = sqlite3.Row
    now_str = "2026-11-10T12:00:00.000000Z"
    canonical_hash = compute_canonical_audit_hash(
        prev_hash=fake_parent_hash,
        user_id="u_fake",
        purpose="Analytics",
        action="broken_ref_event",
        http_status=200,
        reason_code="OK",
        notice_version="1.0",
        notice_hash="h",
        source="user",
        created_at=now_str,
        details="",
    )
    conn.execute(
        """
        INSERT INTO audit_events (user_id, purpose, action, http_status, reason_code, notice_version, notice_hash, short_notice_hash, source, prev_hash, row_hash, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        ("u_fake", "Analytics", "broken_ref_event", 200, "OK", "1.0", "h", "", "user", fake_parent_hash, canonical_hash, "", now_str),
    )
    conn.commit()
    conn.close()

    with get_connection() as conn:
        verification = verify_audit_chain(conn)
        assert verification["status"] == "broken"
        assert verification["broken_references"] > 0
        assert verification["reason_code"] in ("BROKEN_ANCESTOR_LINK", "BROKEN_REFERENCE")


def test_20_audit_valid_branch(part11_app):
    """Audit 4: Valid branch support allows legitimate concurrent branches without flagging tampering."""
    _, test_db = part11_app
    with get_connection() as conn:
        parent_hash = append_audit_event(conn, "u_root", "Analytics", "root_branch_event", 200, "OK", "1.0", "h")

    conn = sqlite3.connect(str(test_db))
    ts1 = "2026-11-10T12:01:00.000000Z"
    h_child1 = compute_canonical_audit_hash(
        prev_hash=parent_hash,
        user_id="u1",
        purpose="Analytics",
        action="branch_child_1",
        http_status=200,
        reason_code="OK",
        notice_version="1.0",
        notice_hash="h",
        source="w1",
        created_at=ts1,
        details="",
    )
    conn.execute(
        "INSERT INTO audit_events (user_id, purpose, action, http_status, reason_code, notice_version, notice_hash, short_notice_hash, source, prev_hash, row_hash, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("u1", "Analytics", "branch_child_1", 200, "OK", "1.0", "h", "", "w1", parent_hash, h_child1, "", ts1),
    )

    ts2 = "2026-11-10T12:01:01.000000Z"
    h_child2 = compute_canonical_audit_hash(
        prev_hash=parent_hash,
        user_id="u2",
        purpose="Analytics",
        action="branch_child_2",
        http_status=200,
        reason_code="OK",
        notice_version="1.0",
        notice_hash="h",
        source="w2",
        created_at=ts2,
        details="",
    )
    conn.execute(
        "INSERT INTO audit_events (user_id, purpose, action, http_status, reason_code, notice_version, notice_hash, short_notice_hash, source, prev_hash, row_hash, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("u2", "Analytics", "branch_child_2", 200, "OK", "1.0", "h", "", "w2", parent_hash, h_child2, "", ts2),
    )
    conn.commit()
    conn.close()

    with get_connection() as conn:
        verification = verify_audit_chain(conn, strict_linear=False)
        assert verification["status"] == "intact"
        assert verification["detected_tampering"] is False
        assert verification["branches_count"] >= 1


def test_21_audit_concurrent_writes(part11_app):
    """Audit 5: Concurrent threads writing audit events succeed without database corruption."""
    _, test_db = part11_app

    def worker(worker_id):
        for i in range(4):
            with get_connection() as conn:
                append_audit_event(
                    connection=conn,
                    user_id=f"user_{worker_id}",
                    purpose="Analytics",
                    action=f"concurrent_event_{worker_id}_{i}",
                    http_status=200,
                    reason_code="OK",
                    notice_version="1.0",
                    notice_hash="h",
                    source="worker",
                )
            time.sleep(0.002)

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = [executor.submit(worker, w) for w in range(3)]
        concurrent.futures.wait(futures)

    with get_connection() as conn:
        verification = verify_audit_chain(conn)
        assert verification["status"] == "intact"
        assert verification["detected_tampering"] is False
        assert verification["valid_records"] == verification["total_records"]


def test_22_audit_tampering_detection(part11_app):
    """Audit 6: Detailed forensic reporting when tampering is detected via API verification endpoint."""
    client, test_db = part11_app
    with get_connection() as conn:
        append_audit_event(conn, "target_user", "Marketing", "forensic_target", 200, "OK", "1.0", "h")

    # Tamper record
    conn = sqlite3.connect(str(test_db))
    conn.execute("DROP TRIGGER IF EXISTS trg_prevent_audit_update")
    conn.execute("UPDATE audit_events SET purpose = 'UnauthorizedPurpose' WHERE action = 'forensic_target'")
    conn.commit()
    conn.close()

    res = client.get("/api/audit/verify")
    assert res.status_code in (200, 409)
    data = res.get_json()
    assert data["status"] == "broken"
    assert data["detected_tampering"] is True
    assert len(data["tampered_records"]) > 0


# ============================================================================
# 5. PURPOSE-BASED DATA SHARING TESTS (8 TESTS)
# ============================================================================

def test_23_data_sharing_valid_consumer_request(part11_app):
    """Sharing 1: Authorized consumer successfully accesses data permitted by active consent."""
    client, _ = part11_app
    reg = client.post(
        "/api/auth/signup",
        json={"name": "Ken Sharing", "email": "ken.sharing@example.com", "password": "SecurePassword123!"},
    )
    user_id = reg.get_json()["user"]["id"]
    token = reg.get_json()["token"]

    client.post(
        "/api/consents",
        headers={"Authorization": f"Bearer {token}"},
        json={"purpose": "Analytics", "action": "grant"},
    )

    res = client.post(
        "/api/share/request",
        headers={"X-API-Key": DEFAULT_PARTNER_ALL_KEY},
        json={"user_id": user_id, "purpose": "Analytics", "requested_fields": ["page_views"]},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["allowed"] is True
    assert "page_views" in data["data"]


def test_24_data_sharing_invalid_api_key(part11_app):
    """Sharing 2: Request with invalid API key rejected with 401 INVALID_API_KEY."""
    client, _ = part11_app
    res = client.post(
        "/api/share/request",
        headers={"X-API-Key": "key_invalid_fake_1234567890"},
        json={"user_id": "any_user", "purpose": "Analytics"},
    )
    assert res.status_code == 401
    assert res.get_json()["reason_code"] == "INVALID_API_KEY"


def test_25_data_sharing_revoked_api_key(part11_app):
    """Sharing 3: Consumer whose API key has been revoked by admin is rejected with 401 API_KEY_REVOKED."""
    client, _ = part11_app
    admin_key = api.ADMIN_KEY

    # Revoke partner-limited key
    rev_res = client.post(
        "/api/consumers/revoke",
        headers={"X-Admin-Key": admin_key},
        json={"consumer_id": "partner-limited"},
    )
    assert rev_res.status_code == 200

    # Attempt data sharing
    res = client.post(
        "/api/share/request",
        headers={"X-API-Key": DEFAULT_PARTNER_LIMITED_KEY},
        json={"user_id": "any_user", "purpose": "Analytics"},
    )
    assert res.status_code == 401
    assert res.get_json()["reason_code"] == "API_KEY_REVOKED"


def test_26_data_sharing_unauthorized_purpose(part11_app):
    """Sharing 4: Consumer requesting purpose outside its authorization profile blocked with 403."""
    client, _ = part11_app
    # Partner-Limited is only authorized for 'Analytics'
    res = client.post(
        "/api/share/request",
        headers={"X-API-Key": DEFAULT_PARTNER_LIMITED_KEY},
        json={"user_id": "any_user", "purpose": "Marketing"},
    )
    assert res.status_code == 403
    assert res.get_json()["reason_code"] == "CONSUMER_NOT_AUTHORIZED"


def test_27_data_sharing_missing_consent(part11_app):
    """Sharing 5: Request for user who never granted consent rejected with 403 NO_CONSENT."""
    client, _ = part11_app
    reg = client.post(
        "/api/auth/signup",
        json={"name": "Leo NoConsent", "email": "leo.noconsent@example.com", "password": "SecurePassword123!"},
    )
    user_id = reg.get_json()["user"]["id"]

    res = client.post(
        "/api/share/request",
        headers={"X-API-Key": DEFAULT_PARTNER_ALL_KEY},
        json={"user_id": user_id, "purpose": "Analytics"},
    )
    assert res.status_code == 403
    assert res.get_json()["reason_code"] == "NO_CONSENT"


def test_28_data_sharing_withdrawn_consent(part11_app):
    """Sharing 6: Request blocked with 403 WITHDRAWN after user withdraws consent."""
    client, _ = part11_app
    reg = client.post(
        "/api/auth/signup",
        json={"name": "Mona Withdraw", "email": "mona.withdraw@example.com", "password": "SecurePassword123!"},
    )
    user_id = reg.get_json()["user"]["id"]
    token = reg.get_json()["token"]

    # Grant then withdraw
    client.post("/api/consents", headers={"Authorization": f"Bearer {token}"}, json={"purpose": "Analytics", "action": "grant"})
    client.post("/api/consents", headers={"Authorization": f"Bearer {token}"}, json={"purpose": "Analytics", "action": "withdraw"})

    res = client.post(
        "/api/share/request",
        headers={"X-API-Key": DEFAULT_PARTNER_ALL_KEY},
        json={"user_id": user_id, "purpose": "Analytics"},
    )
    assert res.status_code == 403
    assert res.get_json()["reason_code"] == "WITHDRAWN"


def test_29_data_sharing_partner_all_restrictions(part11_app):
    """Sharing 7: Partner-All can access multiple authorized purposes if consent is valid, but blocked if missing."""
    client, _ = part11_app
    reg = client.post(
        "/api/auth/signup",
        json={"name": "Nina PartnerAll", "email": "nina.partnerall@example.com", "password": "SecurePassword123!"},
    )
    user_id = reg.get_json()["user"]["id"]
    token = reg.get_json()["token"]

    # Grant only Marketing
    client.post("/api/consents", headers={"Authorization": f"Bearer {token}"}, json={"purpose": "Marketing", "action": "grant"})

    # Marketing allowed
    m_res = client.post(
        "/api/share/request",
        headers={"X-API-Key": DEFAULT_PARTNER_ALL_KEY},
        json={"user_id": user_id, "purpose": "Marketing"},
    )
    assert m_res.status_code == 200

    # Analytics blocked (no consent)
    a_res = client.post(
        "/api/share/request",
        headers={"X-API-Key": DEFAULT_PARTNER_ALL_KEY},
        json={"user_id": user_id, "purpose": "Analytics"},
    )
    assert a_res.status_code == 403


def test_30_data_sharing_partner_limited_restrictions(part11_app):
    """Sharing 8: Partner-Limited is restricted strictly to authorized subset fields."""
    client, _ = part11_app
    reg = client.post(
        "/api/auth/signup",
        json={"name": "Oscar Limited", "email": "oscar.limited@example.com", "password": "SecurePassword123!"},
    )
    user_id = reg.get_json()["user"]["id"]
    token = reg.get_json()["token"]

    client.post("/api/consents", headers={"Authorization": f"Bearer {token}"}, json={"purpose": "Analytics", "action": "grant"})

    # Requesting unauthorized fields (e.g., credit card or non-permitted fields)
    res = client.post(
        "/api/share/request",
        headers={"X-API-Key": DEFAULT_PARTNER_LIMITED_KEY},
        json={"user_id": user_id, "purpose": "Analytics", "requested_fields": ["unauthorized_pii_field"]},
    )
    assert res.status_code == 403
    assert res.get_json()["reason_code"] == "UNAUTHORIZED_FIELDS"


# ============================================================================
# 6. SECURITY PROTECTIONS TESTS (5 TESTS)
# ============================================================================

def test_31_security_invalid_input(part11_app):
    """Security 1: Malformed and non-dictionary JSON payloads safely rejected with 400 Bad Request."""
    client, _ = part11_app
    # Array payload
    res = client.post(
        "/api/auth/login",
        data="['malformed', 'array']",
        content_type="application/json",
    )
    assert res.status_code == 400
    assert "MISSING" in res.get_json().get("reason_code", "")


def test_32_security_sql_injection_resilience(part11_app):
    """Security 2: SQL injection payloads handled safely via parameterized queries without syntax error or leak."""
    client, _ = part11_app
    sqli_payload = "' OR '1'='1' --"
    res = client.post(
        "/api/auth/login",
        json={"email": sqli_payload, "password": "some_password"},
    )
    assert res.status_code == 401
    assert res.get_json()["reason_code"] == "INVALID_CREDENTIALS"


def test_33_security_cors_restrictions(part11_app):
    """Security 3: Disallowed origin does not receive Access-Control-Allow-Origin header."""
    client, _ = part11_app
    # Disallowed origin
    res = client.get("/api/health", headers={"Origin": "https://malicious-site.attacker.com"})
    assert res.headers.get("Access-Control-Allow-Origin") != "https://malicious-site.attacker.com"

    # Preflight for allowed origin
    options_res = client.open("/api/health", method="OPTIONS", headers={"Origin": "http://localhost:3000"})
    assert options_res.status_code == 204
    assert options_res.headers.get("Access-Control-Allow-Origin") == "http://localhost:3000"


def test_34_security_error_information_leakage(part11_app):
    """Security 4: Database failures and errors do not expose credentials, connection strings, or tracebacks."""
    client, _ = part11_app
    with patch("api.get_connection") as mock_conn:
        mock_conn.side_effect = sqlite3.OperationalError("Sensitive internal path: /var/secrets/db_password")
        res = client.get("/api/health")
        assert res.status_code == 503
        data_str = res.get_data(as_text=True)
        assert "/var/secrets" not in data_str
        assert "OperationalError" not in data_str


def test_35_security_rate_limiting(part11_app):
    """Security 5: In-memory sliding-window rate limiter prevents brute-force or rapid request floods."""
    limiter = api.InMemoryRateLimiter()
    ip = "192.168.1.100"
    # Trigger 5 requests with max 5
    for _ in range(5):
        assert limiter.is_rate_limited(ip, max_requests=5, window_seconds=60) is False
    # 6th request is rate limited
    assert limiter.is_rate_limited(ip, max_requests=5, window_seconds=60) is True


# ============================================================================
# 7. 100% OFFLINE RESILIENCE TESTS (6 TESTS)
# ============================================================================

def test_36_offline_local_database_initialization():
    """Offline 1: Local SQLite database schema initializes cleanly offline without network connectivity."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
        test_db = Path(temp_dir) / "offline_init.db"
        with patch.object(database, "DATABASE_PATH", test_db):
            with patch.dict(os.environ, {"DATABASE_URL": ""}):
                initialize_database()
                assert test_db.exists()

                conn = sqlite3.connect(str(test_db))
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = {row[0] for row in cursor.fetchall()}
                cursor.close()
                conn.close()
                del cursor, conn
                gc.collect()

                expected = {"users", "notice_versions", "purposes", "consents", "audit_events", "consumers"}
                assert expected.issubset(tables)


def test_37_offline_synthetic_data_initialization():
    """Offline 2: Synthetic demo users, purposes, notices, and consumers populate offline."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
        test_db = Path(temp_dir) / "offline_synthetic.db"
        with patch.object(database, "DATABASE_PATH", test_db):
            with patch.dict(os.environ, {"DATABASE_URL": ""}):
                initialize_database()

                conn = sqlite3.connect(str(test_db))
                conn.row_factory = sqlite3.Row
                # Verify demo users exist
                demo_user = conn.execute("SELECT * FROM users WHERE email = 'demo@consentguard.local'").fetchone()
                assert demo_user is not None

                # Verify default purposes exist
                purposes = conn.execute("SELECT COUNT(*) FROM purposes").fetchone()[0]
                assert purposes >= 3

                # Verify consumers exist
                consumers = conn.execute("SELECT COUNT(*) FROM consumers").fetchone()[0]
                assert consumers >= 2
                conn.close()
                del conn
                gc.collect()


def test_38_offline_authentication(part11_app):
    """Offline 3: Offline PBKDF2/SHA-256 password hashing, registration, and signed token validation function without network."""
    client, _ = part11_app
    res = client.post(
        "/api/auth/signup",
        json={"name": "Offline User", "email": "offline.user@local.test", "password": "OfflinePassword123!"},
    )
    assert res.status_code == 201
    token = res.get_json()["token"]

    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    assert me_res.get_json()["user"]["email"] == "offline.user@local.test"


def test_39_offline_consent(part11_app):
    """Offline 4: Consent lifecycle (grant, status inspection, withdraw) executes completely offline."""
    client, _ = part11_app
    reg = client.post(
        "/api/auth/signup",
        json={"name": "Offline Consent", "email": "offline.consent@local.test", "password": "OfflinePassword123!"},
    )
    token = reg.get_json()["token"]

    # Grant
    g_res = client.post("/api/consents", headers={"Authorization": f"Bearer {token}"}, json={"purpose": "Analytics", "action": "grant"})
    assert g_res.status_code == 201

    # Inspect
    s_res = client.get("/api/consents", headers={"Authorization": f"Bearer {token}"})
    assert any(c["purpose"] == "Analytics" and c["granted"] == 1 for c in s_res.get_json())

    # Withdraw
    w_res = client.post("/api/consents", headers={"Authorization": f"Bearer {token}"}, json={"purpose": "Analytics", "action": "withdraw"})
    assert w_res.status_code == 201
    assert w_res.get_json()["granted"] is False


def test_40_offline_audit(part11_app):
    """Offline 5: Cryptographic Merkle DAG audit events generate and chain together offline."""
    _, test_db = part11_app
    with get_connection() as conn:
        h1 = append_audit_event(conn, "offline_u1", "Analytics", "offline_event_1", 200, "OK", "1.0", "h")
        h2 = append_audit_event(conn, "offline_u1", "Marketing", "offline_event_2", 200, "OK", "1.0", "h")
        assert len(h1) == 64 and len(h2) == 64

        res = verify_audit_chain(conn)
        assert res["status"] == "intact"
        assert res["detected_tampering"] is False


def test_41_offline_sharing(part11_app):
    """Offline 6: PEP centralized authorization and purpose-based data sharing execute 100% offline."""
    client, _ = part11_app
    reg = client.post(
        "/api/auth/signup",
        json={"name": "Offline Sharing", "email": "offline.sharing@local.test", "password": "OfflinePassword123!"},
    )
    user_id = reg.get_json()["user"]["id"]
    token = reg.get_json()["token"]

    client.post("/api/consents", headers={"Authorization": f"Bearer {token}"}, json={"purpose": "Analytics", "action": "grant"})

    share_res = client.post(
        "/api/share/request",
        headers={"X-API-Key": DEFAULT_PARTNER_ALL_KEY},
        json={"user_id": user_id, "purpose": "Analytics"},
    )
    assert share_res.status_code == 200
    assert share_res.get_json()["allowed"] is True
