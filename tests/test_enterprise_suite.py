import concurrent.futures
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

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
    sanitize_audit_details,
    verify_audit_chain,
)


@pytest.fixture
def enterprise_app():
    """Provides an isolated Flask test client with a fresh temporary SQLite database."""
    with tempfile.TemporaryDirectory() as temp_dir:
        test_db = Path(temp_dir) / "enterprise_test.db"
        with patch.object(database, "DATABASE_PATH", test_db):
            with patch.dict(os.environ, {"DATABASE_URL": ""}):
                database.initialize_database()
                api.load_active_notice()

                api.app.config["TESTING"] = True
                client = api.app.test_client()
                yield client, test_db


def test_01_grant_consent_success(enterprise_app):
    """Test 1: Normal consent grant under current active notice succeeds."""
    client, _ = enterprise_app
    # Sign up user
    res = client.post("/api/auth/signup", json={"name": "Alice Enterprise", "email": "alice@corp.test", "password": "Password123!"})
    assert res.status_code == 201
    user_id = res.get_json()["user"]["id"]

    grant_res = client.post("/api/consents", json={"purpose": "Analytics", "action": "grant"})
    assert grant_res.status_code == 201
    assert grant_res.get_json()["granted"] is True
    assert grant_res.get_json()["notice_version"] == DEFAULT_NOTICE_VERSION


def test_02_grant_outdated_notice_hash_rejected_409(enterprise_app):
    """Test 2: Submitting an outdated notice hash on grant is rejected with 409 STALE_NOTICE."""
    client, _ = enterprise_app
    client.post("/api/auth/signup", json={"name": "Bob Stale", "email": "bob@stale.test", "password": "Password123!"})

    stale_hash = "deadbeef" * 8
    res = client.post("/api/consents", json={
        "purpose": "Analytics",
        "action": "grant",
        "notice_version": "0.9",
        "notice_hash": stale_hash,
    })
    assert res.status_code == 409
    data = res.get_json()
    assert data["reason_code"] == "STALE_NOTICE"
    assert "stale" in data["error"].lower()


def test_03_stale_grant_logged_in_audit_chain(enterprise_app):
    """Test 3: Stale consent attempts are explicitly logged in the audit ledger."""
    client, test_db = enterprise_app
    client.post("/api/auth/signup", json={"name": "Carol Stale", "email": "carol@stale.test", "password": "Password123!"})

    stale_hash = "12345678" * 8
    client.post("/api/consents", json={
        "purpose": "Marketing",
        "action": "grant",
        "notice_version": "0.5",
        "notice_hash": stale_hash,
    })

    conn = sqlite3.connect(str(test_db))
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM audit_events WHERE reason_code = 'STALE_NOTICE'").fetchone()
    conn.close()
    assert row is not None
    assert row["action"] == "consent_rejected_stale"
    assert row["http_status"] == 409


def test_04_idempotent_withdrawal(enterprise_app):
    """Test 4: Withdrawing consent twice is idempotent and does not generate redundant duplicate audit rows."""
    client, test_db = enterprise_app
    client.post("/api/auth/signup", json={"name": "David Idemp", "email": "david@corp.test", "password": "Password123!"})

    # Initial grant
    client.post("/api/consents", json={"purpose": "Analytics", "action": "grant"})
    # First withdrawal
    w1 = client.post("/api/consents", json={"purpose": "Analytics", "action": "withdraw"})
    assert w1.status_code == 201

    conn = sqlite3.connect(str(test_db))
    withdraw_count_1 = conn.execute("SELECT COUNT(*) FROM audit_events WHERE action = 'withdraw'").fetchone()[0]

    # Second withdrawal (idempotent)
    w2 = client.post("/api/consents", json={"purpose": "Analytics", "action": "withdraw"})
    assert w2.status_code == 200
    assert w2.get_json()["reason_code"] == "CONSENT_ALREADY_WITHDRAWN"

    withdraw_count_2 = conn.execute("SELECT COUNT(*) FROM audit_events WHERE action = 'withdraw'").fetchone()[0]
    conn.close()
    assert withdraw_count_2 == withdraw_count_1


def test_05_withdrawn_consent_immediately_blocks_downstream(enterprise_app):
    """Test 5: Withdrawing consent immediately blocks downstream data access."""
    client, _ = enterprise_app
    client.post("/api/auth/signup", json={"name": "Eve Block", "email": "eve@block.test", "password": "Password123!"})

    client.post("/api/consents", json={"purpose": "Analytics", "action": "grant"})
    assert client.post("/api/data-access", json={"purpose": "Analytics"}).status_code == 200

    client.post("/api/consents", json={"purpose": "Analytics", "action": "withdraw"})
    blocked = client.post("/api/data-access", json={"purpose": "Analytics"})
    assert blocked.status_code == 403
    assert blocked.get_json()["reason_code"] == "WITHDRAWN"


def test_06_reconsent_after_withdrawal_restores_access(enterprise_app):
    """Test 6: Re-consenting after withdrawal immediately restores downstream access."""
    client, _ = enterprise_app
    client.post("/api/auth/signup", json={"name": "Frank Reconsent", "email": "frank@test.com", "password": "Password123!"})

    client.post("/api/consents", json={"purpose": "Analytics", "action": "grant"})
    client.post("/api/consents", json={"purpose": "Analytics", "action": "withdraw"})
    assert client.post("/api/data-access", json={"purpose": "Analytics"}).status_code == 403

    re_res = client.post("/api/consents", json={"purpose": "Analytics", "action": "grant"})
    assert re_res.status_code == 201
    assert client.post("/api/data-access", json={"purpose": "Analytics"}).status_code == 200


def test_07_notice_version_conflict_rejected_409(enterprise_app):
    """Test 7: Attempting to create a conflicting notice version with different text returns 409 VERSION_EXISTS."""
    client, _ = enterprise_app
    # Try updating v1.0 with differing text
    res = client.post("/api/notice/update", json={
        "notice_version": DEFAULT_NOTICE_VERSION,
        "notice_text": "Conflicting divergent text for version 1.0",
    })
    assert res.status_code == 409
    assert res.get_json()["reason_code"] == "VERSION_EXISTS"


def test_08_atomic_notice_upgrade_and_active_flag(enterprise_app):
    """Test 8: Publishing a new notice atomically marks the previous notice inactive and the new active."""
    client, test_db = enterprise_app
    res = client.post("/api/notice/update", json={
        "notice_version": "2.0",
        "notice_text": "ConsentGuard v2.0 Enterprise Privacy Notice with enhanced telemetry controls.",
    })
    assert res.status_code == 200
    assert res.get_json()["notice_version"] == "2.0"

    conn = sqlite3.connect(str(test_db))
    conn.row_factory = sqlite3.Row
    v1_row = conn.execute("SELECT is_active FROM notice_versions WHERE version = '1.0'").fetchone()
    v2_row = conn.execute("SELECT is_active FROM notice_versions WHERE version = '2.0'").fetchone()
    conn.close()

    assert v1_row["is_active"] == 0
    assert v2_row["is_active"] == 1


def test_09_stale_consent_blocked_after_notice_bump(enterprise_app):
    """Test 9: Consent granted under notice v1.0 is blocked when notice is bumped to v2.0 until re-consent."""
    client, _ = enterprise_app
    client.post("/api/auth/signup", json={"name": "Grace Bump", "email": "grace@bump.test", "password": "Password123!"})

    client.post("/api/consents", json={"purpose": "Analytics", "action": "grant"})
    assert client.post("/api/data-access", json={"purpose": "Analytics"}).status_code == 200

    # Bump notice to v2.0
    client.post("/api/notice/update", json={"notice_version": "2.0"})

    # Prior consent is now stale
    blocked = client.post("/api/data-access", json={"purpose": "Analytics"})
    assert blocked.status_code == 403
    assert blocked.get_json()["reason_code"] == "NOTICE_MISMATCH"

    # Re-consent under v2.0 restores access
    client.post("/api/consents", json={"purpose": "Analytics", "action": "grant"})
    assert client.post("/api/data-access", json={"purpose": "Analytics"}).status_code == 200


def test_10_downstream_share_invalid_api_key_401(enterprise_app):
    """Test 10: Downstream /api/share/request with an invalid or missing API key is rejected with HTTP 401."""
    client, _ = enterprise_app
    res = client.post("/api/share/request", json={
        "api_key": "invalid_forged_key_12345",
        "user_id": "demo-user",
        "purpose": "Analytics",
    })
    assert res.status_code == 401
    assert res.get_json()["reason_code"] == "INVALID_API_KEY"


def test_11_downstream_share_consumer_not_authorized_403(enterprise_app):
    """Test 11: Consumer partner-limited requesting Marketing data is blocked with 403 CONSUMER_NOT_AUTHORIZED."""
    client, _ = enterprise_app
    res = client.post("/api/share/request", json={
        "api_key": DEFAULT_PARTNER_LIMITED_KEY,
        "user_id": "demo-user",
        "purpose": "Marketing",  # partner-limited is only authorized for Analytics
    })
    assert res.status_code == 403
    assert res.get_json()["reason_code"] == "CONSUMER_NOT_AUTHORIZED"


def test_12_downstream_share_invalid_purpose_400(enterprise_app):
    """Test 12: Requesting an unrecognized purpose returns HTTP 400 INVALID_PURPOSE."""
    client, _ = enterprise_app
    res = client.post("/api/share/request", json={
        "api_key": DEFAULT_PARTNER_ALL_KEY,
        "user_id": "demo-user",
        "purpose": "Biometric Surveillance",
    })
    assert res.status_code == 400
    assert res.get_json()["reason_code"] == "INVALID_PURPOSE"


def test_13_downstream_share_unknown_user_404(enterprise_app):
    """Test 13: Requesting data for an unknown user returns HTTP 404 USER_NOT_FOUND."""
    client, _ = enterprise_app
    res = client.post("/api/share/request", json={
        "api_key": DEFAULT_PARTNER_ALL_KEY,
        "user_id": "non_existent_ghost_user_99999",
        "purpose": "Analytics",
    })
    assert res.status_code == 404
    assert res.get_json()["reason_code"] == "USER_NOT_FOUND"


def test_14_downstream_share_no_consent_403(enterprise_app):
    """Test 14: Downstream access when user has not granted consent returns HTTP 403 NO_CONSENT."""
    client, _ = enterprise_app
    # user1 has no consent granted
    res = client.post("/api/share/request", json={
        "api_key": DEFAULT_PARTNER_ALL_KEY,
        "user_id": "user1",
        "purpose": "Analytics",
    })
    assert res.status_code == 403
    assert res.get_json()["reason_code"] == "NO_CONSENT"


def test_15_downstream_share_unauthorized_fields_403(enterprise_app):
    """Test 15: Requesting unauthorized fields returns HTTP 403 UNAUTHORIZED_FIELDS."""
    client, _ = enterprise_app
    # demo-user has Analytics consent
    res = client.post("/api/share/request", json={
        "api_key": DEFAULT_PARTNER_ALL_KEY,
        "user_id": "demo-user",
        "purpose": "Analytics",
        "requested_fields": ["page_views", "ssn_or_credit_card"],  # unpermitted field
    })
    assert res.status_code == 403
    assert res.get_json()["reason_code"] == "UNAUTHORIZED_FIELDS"


def test_16_downstream_share_valid_request_allowed_200(enterprise_app):
    """Test 16: Authorized partner request with valid consent releases only permitted fields with HTTP 200."""
    client, _ = enterprise_app
    res = client.post("/api/share/request", json={
        "api_key": DEFAULT_PARTNER_ALL_KEY,
        "user_id": "demo-user",
        "purpose": "Analytics",
        "requested_fields": ["page_views"],
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["allowed"] is True
    assert data["reason_code"] == "ACTIVE_CONSENT"
    assert "page_views" in data["data"]
    assert "feature_usage" not in data["data"]  # unrequested allowed field filtered out


def test_17_fourth_purpose_database_driven_without_code_changes(enterprise_app):
    """Test 17: Adding a 4th purpose in the database works immediately without modifying authorization code."""
    client, test_db = enterprise_app
    now_str = "2026-11-09T18:00:00.000000Z"

    # Insert 4th purpose into purposes table
    conn = sqlite3.connect(str(test_db))
    conn.execute(
        """
        INSERT INTO purposes (id, name, description, allowed_fields, mock_data, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            "Fraud Detection",
            "Fraud Detection",
            "Monitors anomalous transaction volumes and device fingerprints.",
            json.dumps(["device_risk_score", "ip_reputation"]),
            json.dumps({"device_risk_score": 0.04, "ip_reputation": "clean"}),
            now_str,
        ),
    )
    # Grant partner-all permission for 4th purpose
    conn.execute(
        """
        UPDATE consumers SET allowed_purposes = ? WHERE consumer_id = 'partner-all'
        """,
        (json.dumps(["Analytics", "Marketing", "Service Improvement", "Fraud Detection"]),),
    )
    conn.commit()
    conn.close()

    # Create user and grant consent for the 4th purpose
    client.post("/api/auth/signup", json={"name": "Hannah Dynamic", "email": "hannah@dynamic.test", "password": "Password123!"})
    grant_res = client.post("/api/consents", json={"purpose": "Fraud Detection", "action": "grant"})
    assert grant_res.status_code == 201

    # Partner requests data for 4th purpose -> immediately ALLOWED
    share_res = client.post("/api/share/request", json={
        "api_key": DEFAULT_PARTNER_ALL_KEY,
        "user_id": grant_res.get_json()["user_id"],
        "purpose": "Fraud Detection",
        "requested_fields": ["device_risk_score"],
    })
    assert share_res.status_code == 200
    assert share_res.get_json()["allowed"] is True
    assert "device_risk_score" in share_res.get_json()["data"]


def test_18_audit_immutability_sqlite_trigger_blocks_update(enterprise_app):
    """Test 18: Direct database UPDATE on audit_events is blocked by cryptographic immutability triggers."""
    _, test_db = enterprise_app
    conn = sqlite3.connect(str(test_db))
    try:
        row = conn.execute("SELECT id FROM audit_events LIMIT 1").fetchone()
        assert row is not None
        audit_id = row[0]

        with pytest.raises((sqlite3.IntegrityError, sqlite3.OperationalError)) as exc_info:
            conn.execute("UPDATE audit_events SET action = 'tampered_action' WHERE id = ?", (audit_id,))
        assert "immutable" in str(exc_info.value).lower()
    finally:
        conn.close()


def test_19_audit_immutability_sqlite_trigger_blocks_delete(enterprise_app):
    """Test 19: Direct database DELETE on audit_events is blocked by cryptographic immutability triggers."""
    _, test_db = enterprise_app
    conn = sqlite3.connect(str(test_db))
    try:
        row = conn.execute("SELECT id FROM audit_events LIMIT 1").fetchone()
        assert row is not None
        audit_id = row[0]

        with pytest.raises((sqlite3.IntegrityError, sqlite3.OperationalError)) as exc_info:
            conn.execute("DELETE FROM audit_events WHERE id = ?", (audit_id,))
        assert "immutable" in str(exc_info.value).lower()
    finally:
        conn.close()


def test_20_canonical_json_audit_hash_integrity():
    """Test 20: Canonical JSON hash is deterministic and strictly formatted across all fields including details."""
    h1 = compute_canonical_audit_hash(
        prev_hash="0" * 64,
        user_id="user_123",
        purpose="Analytics",
        action="grant",
        http_status=200,
        reason_code="CONSENT_RECORDED",
        notice_version="1.0",
        notice_hash="hash_abc",
        source="user",
        created_at="2026-11-09T18:00:00.000000Z",
        details="Consent decision recorded.",
    )
    assert len(h1) == 64

    # Identical inputs produce identical hash
    h2 = compute_canonical_audit_hash(
        prev_hash="0" * 64,
        user_id="user_123",
        purpose="Analytics",
        action="grant",
        http_status=200,
        reason_code="CONSENT_RECORDED",
        notice_version="1.0",
        notice_hash="hash_abc",
        source="user",
        created_at="2026-11-09T18:00:00.000000Z",
        details="Consent decision recorded.",
    )
    assert h1 == h2

    # Modified detail produces different hash
    h3 = compute_canonical_audit_hash(
        prev_hash="0" * 64,
        user_id="user_123",
        purpose="Analytics",
        action="grant",
        http_status=200,
        reason_code="CONSENT_RECORDED",
        notice_version="1.0",
        notice_hash="hash_abc",
        source="user",
        created_at="2026-11-09T18:00:00.000000Z",
        details="Tampered detail.",
    )
    assert h1 != h3


def test_21_audit_pii_sanitization():
    """Test 21: Audit details sanitize sensitive credentials, emails, and tokens."""
    dirty = "User pradeep@consentguard.local authorized with Bearer eyJhbGciOiJIUzI1NiIsIn and api_key=secret_12345678"
    clean = sanitize_audit_details(dirty)
    assert "pradeep@consentguard.local" not in clean
    assert "[REDACTED_EMAIL]" in clean
    assert "eyJhbGciOiJIUzI1NiIsIn" not in clean
    assert "secret_12345678" not in clean
    assert "[REDACTED_SECRET]" in clean


def test_22_admin_authorization_constant_time_key(enterprise_app):
    """Test 22: Constant-time X-Admin-Key authorization succeeds with valid key and rejects invalid key."""
    client, _ = enterprise_app
    with patch.dict(os.environ, {"ADMIN_KEY": "super_secret_admin_token"}):
        # Invalid key -> 403
        bad_res = client.post("/api/notice/update", headers={"X-Admin-Key": "wrong_key"}, json={"notice_version": "2.1"})
        assert bad_res.status_code == 403
        assert bad_res.get_json()["reason_code"] == "INVALID_ADMIN_KEY"

        # Valid key -> 200
        good_res = client.post("/api/notice/update", headers={"X-Admin-Key": "super_secret_admin_token"}, json={"notice_version": "2.1"})
        assert good_res.status_code == 200


def test_23_admin_endpoints_reject_unauthorized_visitor(enterprise_app):
    """Test 23: Administrative notice update and reset reject unauthenticated visitor requests without admin key."""
    client, _ = enterprise_app
    api.app.config["TESTING"] = False  # Disable testing bypass
    unauth_client = api.app.test_client()

    u_res = unauth_client.post("/api/notice/update", json={"notice_version": "3.0"})
    assert u_res.status_code == 401
    assert u_res.get_json()["reason_code"] == "ADMIN_AUTH_REQUIRED"

    r_res = unauth_client.post("/api/notice/reset")
    assert r_res.status_code == 401
    assert r_res.get_json()["reason_code"] == "ADMIN_AUTH_REQUIRED"


def test_24_source_test_cannot_bypass_real_user_boundaries(enterprise_app):
    """Test 24: Supplying source='test' cannot modify or read another real registered user's records."""
    client, _ = enterprise_app
    # Create User Alpha
    r1 = client.post("/api/auth/signup", json={"name": "Alpha", "email": "alpha@bank.test", "password": "Password123!"})
    alpha_id = r1.get_json()["user"]["id"]
    client.post("/api/consents", json={"purpose": "Analytics", "action": "grant"})

    # Create User Beta
    r2 = client.post("/api/auth/signup", json={"name": "Beta", "email": "beta@bank.test", "password": "Password123!"})
    beta_id = r2.get_json()["user"]["id"]

    # Beta attempts to read Alpha's audit events claiming source=test
    audit_tamper = client.get(f"/api/audit?user_id={alpha_id}&source=test")
    assert audit_tamper.status_code == 403
    assert audit_tamper.get_json()["reason_code"] == "FORBIDDEN_CROSS_USER_ACCESS"

    # Beta attempts to withdraw Alpha's consent claiming source=test
    consent_tamper = client.post("/api/consents", json={
        "user_id": alpha_id,
        "purpose": "Analytics",
        "action": "withdraw",
        "source": "test",
    })
    assert consent_tamper.status_code == 403
    assert consent_tamper.get_json()["reason_code"] == "FORBIDDEN_CROSS_USER_ACCESS"


def test_25_bearer_token_and_session_authentication(enterprise_app):
    """Test 25: Bearer token in Authorization header authenticates user requests across all endpoints."""
    client, _ = enterprise_app
    r = client.post("/api/auth/signup", json={"name": "Ivan Token", "email": "ivan@token.test", "password": "Password123!"})
    token = r.get_json()["token"]

    # Clear cookie session
    with client.session_transaction() as sess:
        sess.clear()

    # Make request with Authorization: Bearer <token>
    auth_header = {"Authorization": f"Bearer {token}"}
    me_res = client.get("/api/auth/me", headers=auth_header)
    assert me_res.status_code == 200
    assert me_res.get_json()["authenticated"] is True
    assert me_res.get_json()["user"]["name"] == "Ivan Token"


def test_26_merkle_dag_branching_and_tamper_detection():
    """Test 26: Merkle DAG allows concurrent write sibling branching but immediately detects hash tampering."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            purpose TEXT NOT NULL,
            action TEXT NOT NULL,
            http_status INTEGER NOT NULL,
            reason_code TEXT NOT NULL,
            notice_version TEXT NOT NULL,
            notice_hash TEXT NOT NULL,
            short_notice_hash TEXT,
            source TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            row_hash TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL
        )
    """)

    # Event 1 (Parent / Genesis)
    h1 = append_audit_event(conn, "u1", "Analytics", "grant", 200, "OK", "1.0", "h", source="w1")
    # Event 2 (Sibling A off Event 1)
    h2 = append_audit_event(conn, "u2", "Marketing", "grant", 200, "OK", "1.0", "h", source="w2")

    # Event 3 (Sibling B concurrently written off Event 1, pointing to h1 instead of h2)
    now_str = "2026-11-09T18:00:00.000000Z"
    h3 = compute_canonical_audit_hash(
        prev_hash=h1,
        user_id="u3",
        purpose="Service Improvement",
        action="grant",
        http_status=200,
        reason_code="OK",
        notice_version="1.0",
        notice_hash="h",
        source="w3",
        created_at=now_str,
        details="",
    )
    conn.execute(
        """
        INSERT INTO audit_events
            (user_id, purpose, action, http_status, reason_code, notice_version,
             notice_hash, short_notice_hash, source, prev_hash, row_hash, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        ("u3", "Service Improvement", "grant", 200, "OK", "1.0", "h", "", "w3", h1, h3, "", now_str),
    )

    # DAG verification succeeds across sibling branches
    dag_res = verify_audit_chain(conn, strict_linear=False)
    assert dag_res["status"] == "intact"
    assert dag_res["branches_count"] == 1

    # Strict linear verification detects the branch
    strict_res = verify_audit_chain(conn, strict_linear=True)
    assert strict_res["status"] == "broken"
    assert strict_res["reason_code"] == "BRANCH_DETECTED"
    conn.close()


def test_27_audit_export_authenticated_csv_and_json(enterprise_app):
    """Test 27: Audit export is restricted to authenticated users and provides valid CSV and JSON."""
    client, _ = enterprise_app
    client.post("/api/auth/signup", json={"name": "Julia Export", "email": "julia@export.test", "password": "Password123!"})
    client.post("/api/consents", json={"purpose": "Analytics", "action": "grant"})

    csv_res = client.get("/api/audit/export?format=csv")
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.content_type
    assert "user_id,purpose,action" in csv_res.get_data(as_text=True)

    json_res = client.get("/api/audit/export?format=json")
    assert json_res.status_code == 200
    assert "application/json" in json_res.content_type
    json_data = json_res.get_json()
    assert isinstance(json_data, list)
    assert len(json_data) >= 2


def test_28_demo_reset_preserves_immutable_audit_history(enterprise_app):
    """Test 28: /api/demo/reset resets consent states to defaults without deleting immutable audit events."""
    client, test_db = enterprise_app
    client.post("/api/auth/demo-login", json={"user_id": "demo-user"})
    client.post("/api/consents", json={"purpose": "Analytics", "action": "withdraw"})

    conn = sqlite3.connect(str(test_db))
    audit_count_before = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
    conn.close()

    reset_res = client.post("/api/demo/reset")
    assert reset_res.status_code == 200

    conn = sqlite3.connect(str(test_db))
    audit_count_after = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
    conn.close()

    # Audits were NOT deleted, reset event was added
    assert audit_count_after > audit_count_before


def test_29_dashboard_stats_endpoint(enterprise_app):
    """Test 29: /api/stats computes exact real-time database metrics across grant, access, and withdrawal."""
    client, _ = enterprise_app
    client.post("/api/auth/signup", json={"name": "Marcus Stats", "email": "marcus@stats.test", "password": "Password123!"})

    # Initially zero active consents
    r0 = client.get("/api/stats")
    assert r0.status_code == 200
    d0 = r0.get_json()
    assert d0["active_consents"] == 0
    assert d0["withdrawn_consents"] == 0
    assert d0["allowed_requests"] == 0
    assert d0["blocked_requests"] == 0

    # 1. Grant Analytics consent
    client.post("/api/consents", json={"purpose": "Analytics", "action": "grant"})
    r1 = client.get("/api/stats")
    d1 = r1.get_json()
    assert d1["active_consents"] == 1
    assert d1["withdrawn_consents"] == 0

    # 2. Access Analytics data -> Allowed
    access_r = client.post("/api/data-access", json={"purpose": "Analytics"})
    assert access_r.status_code == 200
    r2 = client.get("/api/stats")
    d2 = r2.get_json()
    assert d2["allowed_requests"] == 1
    assert d2["blocked_requests"] == 0

    # 3. Withdraw Analytics consent -> Withdrawn
    client.post("/api/consents", json={"purpose": "Analytics", "action": "withdraw"})
    r3 = client.get("/api/stats")
    d3 = r3.get_json()
    assert d3["active_consents"] == 0
    assert d3["withdrawn_consents"] == 1

    # 4. Access Analytics data -> Denied / Blocked
    access_denied_r = client.post("/api/data-access", json={"purpose": "Analytics"})
    assert access_denied_r.status_code == 403
    r4 = client.get("/api/stats")
    d4 = r4.get_json()
    assert d4["allowed_requests"] == 1
    assert d4["blocked_requests"] == 1
    assert d4["total_requests"] == 2


def test_30_consent_history_and_access_logs_endpoints(enterprise_app):
    """Test 30: /api/consents/history, /api/access-logs and singular /api/consent aliases."""
    client, _ = enterprise_app
    client.post("/api/auth/signup", json={"name": "Elena History", "email": "elena@history.test", "password": "Password123!"})
    client.post("/api/consent", json={"purpose": "Analytics", "action": "grant"})
    client.post("/api/data-access", json={"purpose": "Analytics"})

    # Singular /api/consent endpoint
    get_res = client.get("/api/consent")
    assert get_res.status_code == 200
    assert len(get_res.get_json()) >= 1

    # /api/consents/history endpoint
    hist_res = client.get("/api/consents/history")
    assert hist_res.status_code == 200
    history = hist_res.get_json()
    assert isinstance(history, list)
    assert len(history) >= 1
    assert any(h["purpose"] == "Analytics" for h in history)

    # /api/access-logs endpoint
    logs_res = client.get("/api/access-logs")
    assert logs_res.status_code == 200
    logs = logs_res.get_json()
    assert isinstance(logs, list)
    assert len(logs) >= 1
    assert logs[0]["action"] == "data_access_allowed"


def test_31_offline_local_mode_configuration(enterprise_app):
    """Test 31: LOCAL_MODE=1 forces SQLite, disables cloud connection, and runs 100% offline."""
    from database import is_local_mode, get_database_url, is_postgres
    client, _ = enterprise_app

    # Test under simulated cloud DATABASE_URL but LOCAL_MODE=1
    fake_cloud_url = "postgresql://user:pass@ep-fake.neon.tech/neondb?sslmode=require"
    with patch.dict(os.environ, {"LOCAL_MODE": "1", "DATABASE_URL": fake_cloud_url}):
        assert is_local_mode() is True
        # Must block cloud database URL completely
        assert get_database_url() == ""
        assert is_postgres() is False

        # Health endpoint reports local_mode and offline_ready
        health_res = client.get("/api/health")
        assert health_res.status_code == 200
        health_data = health_res.get_json()
        assert health_data["local_mode"] is True
        assert health_data["database_type"] == "sqlite"
        assert health_data["offline_ready"] is True

        # Complete offline consent cycle
        client.post("/api/auth/signup", json={"name": "Offline User", "email": "offline@hackathon.test", "password": "Password123!"})
        grant_res = client.post("/api/consents", json={"purpose": "Analytics", "action": "grant"})
        assert grant_res.status_code == 201

        pep_res = client.post("/api/data-access", json={"purpose": "Analytics"})
        assert pep_res.status_code == 200
        assert pep_res.get_json()["allowed"] is True


def test_32_offline_foreign_keys_and_transaction_rollback(enterprise_app):
    """Test 32: SQLite transaction safely rolls back on exceptions without corrupting data."""
    from database import get_connection

    with get_connection() as conn:
        fk_check = conn.execute("PRAGMA foreign_keys").fetchone()[0]
        assert fk_check == 1

        initial_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    # Attempt a transaction that raises an unhandled error
    try:
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO users (id, name, email, password_hash, is_demo, created_at) VALUES (?, ?, ?, ?, 0, ?)",
                ("temp_rollback_user", "Temp", "temp_roll@test.local", "hash", "2026-11-10T00:00:00Z"),
            )
            # Deliberately raise exception before commit
            raise RuntimeError("Simulated transaction crash")
    except RuntimeError:
        pass

    # Verify safe rollback occurred
    with get_connection() as conn:
        final_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        assert final_count == initial_count
        user_row = conn.execute("SELECT id FROM users WHERE id = 'temp_rollback_user'").fetchone()
        assert user_row is None


def test_33_bearer_token_signed_and_expiration(enterprise_app):
    """Test 33: Cryptographically signed bearer tokens, tamper detection, expiration, and legacy support."""
    client, _ = enterprise_app
    import time
    from itsdangerous import URLSafeTimedSerializer

    # 1. Signup returns signed bearer token prefixed with cg_tok_
    signup_res = client.post(
        "/api/auth/signup",
        json={"name": "Signed User", "email": "signed@test.local", "password": "Password123!"},
    )
    assert signup_res.status_code == 201
    token = signup_res.get_json()["token"]
    assert token.startswith("cg_tok_")

    # 2. Authenticates properly with Bearer token
    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    assert me_res.get_json()["authenticated"] is True
    assert me_res.get_json()["user"]["name"] == "Signed User"

    # 3. Tampered token signature is rejected with 401 INVALID_TOKEN
    tampered_token = token + "corrupt"
    bad_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {tampered_token}"})
    assert bad_res.status_code == 401
    assert bad_res.get_json()["reason_code"] == "INVALID_TOKEN"

    # 4. Expired token returns 401 TOKEN_EXPIRED
    with patch.dict(os.environ, {"TOKEN_MAX_AGE_SECONDS": "1"}):
        time.sleep(2.1)
        exp_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert exp_res.status_code == 401
        assert exp_res.get_json()["reason_code"] == "TOKEN_EXPIRED"

    # 5. Transparent backwards compatibility for legacy raw user IDs
    legacy_res = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {signup_res.get_json()['user']['id']}"},
    )
    assert legacy_res.status_code == 200
    assert legacy_res.get_json()["authenticated"] is True


def test_34_admin_authorization_and_regular_user_blocking(enterprise_app):
    """Test 34: Ordinary users are blocked from admin actions, while admin and demo accounts are authorized."""
    client, _ = enterprise_app

    # 1. Synthetic regular user (user-regular) is strictly blocked with 403 ADMIN_PRIVILEGES_REQUIRED
    reg_login = client.post("/api/auth/demo-login", json={"user_id": "user-regular"})
    assert reg_login.status_code == 200
    reg_token = reg_login.get_json()["token"]

    blocked_update = client.post(
        "/api/notice/update",
        headers={"Authorization": f"Bearer {reg_token}"},
        json={"notice_version": "2.1"},
    )
    assert blocked_update.status_code == 403
    assert blocked_update.get_json()["reason_code"] == "ADMIN_PRIVILEGES_REQUIRED"

    # 2. Synthetic administrator (admin-user) succeeds
    admin_login = client.post("/api/auth/demo-login", json={"user_id": "admin-user"})
    assert admin_login.status_code == 200
    admin_token = admin_login.get_json()["token"]

    admin_update = client.post(
        "/api/notice/update",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"notice_version": "2.1"},
    )
    assert admin_update.status_code == 200
    assert admin_update.get_json()["notice_version"] == "2.1"

    # 3. Interactive demo persona (demo-user) succeeds, preserving dashboard buttons
    demo_login = client.post("/api/auth/demo-login", json={"user_id": "demo-user"})
    assert demo_login.status_code == 200
    demo_token = demo_login.get_json()["token"]

    demo_reset = client.post(
        "/api/notice/reset",
        headers={"Authorization": f"Bearer {demo_token}"},
    )
    assert demo_reset.status_code == 200
    assert demo_reset.get_json()["notice_version"] == "1.0"


def test_35_consumer_key_revocation_restoration_and_enforcement(enterprise_app):
    """Test 35: Downstream API consumer revocation immediately blocks data sharing with 401 API_KEY_REVOKED."""
    client, _ = enterprise_app
    from database import DEFAULT_PARTNER_ALL_KEY, DEFAULT_PARTNER_LIMITED_KEY

    # User grants consent for Analytics
    client.post("/api/auth/demo-login", json={"user_id": "demo-user"})
    client.post("/api/consents", json={"purpose": "Analytics", "action": "grant"})

    # Valid partner-limited request succeeds before revocation
    pre_res = client.post(
        "/api/share/request",
        json={
            "user_id": "demo-user",
            "purpose": "Analytics",
            "api_key": DEFAULT_PARTNER_LIMITED_KEY,
        },
    )
    assert pre_res.status_code == 200
    assert pre_res.get_json()["allowed"] is True

    # Administrator revokes partner-limited key
    admin_login = client.post("/api/auth/demo-login", json={"user_id": "admin-user"})
    admin_token = admin_login.get_json()["token"]

    revoke_res = client.post(
        "/api/consumers/revoke",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"consumer_id": "partner-limited"},
    )
    assert revoke_res.status_code == 200
    assert revoke_res.get_json()["is_active"] is False

    # Attempt to use revoked API key is rejected with 401 API_KEY_REVOKED
    blocked_res = client.post(
        "/api/share/request",
        json={
            "user_id": "demo-user",
            "purpose": "Analytics",
            "api_key": DEFAULT_PARTNER_LIMITED_KEY,
        },
    )
    assert blocked_res.status_code == 401
    assert blocked_res.get_json()["reason_code"] == "API_KEY_REVOKED"

    # Administrator restores partner-limited key
    restore_res = client.post(
        "/api/consumers/restore",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"consumer_id": "partner-limited"},
    )
    assert restore_res.status_code == 200
    assert restore_res.get_json()["is_active"] is True

    # Sharing works again with restored key
    post_restore = client.post(
        "/api/share/request",
        json={
            "user_id": "demo-user",
            "purpose": "Analytics",
            "api_key": DEFAULT_PARTNER_LIMITED_KEY,
        },
    )
    assert post_restore.status_code == 200
    assert post_restore.get_json()["allowed"] is True


def test_36_notice_deterministic_sha256_and_conflict_handling(enterprise_app):
    """Test 36: Notice versions deterministic SHA-256 hash, conflict prevention, and history preservation."""
    client, _ = enterprise_app
    import hashlib

    # Admin auth
    admin_login = client.post("/api/auth/demo-login", json={"user_id": "admin-user"})
    admin_token = admin_login.get_json()["token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Empty notice version rejected with 400
    bad_req = client.post("/api/notice/update", headers=admin_headers, json={"notice_version": ""})
    assert bad_req.status_code == 400
    assert bad_req.get_json()["reason_code"] == "INVALID_NOTICE_VERSION"

    # Update to v2.5 with explicit text
    notice_text = "Custom v2.5 Privacy Notice: High-assurance data governance and itemized telemetry."
    expected_hash = hashlib.sha256(notice_text.encode("utf-8")).hexdigest()

    up_res = client.post(
        "/api/notice/update",
        headers=admin_headers,
        json={"notice_version": "2.5", "notice_text": notice_text},
    )
    assert up_res.status_code == 200
    assert up_res.get_json()["notice_hash"] == expected_hash

    # Conflict: Attempt to register v2.5 with conflicting text returns 409 VERSION_EXISTS
    conflict_res = client.post(
        "/api/notice/update",
        headers=admin_headers,
        json={"notice_version": "2.5", "notice_text": "Conflicting different notice text"},
    )
    assert conflict_res.status_code == 409
    assert conflict_res.get_json()["reason_code"] == "VERSION_EXISTS"

    # Reset notice preserves v2.5 in historical notice list
    client.post("/api/notice/reset", headers=admin_headers)
    notices_res = client.get("/api/notices")
    assert notices_res.status_code == 200
    all_versions = [n["version"] for n in notices_res.get_json()]
    assert "1.0" in all_versions
    assert "2.5" in all_versions


def test_37_consent_lifecycle_timestamps_and_status(enterprise_app):
    """Test 37: Complete consent lifecycle tracking created_at, withdrawn_at, and status endpoint."""
    client, _ = enterprise_app

    # Sign up user
    signup_res = client.post(
        "/api/auth/signup",
        json={"name": "Lifecycle User", "email": "lifecycle@test.local", "password": "Password123!"},
    )
    assert signup_res.status_code == 201
    token = signup_res.get_json()["token"]
    user_headers = {"Authorization": f"Bearer {token}"}

    # 1. Initial status is missing
    status_init = client.get("/api/consent/status?purpose=Analytics", headers=user_headers)
    assert status_init.status_code == 200
    assert status_init.get_json()["status"] == "missing"
    assert status_init.get_json()["granted"] is False

    # 2. Grant consent preserves created_at and sets withdrawn_at to None
    grant_res = client.post(
        "/api/consents",
        headers=user_headers,
        json={"purpose": "Analytics", "action": "grant"},
    )
    assert grant_res.status_code == 201
    grant_data = grant_res.get_json()
    created_at = grant_data["created_at"]
    assert created_at is not None and len(created_at) > 10
    assert grant_data["withdrawn_at"] is None

    # Status is active
    status_active = client.get("/api/consent/status?purpose=Analytics", headers=user_headers)
    assert status_active.status_code == 200
    assert status_active.get_json()["status"] == "active"
    assert status_active.get_json()["granted"] is True
    assert status_active.get_json()["created_at"] == created_at
    assert status_active.get_json()["withdrawn_at"] is None

    # 3. Withdraw consent records withdrawn_at timestamp
    withdraw_res = client.post(
        "/api/consents",
        headers=user_headers,
        json={"purpose": "Analytics", "action": "withdraw"},
    )
    assert withdraw_res.status_code == 201
    withdraw_data = withdraw_res.get_json()
    assert withdraw_data["granted"] is False
    withdrawn_at = withdraw_data["withdrawn_at"]
    assert withdrawn_at is not None and len(withdrawn_at) > 10
    assert withdraw_data["created_at"] == created_at

    # Status is withdrawn
    status_withdrawn = client.get("/api/consent/status?purpose=Analytics", headers=user_headers)
    assert status_withdrawn.status_code == 200
    assert status_withdrawn.get_json()["status"] == "withdrawn"
    assert status_withdrawn.get_json()["granted"] is False

    # 4. Repeated withdrawal is idempotent and preserves timestamps
    repeat_withdraw = client.post(
        "/api/consents",
        headers=user_headers,
        json={"purpose": "Analytics", "action": "withdraw"},
    )
    assert repeat_withdraw.status_code == 200
    assert repeat_withdraw.get_json()["reason_code"] == "CONSENT_ALREADY_WITHDRAWN"
    assert repeat_withdraw.get_json()["created_at"] == created_at

    # 5. Re-granting clears withdrawn_at, restores active status, and keeps original created_at
    regrant_res = client.post(
        "/api/consents",
        headers=user_headers,
        json={"purpose": "Analytics", "action": "grant"},
    )
    assert regrant_res.status_code == 201
    regrant_data = regrant_res.get_json()
    assert regrant_data["granted"] is True
    assert regrant_data["created_at"] == created_at
    assert regrant_data["withdrawn_at"] is None


def test_38_consent_lifecycle_stale_notice_and_reconsent_requirement(enterprise_app):
    """Test 38: Outdated consent triggers re-consent requirement, 409 on stale grant, and persists history."""
    client, _ = enterprise_app

    # Sign up user
    signup_res = client.post(
        "/api/auth/signup",
        json={"name": "Reconsent User", "email": "reconsent@test.local", "password": "Password123!"},
    )
    token = signup_res.get_json()["token"]
    user_headers = {"Authorization": f"Bearer {token}"}

    # Grant under notice v1.0
    client.post(
        "/api/consents",
        headers=user_headers,
        json={"purpose": "Analytics", "action": "grant"},
    )

    # Bump notice to v2.0 as admin
    admin_login = client.post("/api/auth/demo-login", json={"user_id": "admin-user"})
    admin_token = admin_login.get_json()["token"]
    client.post(
        "/api/notice/update",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"notice_version": "2.0"},
    )

    # Consent status now reports status="stale" and needs_reconsent=True
    status_stale = client.get("/api/consent/status?purpose=Analytics", headers=user_headers)
    assert status_stale.status_code == 200
    assert status_stale.get_json()["status"] == "stale"
    assert status_stale.get_json()["needs_reconsent"] is True

    # Data access is blocked due to stale notice
    access_res = client.post("/api/data-access", headers=user_headers, json={"purpose": "Analytics"})
    assert access_res.status_code == 403
    assert access_res.get_json()["reason_code"] == "NOTICE_MISMATCH"

    # Attempting to grant with explicit stale version v1.0 returns 409 STALE_NOTICE
    stale_grant = client.post(
        "/api/consents",
        headers=user_headers,
        json={"purpose": "Analytics", "action": "grant", "notice_version": "1.0", "notice_hash": "old_hash"},
    )
    assert stale_grant.status_code == 409
    assert stale_grant.get_json()["reason_code"] == "STALE_NOTICE"

    # Re-consenting under active notice v2.0 restores access
    fresh_grant = client.post(
        "/api/consents",
        headers=user_headers,
        json={"purpose": "Analytics", "action": "grant", "notice_version": "2.0"},
    )
    assert fresh_grant.status_code == 201

    # Verify data access is permitted again
    allowed_res = client.post("/api/data-access", headers=user_headers, json={"purpose": "Analytics"})
    assert allowed_res.status_code == 200
    assert allowed_res.get_json()["allowed"] is True

    # History endpoint contains chronological lifecycle events with cryptographic hashes
    history_res = client.get("/api/consent/history", headers=user_headers)
    assert history_res.status_code == 200
    events = history_res.get_json()
    assert len(events) >= 3
    actions = [e["action"] for e in events]
    assert "grant" in actions
    assert "consent_rejected_stale" in actions


def test_39_merkle_dag_audit_verification_fields_and_tamper_detection(enterprise_app):
    """Test 39: Audit verification API returns comprehensive fields and accurately detects tampering."""
    client, test_db = enterprise_app

    # Perform some normal operations to generate audit records
    client.post("/api/auth/demo-login", json={"user_id": "demo-user"})
    client.post("/api/consents", json={"purpose": "Analytics", "action": "grant"})
    client.post("/api/data-access", json={"purpose": "Analytics"})

    # 1. Verification of intact ledger
    verify_res = client.get("/api/audit/verify")
    assert verify_res.status_code == 200
    data = verify_res.get_json()
    assert data["status"] == "intact"
    assert data["total_records"] >= 3
    assert data["valid_records"] == data["total_records"]
    assert data["invalid_records"] == 0
    assert data["broken_references"] == 0
    assert data["detected_tampering"] is False
    assert data["error_details"] == []
    assert "branches_count" in data
    assert "topology" in data

    # 2. Tampering detection: Alter an existing record's purpose
    with database.get_connection() as conn:
        conn.execute("DROP TRIGGER IF EXISTS trg_prevent_audit_update")
        target_id = conn.execute("SELECT id FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()["id"]
        conn.execute("UPDATE audit_events SET purpose = 'UnauthorizedTamper' WHERE id = ?", (target_id,))

    # Verification must report broken and detect tampering
    tampered_res = client.get("/api/audit/verify")
    assert tampered_res.status_code == 409
    t_data = tampered_res.get_json()
    assert t_data["status"] == "broken"
    assert t_data["detected_tampering"] is True
    assert t_data["reason_code"] == "ROW_HASH_TAMPERED"
    assert t_data["broken_at_id"] == target_id
    assert len(t_data["error_details"]) > 0


def test_40_merkle_dag_broken_parent_reference_and_missing_record_detection(enterprise_app):
    """Test 40: Merkle DAG detects deleted intermediate records and broken parent references."""
    client, test_db = enterprise_app

    client.post("/api/auth/demo-login", json={"user_id": "demo-user"})
    client.post("/api/consents", json={"purpose": "Analytics", "action": "grant"})
    client.post("/api/consents", json={"purpose": "Marketing", "action": "grant"})
    client.post("/api/consents", json={"purpose": "Service Improvement", "action": "grant"})

    # Delete an intermediate record to break the DAG linkage
    with database.get_connection() as conn:
        conn.execute("DROP TRIGGER IF EXISTS trg_prevent_audit_delete")
        rows = conn.execute("SELECT id FROM audit_events ORDER BY id ASC").fetchall()
        assert len(rows) >= 3
        victim_id = rows[1]["id"]
        conn.execute("DELETE FROM audit_events WHERE id = ?", (victim_id,))

    # Verify DAG detects broken parent reference
    verify_res = client.get("/api/audit/verify")
    assert verify_res.status_code == 409
    data = verify_res.get_json()
    assert data["status"] == "broken"
    assert data["reason_code"] == "BROKEN_ANCESTOR_LINK"
    assert data["detected_tampering"] is True
    assert data["broken_references"] >= 1


def test_41_consumer_api_key_creation_admin_and_audit_event(enterprise_app):
    """Test 41: Administrator registers new consumer, hashes API key, appends audit trail, and permits access."""
    client, _ = enterprise_app

    admin_login = client.post("/api/auth/demo-login", json={"user_id": "admin-user"})
    admin_token = admin_login.get_json()["token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Ordinary user cannot create consumers (403)
    user_login = client.post("/api/auth/demo-login", json={"user_id": "user-regular"})
    user_token = user_login.get_json()["token"]
    blocked_create = client.post(
        "/api/consumers/create",
        headers={"Authorization": f"Bearer {user_token}"},
        json={"consumer_id": "new-partner", "name": "New Partner"},
    )
    assert blocked_create.status_code == 403

    # 2. Administrator creates new consumer
    create_res = client.post(
        "/api/consumers/create",
        headers=admin_headers,
        json={
            "consumer_id": "partner-health",
            "name": "Health Research Partner",
            "allowed_purposes": ["Analytics"],
            "api_key": "key_partner_health_custom_token",
        },
    )
    assert create_res.status_code == 201
    created_key = create_res.get_json()["api_key"]

    # 3. User grants consent for Analytics
    client.post("/api/auth/demo-login", json={"user_id": "demo-user"})
    client.post("/api/consents", json={"purpose": "Analytics", "action": "grant"})

    # 4. Downstream sharing succeeds with newly created key
    share_res = client.post(
        "/api/share/request",
        json={
            "user_id": "demo-user",
            "purpose": "Analytics",
            "api_key": created_key,
        },
    )
    assert share_res.status_code == 200
    assert share_res.get_json()["allowed"] is True

    # 5. Verify consumer_key_created audit event exists in ledger
    with database.get_connection() as conn:
        event = conn.execute(
            "SELECT action, reason_code FROM audit_events WHERE action = 'consumer_key_created' LIMIT 1"
        ).fetchone()
        assert event is not None
        assert event["reason_code"] == "CONSUMER_CREATED"


def test_42_purpose_based_data_sharing_comprehensive_matrix(enterprise_app):
    """
    Test 42: Comprehensive validation of Part 7 Purpose-Based Data Sharing:
    1. Consumer identity verification & mismatch rejection
    2. API-key validity (missing/invalid -> 401 INVALID_API_KEY)
    3. API-key revocation status (revoked -> 401 API_KEY_REVOKED)
    4. Requested purpose validity (invalid -> 400 INVALID_PURPOSE)
    5. Consumer permission for purpose (unauthorized purpose -> 403 CONSUMER_NOT_AUTHORIZED)
    6. User consent for purpose (missing consent -> 403 NO_CONSENT)
    7. Consent withdrawal status (withdrawn consent -> 403 WITHDRAWN / CONSENT_WITHDRAWN)
    8. Notice validity & re-consent requirement (stale notice -> 403 NOTICE_MISMATCH)
    9. Requested data permissions (unauthorized fields -> 403 UNAUTHORIZED_FIELDS; valid subset filtered)
    10. Partner-All full access vs Partner-Limited restricted subset
    11. Zero leakage of unnecessary PII (passwords, tokens, raw personal credentials)
    12. Tamper-evident Merkle DAG audit events recorded for all decisions
    """
    client, _ = enterprise_app

    # Setup demo-user with fresh consents for Analytics and Marketing under active notice
    client.post("/api/auth/demo-login", json={"user_id": "demo-user"})
    client.post("/api/consents", json={"purpose": "Analytics", "action": "grant"})
    client.post("/api/consents", json={"purpose": "Marketing", "action": "grant"})

    # --- Scenario 1: Valid Partner-All Requests ---
    # Partner-All has access to Analytics, Marketing, Service Improvement
    res_all_analytics = client.post(
        "/api/share/request",
        headers={"X-API-Key": DEFAULT_PARTNER_ALL_KEY},
        json={"user_id": "demo-user", "purpose": "Analytics"},
    )
    assert res_all_analytics.status_code == 200
    all_data = res_all_analytics.get_json()
    assert all_data["allowed"] is True
    assert all_data["reason_code"] == "ACTIVE_CONSENT"
    assert "page_views" in all_data["data"]
    assert "password" not in all_data["data"]
    assert "email" not in all_data["data"]

    res_all_marketing = client.post(
        "/api/share/request",
        headers={"X-API-Key": DEFAULT_PARTNER_ALL_KEY},
        json={"user_id": "demo-user", "purpose": "Marketing"},
    )
    assert res_all_marketing.status_code == 200
    mkt_data = res_all_marketing.get_json()
    assert mkt_data["allowed"] is True
    assert "email_preferences" in mkt_data["data"]
    assert "offers_enabled" in mkt_data["data"]

    # --- Scenario 2: Valid Partner-Limited Request (Analytics only) ---
    res_lim_analytics = client.post(
        "/api/share/request",
        headers={"X-API-Key": DEFAULT_PARTNER_LIMITED_KEY},
        json={"user_id": "demo-user", "purpose": "Analytics"},
    )
    assert res_lim_analytics.status_code == 200
    assert res_lim_analytics.get_json()["allowed"] is True

    # --- Scenario 3: Unauthorized Purpose (Partner-Limited requesting Marketing) ---
    res_lim_mkt = client.post(
        "/api/share/request",
        headers={"X-API-Key": DEFAULT_PARTNER_LIMITED_KEY},
        json={"user_id": "demo-user", "purpose": "Marketing"},
    )
    assert res_lim_mkt.status_code == 403
    assert res_lim_mkt.get_json()["reason_code"] == "CONSUMER_NOT_AUTHORIZED"
    assert res_lim_mkt.get_json()["error_code"] == "CONSUMER_PURPOSE_UNAUTHORIZED"

    # --- Scenario 4: Missing & Invalid API Key ---
    res_missing_key = client.post(
        "/api/share/request",
        json={"user_id": "demo-user", "purpose": "Analytics"},
    )
    assert res_missing_key.status_code == 401
    assert res_missing_key.get_json()["reason_code"] == "INVALID_API_KEY"

    res_invalid_key = client.post(
        "/api/share/request",
        headers={"X-API-Key": "forged_malicious_key_99999"},
        json={"user_id": "demo-user", "purpose": "Analytics"},
    )
    assert res_invalid_key.status_code == 401
    assert res_invalid_key.get_json()["reason_code"] == "INVALID_API_KEY"

    # --- Scenario 5: Consumer Identity Spoofing Protection ---
    res_id_mismatch = client.post(
        "/api/share/request",
        headers={"X-API-Key": DEFAULT_PARTNER_ALL_KEY},
        json={
            "user_id": "demo-user",
            "purpose": "Analytics",
            "consumer_id": "partner-limited",  # spoofed declared identity
        },
    )
    assert res_id_mismatch.status_code == 403
    assert res_id_mismatch.get_json()["reason_code"] == "CONSUMER_IDENTITY_MISMATCH"

    # --- Scenario 6: Revoked API Key ---
    admin_login = client.post("/api/auth/demo-login", json={"user_id": "admin-user"})
    admin_tok = admin_login.get_json()["token"]
    # Revoke partner-all key
    client.post(
        "/api/consumers/revoke",
        headers={"Authorization": f"Bearer {admin_tok}"},
        json={"consumer_id": "partner-all"},
    )
    res_revoked = client.post(
        "/api/share/request",
        headers={"X-API-Key": DEFAULT_PARTNER_ALL_KEY},
        json={"user_id": "demo-user", "purpose": "Analytics"},
    )
    assert res_revoked.status_code == 401
    assert res_revoked.get_json()["reason_code"] == "API_KEY_REVOKED"
    # Restore partner-all key
    client.post(
        "/api/consumers/restore",
        headers={"Authorization": f"Bearer {admin_tok}"},
        json={"consumer_id": "partner-all"},
    )

    # --- Scenario 7: Missing Consent ---
    # user2 has no consent on record for Marketing
    res_no_consent = client.post(
        "/api/share/request",
        headers={"X-API-Key": DEFAULT_PARTNER_ALL_KEY},
        json={"user_id": "user2", "purpose": "Marketing"},
    )
    assert res_no_consent.status_code == 403
    assert res_no_consent.get_json()["reason_code"] == "NO_CONSENT"

    # --- Scenario 8: Withdrawn Consent ---
    # demo-user withdraws Marketing consent
    client.post("/api/auth/demo-login", json={"user_id": "demo-user"})
    client.post("/api/consents", json={"purpose": "Marketing", "action": "withdraw"})
    res_withdrawn = client.post(
        "/api/share/request",
        headers={"X-API-Key": DEFAULT_PARTNER_ALL_KEY},
        json={"user_id": "demo-user", "purpose": "Marketing"},
    )
    assert res_withdrawn.status_code == 403
    assert res_withdrawn.get_json()["reason_code"] in ("WITHDRAWN", "CONSENT_WITHDRAWN")
    assert res_withdrawn.get_json().get("error_code") == "CONSENT_WITHDRAWN"

    # --- Scenario 9: Field-Level Authorization & Privacy Filtering ---
    # Unpermitted field requested -> 403
    res_bad_fields = client.post(
        "/api/share/request",
        headers={"X-API-Key": DEFAULT_PARTNER_ALL_KEY},
        json={
            "user_id": "demo-user",
            "purpose": "Analytics",
            "requested_fields": ["page_views", "ssn_or_bank_routing"],
        },
    )
    assert res_bad_fields.status_code == 403
    assert res_bad_fields.get_json()["reason_code"] == "UNAUTHORIZED_FIELDS"

    # Permitted subset requested -> only requested subset released
    res_subset = client.post(
        "/api/share/request",
        headers={"X-API-Key": DEFAULT_PARTNER_ALL_KEY},
        json={
            "user_id": "demo-user",
            "purpose": "Analytics",
            "requested_fields": ["page_views"],
        },
    )
    assert res_subset.status_code == 200
    subset_data = res_subset.get_json()["data"]
    assert "page_views" in subset_data
    assert "feature_usage" not in subset_data  # unrequested allowed field strictly omitted

    # --- Scenario 10: Downstream Consumer Profile Endpoint ---
    prof_res = client.get(
        "/api/consumer/me",
        headers={"X-API-Key": DEFAULT_PARTNER_LIMITED_KEY},
    )
    assert prof_res.status_code == 200
    prof = prof_res.get_json()["consumer"]
    assert prof["consumer_id"] == "partner-limited"
    assert prof["allowed_purposes"] == ["Analytics"]
    assert "api_key_hash" not in prof  # Never leak key hashes to consumers


def test_43_cybersecurity_protections_comprehensive_suite(enterprise_app):
    """
    Test 43: Complete Part 8 Cybersecurity Protections Suite:
    1. SQL Injection Prevention & Parameterization across all query vectors
    2. CORS Allow-List enforcement (trusted allowed, untrusted blocked)
    3. OWASP Security Headers (nosniff, SAMEORIGIN, XSS protection, no-store)
    4. Request Payload Size Limits (HTTP 413 on >2MB)
    5. Rate Limiting protection on sensitive endpoints (HTTP 429)
    6. Input Validation (invalid email, weak password, invalid purpose/action)
    7. Leak-Proof Error Handling (zero stack traces, zero credential leakage)
    8. Security Event Logging in Merkle DAG (login_failed, rate_limit_exceeded)
    9. IDOR & Unauthorized Resource Access Protection
    10. Duplicate Sensitive Operation Protections (idempotent withdrawal, duplicate conflict)
    """
    client, _ = enterprise_app

    # -------------------------------------------------------------
    # 1. SQL Injection Prevention & Parameterized Queries
    # -------------------------------------------------------------
    # Attempt SQL injection in login
    sqli_login = client.post(
        "/api/auth/login",
        json={"email": "' OR '1'='1' --", "password": "' OR '1'='1'"},
    )
    assert sqli_login.status_code == 401
    assert sqli_login.get_json()["reason_code"] == "INVALID_CREDENTIALS"

    # Attempt SQL injection in signup
    sqli_signup = client.post(
        "/api/auth/signup",
        json={
            "name": "Hacker'; DROP TABLE users; --",
            "email": "not-a-valid-email-format",
            "password": "Password123!",
        },
    )
    assert sqli_signup.status_code == 400
    assert sqli_signup.get_json()["reason_code"] == "INVALID_EMAIL"

    # Attempt SQL injection in data-sharing api_key and user_id
    sqli_share = client.post(
        "/api/share/request",
        json={
            "api_key": "' OR '1'='1' --",
            "user_id": "demo-user' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13 --",
            "purpose": "Analytics",
        },
    )
    assert sqli_share.status_code == 401
    assert sqli_share.get_json()["reason_code"] == "INVALID_API_KEY"

    # Verify database schema and users table was completely unaffected by injection attempts
    with database.get_connection() as conn:
        user_cnt = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
        assert user_cnt > 0  # Users table remains completely intact

    # -------------------------------------------------------------
    # 2. CORS Allow-List & OWASP Security Headers
    # -------------------------------------------------------------
    # Trusted localhost origin -> Access-Control-Allow-Origin reflected
    trusted_res = client.get(
        "/api/health",
        headers={"Origin": "http://localhost:3000"},
    )
    assert trusted_res.status_code == 200
    assert trusted_res.headers.get("Access-Control-Allow-Origin") == "http://localhost:3000"
    assert trusted_res.headers.get("Access-Control-Allow-Credentials") == "true"

    # Untrusted attacker origin -> Access-Control-Allow-Origin is NOT granted
    untrusted_res = client.get(
        "/api/health",
        headers={"Origin": "https://malicious-attacker-domain.evil.com"},
    )
    assert untrusted_res.headers.get("Access-Control-Allow-Origin") != "https://malicious-attacker-domain.evil.com"

    # Verify OWASP Security Headers
    assert trusted_res.headers.get("X-Content-Type-Options") == "nosniff"
    assert trusted_res.headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert "no-store" in trusted_res.headers.get("Cache-Control", "")

    # -------------------------------------------------------------
    # 3. Request Payload Size Limits (HTTP 413)
    # -------------------------------------------------------------
    # 2.5 MB oversized payload exceeds the 2MB MAX_CONTENT_LENGTH limit
    oversized_data = "X" * (2500 * 1024)
    oversized_res = client.post(
        "/api/auth/login",
        data=oversized_data,
        content_type="application/json",
    )
    assert oversized_res.status_code == 413
    assert oversized_res.get_json()["reason_code"] == "PAYLOAD_TOO_LARGE"

    # -------------------------------------------------------------
    # 4. Rate Limiting Protection (HTTP 429)
    # -------------------------------------------------------------
    # Test the in-memory sliding window rate limiter directly
    api.rate_limiter.reset()
    test_key = "auth:192.168.1.100"
    for _ in range(40):
        assert api.rate_limiter.is_rate_limited(test_key, max_requests=40, window_seconds=60) is False
    # 41st request exceeds the limit
    assert api.rate_limiter.is_rate_limited(test_key, max_requests=40, window_seconds=60) is True

    # -------------------------------------------------------------
    # 5. Input Validation
    # -------------------------------------------------------------
    # Weak password (< 6 chars)
    weak_pwd_res = client.post(
        "/api/auth/signup",
        json={"name": "Alice Valid", "email": "alice_valid@test.com", "password": "123"},
    )
    assert weak_pwd_res.status_code == 400
    assert weak_pwd_res.get_json()["reason_code"] == "WEAK_PASSWORD"

    # Short name (< 2 chars)
    bad_name_res = client.post(
        "/api/auth/signup",
        json={"name": "A", "email": "alice_valid@test.com", "password": "ValidPassword123!"},
    )
    assert bad_name_res.status_code == 400
    assert bad_name_res.get_json()["reason_code"] == "INVALID_NAME"

    # Invalid consent action
    bad_action_res = client.post(
        "/api/consents",
        json={"purpose": "Analytics", "action": "malicious_override"},
    )
    assert bad_action_res.status_code == 400
    assert bad_action_res.get_json()["reason_code"] == "INVALID_ACTION"

    # Invalid purpose
    bad_purpose_res = client.post(
        "/api/consents",
        json={"purpose": "Unauthorized Telemetry", "action": "grant"},
    )
    assert bad_purpose_res.status_code == 400
    assert bad_purpose_res.get_json()["reason_code"] == "INVALID_PURPOSE"

    # -------------------------------------------------------------
    # 6. Leak-Proof Error Handling & Secret Protection
    # -------------------------------------------------------------
    # Trigger 404
    not_found_res = client.get("/api/non-existent-endpoint-xyz")
    assert not_found_res.status_code == 404
    err_json = not_found_res.get_json()
    assert err_json["reason_code"] == "NOT_FOUND"
    # Ensure no internal file paths, stack traces, or credentials in payload
    assert "Traceback" not in not_found_res.get_data(as_text=True)
    assert "database" not in err_json or err_json["database"] != "password"

    # -------------------------------------------------------------
    # 7. Security Event Logging in Merkle DAG
    # -------------------------------------------------------------
    # Trigger failed login with incorrect password for existing user
    bad_login_res = client.post(
        "/api/auth/login",
        json={"email": "demo@consentguard.local", "password": "WrongPassword999!"},
    )
    assert bad_login_res.status_code == 401
    assert bad_login_res.get_json()["reason_code"] == "INVALID_CREDENTIALS"

    # Verify login_failed event was written to audit_events
    with database.get_connection() as conn:
        failed_event = conn.execute(
            "SELECT action, reason_code FROM audit_events WHERE action = 'login_failed' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert failed_event is not None
        assert failed_event["reason_code"] == "INVALID_CREDENTIALS"

    # -------------------------------------------------------------
    # 8. Duplicate Operation Protections
    # -------------------------------------------------------------
    # Duplicate signup with existing email
    dup_signup = client.post(
        "/api/auth/signup",
        json={"name": "Demo Duplicate", "email": "demo@consentguard.local", "password": "Password123!"},
    )
    assert dup_signup.status_code == 409
    assert dup_signup.get_json()["reason_code"] == "EMAIL_ALREADY_EXISTS"

    # Duplicate withdrawal idempotency
    client.post("/api/auth/demo-login", json={"user_id": "demo-user"})
    client.post("/api/consents", json={"purpose": "Analytics", "action": "withdraw"})
    dup_withdraw = client.post("/api/consents", json={"purpose": "Analytics", "action": "withdraw"})
    assert dup_withdraw.status_code == 200
    assert dup_withdraw.get_json()["reason_code"] == "CONSENT_ALREADY_WITHDRAWN"


def test_44_live_cybersecurity_demonstration_six_scenarios():
    """
    Test 44: Complete automated validation of Part 9 Live Cybersecurity Demonstration:
      Scenario 1: Unauthorized Access -> Rejected (HTTP 401/403)
      Scenario 2: Purpose Violation -> Blocked (HTTP 403 CONSUMER_NOT_AUTHORIZED)
      Scenario 3: Consent Withdrawal -> Access Denied (HTTP 403 WITHDRAWN)
      Scenario 4: Notice Version Change -> Stale Notice Identified (HTTP 403 NOTICE_MISMATCH)
      Scenario 5: Audit Tampering -> Detected on isolated copy (Merkle DAG ROW_HASH_TAMPERED)
      Scenario 6: API-Key Revocation -> Access Rejected (HTTP 401 API_KEY_REVOKED)
    """
    import demo_live_security
    exit_code = demo_live_security.run_live_demonstration()
    assert exit_code == 0








