import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch
import pytest

# Ensure backend directory is in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import api
import database


@pytest.fixture
def auth_client():
    with tempfile.TemporaryDirectory() as temp_dir:
        test_db = Path(temp_dir) / "test_auth.db"
        with patch.object(database, "DATABASE_PATH", test_db):
            database.initialize_database()

            orig_version = api.NOTICE_VERSION
            orig_text = api.NOTICE_TEXT
            orig_hash = api.NOTICE_HASH

            api.NOTICE_VERSION = database.DEFAULT_NOTICE_VERSION
            api.NOTICE_TEXT = database.DEFAULT_NOTICE_TEXT
            api.NOTICE_HASH = database.DEFAULT_NOTICE_HASH

            api.app.config["TESTING"] = True
            client = api.app.test_client()
            yield client

            api.NOTICE_VERSION = orig_version
            api.NOTICE_TEXT = orig_text
            api.NOTICE_HASH = orig_hash


def test_01_user_registration_and_login(auth_client):
    """Scenario 1: A new user can register, verify hash is stored securely, and log in."""
    signup_res = auth_client.post(
        "/api/auth/signup",
        json={
            "name": "Alice Privacy",
            "email": "alice@example.com",
            "password": "Password123!",
        },
    )
    assert signup_res.status_code == 201
    data = signup_res.get_json()
    assert data["success"] is True
    alice_id = data["user"]["id"]
    assert alice_id.startswith("user_")

    # Verify plaintext password is NEVER stored
    with database.get_connection() as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE id = ?", (alice_id,)).fetchone()
        assert row is not None
        assert row["password_hash"] != "Password123!"
        assert row["password_hash"].startswith("scrypt:") or row["password_hash"].startswith("pbkdf2:")

    # Log out
    auth_client.post("/api/auth/logout")

    # Log back in
    login_res = auth_client.post(
        "/api/auth/login",
        json={"email": "alice@example.com", "password": "Password123!"},
    )
    assert login_res.status_code == 200
    assert login_res.get_json()["user"]["id"] == alice_id


def test_02_duplicate_email_registration_rejected(auth_client):
    """Scenario 2: Duplicate email registration is rejected with 409 Conflict."""
    auth_client.post(
        "/api/auth/signup",
        json={"name": "Alice", "email": "alice@example.com", "password": "Password123!"},
    )

    # Attempt registration with duplicate email (different casing)
    dup_res = auth_client.post(
        "/api/auth/signup",
        json={"name": "Alice Duplicate", "email": "ALICE@example.com", "password": "Password456!"},
    )
    assert dup_res.status_code == 409
    assert dup_res.get_json()["reason_code"] == "EMAIL_ALREADY_EXISTS"


def test_03_new_account_zero_activity_and_no_consent(auth_client):
    """Scenario 3: A new account starts with zero activity and no consent granted."""
    signup_res = auth_client.post(
        "/api/auth/signup",
        json={"name": "Bob Clean", "email": "bob@example.com", "password": "Password123!"},
    )
    assert signup_res.status_code == 201

    # Consents list should be completely empty
    consents_res = auth_client.get("/api/consents")
    assert consents_res.status_code == 200
    assert len(consents_res.get_json()) == 0

    # Data access without consent must be blocked with HTTP 403 NO_CONSENT
    access_res = auth_client.post("/api/data-access", json={"purpose": "Analytics"})
    assert access_res.status_code == 403
    assert access_res.get_json()["reason_code"] == "NO_CONSENT"


def test_04_purpose_isolation_analytics_not_marketing(auth_client):
    """Scenario 4: Granting Analytics consent does not grant Marketing consent."""
    auth_client.post(
        "/api/auth/signup",
        json={"name": "Charlie", "email": "charlie@example.com", "password": "Password123!"},
    )

    grant_res = auth_client.post(
        "/api/consents",
        json={"purpose": "Analytics", "action": "grant"},
    )
    assert grant_res.status_code == 201

    # Analytics access is permitted
    analytics_access = auth_client.post("/api/data-access", json={"purpose": "Analytics"})
    assert analytics_access.status_code == 200
    assert analytics_access.get_json()["allowed"] is True

    # Marketing access remains blocked
    marketing_access = auth_client.post("/api/data-access", json={"purpose": "Marketing"})
    assert marketing_access.status_code == 403
    assert marketing_access.get_json()["reason_code"] == "NO_CONSENT"


def test_05_consent_persistence_in_database(auth_client):
    """Scenario 5: Consent changes are saved in the database."""
    signup_res = auth_client.post(
        "/api/auth/signup",
        json={"name": "Dave", "email": "dave@example.com", "password": "Password123!"},
    )
    user_id = signup_res.get_json()["user"]["id"]

    auth_client.post("/api/consents", json={"purpose": "Marketing", "action": "grant"})

    with database.get_connection() as conn:
        row = conn.execute(
            "SELECT granted, notice_version, notice_hash, last_action FROM consents WHERE user_id = ? AND purpose = ?",
            (user_id, "Marketing"),
        ).fetchone()
        assert row is not None
        assert row["granted"] == 1
        assert row["notice_version"] == "1.0"
        assert row["last_action"] == "grant"
        assert len(row["notice_hash"]) == 64


def test_06_session_persistence_across_refresh(auth_client):
    """Scenario 6: Refreshing the page / checking session preserves the authenticated user."""
    auth_client.post(
        "/api/auth/signup",
        json={"name": "Emma", "email": "emma@example.com", "password": "Password123!"},
    )

    me_res = auth_client.get("/api/auth/me")
    assert me_res.status_code == 200
    me_data = me_res.get_json()
    assert me_data["authenticated"] is True
    assert me_data["user"]["email"] == "emma@example.com"


def test_07_logout_and_login_restores_data(auth_client):
    """Scenario 7: Logging out and logging back in restores the same user data."""
    auth_client.post(
        "/api/auth/signup",
        json={"name": "Frank", "email": "frank@example.com", "password": "Password123!"},
    )

    # Record consent
    auth_client.post("/api/consents", json={"purpose": "Service Improvement", "action": "grant"})

    # Log out
    auth_client.post("/api/auth/logout")
    me_logged_out = auth_client.get("/api/auth/me")
    assert me_logged_out.get_json()["authenticated"] is False

    # Log back in
    auth_client.post("/api/auth/login", json={"email": "frank@example.com", "password": "Password123!"})
    consents_res = auth_client.get("/api/consents")
    assert consents_res.status_code == 200
    user_consents = consents_res.get_json()
    assert len(user_consents) == 1
    assert user_consents[0]["purpose"] == "Service Improvement"
    assert user_consents[0]["granted"] == 1


def test_08_second_user_cannot_see_first_user_consents(auth_client):
    """Scenario 8: A second user cannot see the first user's consent records."""
    # User 1 registers and grants Analytics
    res1 = auth_client.post(
        "/api/auth/signup",
        json={"name": "User One", "email": "one@example.com", "password": "Password123!"},
    )
    user1_id = res1.get_json()["user"]["id"]
    auth_client.post("/api/consents", json={"purpose": "Analytics", "action": "grant"})
    auth_client.post("/api/auth/logout")

    # User 2 registers
    auth_client.post(
        "/api/auth/signup",
        json={"name": "User Two", "email": "two@example.com", "password": "Password123!"},
    )

    # User 2 sees zero consents
    user2_consents = auth_client.get("/api/consents").get_json()
    assert len(user2_consents) == 0

    # User 2 tries to explicitly request User 1's consents -> 403 Forbidden
    cross_res = auth_client.get(f"/api/consents?user_id={user1_id}")
    assert cross_res.status_code == 403
    assert cross_res.get_json()["reason_code"] == "FORBIDDEN_CROSS_USER_ACCESS"


def test_09_second_user_cannot_access_first_user_audit(auth_client):
    """Scenario 9: A second user cannot access the first user's audit logs."""
    # User 1 generates audit logs
    res1 = auth_client.post(
        "/api/auth/signup",
        json={"name": "User One", "email": "one_audit@example.com", "password": "Password123!"},
    )
    user1_id = res1.get_json()["user"]["id"]
    auth_client.post("/api/consents", json={"purpose": "Analytics", "action": "grant"})
    auth_client.post("/api/auth/logout")

    # User 2 logs in
    auth_client.post(
        "/api/auth/signup",
        json={"name": "User Two", "email": "two_audit@example.com", "password": "Password123!"},
    )

    # User 2's audit query returns only User 2's logs
    u2_audit = auth_client.get("/api/audit").get_json()
    for event in u2_audit:
        assert event["user_id"] != user1_id

    # User 2 tries to explicitly query User 1's audit logs -> 403 Forbidden
    cross_audit = auth_client.get(f"/api/audit?user_id={user1_id}")
    assert cross_audit.status_code == 403
    assert cross_audit.get_json()["reason_code"] == "FORBIDDEN_CROSS_USER_ACCESS"


def test_10_user_cannot_change_another_user_consent(auth_client):
    """Scenario 10: One user cannot change another user's consent by modifying API requests."""
    # User 1 registers
    res1 = auth_client.post(
        "/api/auth/signup",
        json={"name": "Target User", "email": "target@example.com", "password": "Password123!"},
    )
    user1_id = res1.get_json()["user"]["id"]
    auth_client.post("/api/auth/logout")

    # Attacker registers
    auth_client.post(
        "/api/auth/signup",
        json={"name": "Attacker", "email": "attacker@example.com", "password": "Password123!"},
    )

    # Attacker sends POST with user_id set to target user
    attack_res = auth_client.post(
        "/api/consents",
        json={"user_id": user1_id, "purpose": "Analytics", "action": "grant"},
    )
    assert attack_res.status_code == 403
    assert attack_res.get_json()["reason_code"] == "FORBIDDEN_CROSS_USER_ACCESS"


def test_11_withdrawal_blocks_subsequent_access(auth_client):
    """Scenario 11: Withdrawal immediately blocks subsequent unauthorized access."""
    auth_client.post(
        "/api/auth/signup",
        json={"name": "Withdraw Tester", "email": "withdraw@example.com", "password": "Password123!"},
    )

    # Grant & verify access
    auth_client.post("/api/consents", json={"purpose": "Analytics", "action": "grant"})
    access1 = auth_client.post("/api/data-access", json={"purpose": "Analytics"})
    assert access1.status_code == 200

    # Withdraw
    withdraw_res = auth_client.post("/api/consents", json={"purpose": "Analytics", "action": "withdraw"})
    assert withdraw_res.status_code == 201

    # Access must be blocked immediately
    access2 = auth_client.post("/api/data-access", json={"purpose": "Analytics"})
    assert access2.status_code == 403
    assert access2.get_json()["reason_code"] == "WITHDRAWN"


def test_12_notice_version_change_requires_fresh_consent(auth_client):
    """Scenario 12: Notice version changes invalidate old consent and require fresh consent."""
    auth_client.post(
        "/api/auth/signup",
        json={"name": "Notice Tester", "email": "notice@example.com", "password": "Password123!"},
    )

    # Grant under v1.0
    auth_client.post("/api/consents", json={"purpose": "Analytics", "action": "grant"})
    assert auth_client.post("/api/data-access", json={"purpose": "Analytics"}).status_code == 200

    # Notice upgraded to v2.0
    auth_client.post("/api/notice/update", json={"notice_version": "2.0"})

    # Prior consent is now outdated -> 403
    stale_res = auth_client.post("/api/data-access", json={"purpose": "Analytics"})
    assert stale_res.status_code == 403
    assert stale_res.get_json()["reason_code"] == "NOTICE_MISMATCH"

    # Grant fresh consent under v2.0
    auth_client.post("/api/consents", json={"purpose": "Analytics", "action": "grant"})
    assert auth_client.post("/api/data-access", json={"purpose": "Analytics"}).status_code == 200


def test_13_unauthenticated_users_cannot_access_protected_apis():
    """Scenario 13: Unauthenticated requests cannot access protected pages or APIs."""
    # Create a non-testing client
    with tempfile.TemporaryDirectory() as temp_dir:
        test_db = Path(temp_dir) / "test_unauth.db"
        with patch.object(database, "DATABASE_PATH", test_db):
            database.initialize_database()

            # Create test client without TESTING flag
            api.app.config["TESTING"] = False
            unauth_client = api.app.test_client()

            # Attempt unauthenticated requests
            c_res = unauth_client.get("/api/consents")
            assert c_res.status_code == 401
            assert c_res.get_json()["reason_code"] == "UNAUTHENTICATED"

            post_c = unauth_client.post("/api/consents", json={"purpose": "Analytics", "action": "grant"})
            assert post_c.status_code == 401

            access_res = unauth_client.post("/api/data-access", json={"purpose": "Analytics"})
            assert access_res.status_code == 401

            audit_res = unauth_client.get("/api/audit")
            assert audit_res.status_code == 401


def test_14_demo_accounts_isolation_and_integrity(auth_client):
    """Scenario 14: Demo accounts are isolated and existing diagnostic integrity remains functional."""
    # Log in as demo-user
    d1 = auth_client.post("/api/auth/demo-login", json={"user_id": "demo-user"})
    assert d1.status_code == 200
    assert d1.get_json()["user"]["id"] == "demo-user"

    auth_client.post("/api/consents", json={"purpose": "Analytics", "action": "grant"})
    assert auth_client.post("/api/data-access", json={"purpose": "Analytics"}).status_code == 200

    # Switch to user1
    d2 = auth_client.post("/api/auth/demo-login", json={"user_id": "user1"})
    assert d2.status_code == 200
    assert d2.get_json()["user"]["id"] == "user1"

    # user1 has no consent granted
    user1_access = auth_client.post("/api/data-access", json={"purpose": "Analytics"})
    assert user1_access.status_code == 403
    assert user1_access.get_json()["reason_code"] == "NO_CONSENT"
