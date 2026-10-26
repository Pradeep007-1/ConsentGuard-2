import hashlib
import json
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
def app_client():
    with tempfile.TemporaryDirectory() as temp_dir:
        test_db = Path(temp_dir) / "test_consent.db"
        with patch.object(database, "DATABASE_PATH", test_db):
            database.initialize_database()

            # Save initial global notice state
            orig_version = api.NOTICE_VERSION
            orig_text = api.NOTICE_TEXT
            orig_hash = api.NOTICE_HASH

            api.NOTICE_VERSION = database.DEFAULT_NOTICE_VERSION
            api.NOTICE_TEXT = database.DEFAULT_NOTICE_TEXT
            api.NOTICE_HASH = database.DEFAULT_NOTICE_HASH

            client = api.app.test_client()
            yield client

            # Restore global notice state
            api.NOTICE_VERSION = orig_version
            api.NOTICE_TEXT = orig_text
            api.NOTICE_HASH = orig_hash


# Helper functions
def record_consent(client, user_id, purpose, action, source="test"):
    return client.post(
        "/api/consents",
        json={
            "user_id": user_id,
            "purpose": purpose,
            "action": action,
            "source": source,
        },
    )


def request_data(client, user_id, purpose, source="test"):
    return client.post(
        "/api/data-access",
        json={
            "user_id": user_id,
            "purpose": purpose,
            "source": source,
        },
    )


# =========================================================================
# REQUIRED 14 TESTS FOR AIORI-3 HACKATHON 2026 PS-002
# =========================================================================

def test_01_access_without_consent_is_denied(app_client):
    """1. Access without consent is denied with HTTP 403 NO_CONSENT."""
    resp = request_data(app_client, "user2", "Marketing")
    assert resp.status_code == 403
    data = resp.get_json()
    assert data["allowed"] is False
    assert data["reason_code"] == "NO_CONSENT"


def test_02_granting_consent_permits_access_for_granted_purpose(app_client):
    """2. Granting consent permits access for the granted purpose (HTTP 200 ACTIVE_CONSENT)."""
    grant_res = record_consent(app_client, "user1", "Analytics", "grant")
    assert grant_res.status_code == 201

    access_res = request_data(app_client, "user1", "Analytics")
    assert access_res.status_code == 200
    data = access_res.get_json()
    assert data["allowed"] is True
    assert data["reason_code"] == "ACTIVE_CONSENT"
    assert "page_views" in data["data"]


def test_03_consent_for_one_purpose_does_not_authorize_another(app_client):
    """3. Consent for one purpose does not authorize another purpose (purpose isolation)."""
    record_consent(app_client, "user1", "Analytics", "grant")

    # Analytics is allowed
    assert request_data(app_client, "user1", "Analytics").status_code == 200

    # Marketing has no consent and must be blocked
    marketing_res = request_data(app_client, "user1", "Marketing")
    assert marketing_res.status_code == 403
    assert marketing_res.get_json()["reason_code"] == "NO_CONSENT"


def test_04_denying_consent_blocks_access(app_client):
    """4. Denying consent explicitly blocks access with HTTP 403 DENIED."""
    deny_res = record_consent(app_client, "user1", "Marketing", "deny")
    assert deny_res.status_code == 201

    access_res = request_data(app_client, "user1", "Marketing")
    assert access_res.status_code == 403
    data = access_res.get_json()
    assert data["allowed"] is False
    assert data["reason_code"] == "DENIED"


def test_05_withdrawing_consent_blocks_subsequent_access(app_client):
    """5. Withdrawing consent blocks subsequent access immediately (HTTP 403 WITHDRAWN)."""
    record_consent(app_client, "user1", "Analytics", "grant")
    assert request_data(app_client, "user1", "Analytics").status_code == 200

    withdraw_res = record_consent(app_client, "user1", "Analytics", "withdraw")
    assert withdraw_res.status_code == 201
    assert withdraw_res.get_json()["granted"] is False

    blocked_res = request_data(app_client, "user1", "Analytics")
    assert blocked_res.status_code == 403
    data = blocked_res.get_json()
    assert data["allowed"] is False
    assert data["reason_code"] == "WITHDRAWN"


def test_06_other_purposes_remain_unaffected_by_withdrawal(app_client):
    """6. Other purposes remain unaffected when one purpose is withdrawn."""
    record_consent(app_client, "user1", "Analytics", "grant")
    record_consent(app_client, "user1", "Marketing", "grant")

    # Withdraw Analytics only
    record_consent(app_client, "user1", "Analytics", "withdraw")

    # Analytics is blocked
    assert request_data(app_client, "user1", "Analytics").status_code == 403
    # Marketing is still allowed
    assert request_data(app_client, "user1", "Marketing").status_code == 200


def test_07_changing_notice_version_invalidates_stale_consent(app_client):
    """7. Changing notice version (v1.0 -> v2.0) invalidates consent granted under old notice."""
    record_consent(app_client, "user1", "Analytics", "grant")  # under v1.0
    assert request_data(app_client, "user1", "Analytics").status_code == 200

    # Publish Notice v2.0
    app_client.post(
        "/api/notice/update",
        json={"notice_version": "2.0", "source": "test"}
    )

    # Request with old v1 consent must be blocked with NOTICE_MISMATCH
    stale_res = request_data(app_client, "user1", "Analytics")
    assert stale_res.status_code == 403
    data = stale_res.get_json()
    assert data["allowed"] is False
    assert data["reason_code"] == "NOTICE_MISMATCH"
    assert data["user_notice_version"] == "1.0"
    assert data["active_notice_version"] == "2.0"


def test_08_fresh_consent_under_current_notice_permits_access(app_client):
    """8. Fresh consent under the current notice permits access after notice change."""
    record_consent(app_client, "user1", "Analytics", "grant")  # v1.0
    app_client.post(
        "/api/notice/update",
        json={"notice_version": "2.0", "source": "test"}
    )
    assert request_data(app_client, "user1", "Analytics").status_code == 403

    # Re-consent under v2.0
    reconsent_res = record_consent(app_client, "user1", "Analytics", "grant")
    assert reconsent_res.status_code == 201
    assert reconsent_res.get_json()["notice_version"] == "2.0"

    # Access is restored
    access_res = request_data(app_client, "user1", "Analytics")
    assert access_res.status_code == 200
    assert access_res.get_json()["allowed"] is True
    assert access_res.get_json()["reason_code"] == "ACTIVE_CONSENT"


def test_09_unknown_purposes_are_rejected(app_client):
    """9. Unknown/unregistered purposes are rejected with HTTP 400 INVALID_PURPOSE."""
    bad_req = request_data(app_client, "user1", "Biometric Profiling")
    assert bad_req.status_code == 400
    data = bad_req.get_json()
    assert data["allowed"] is False
    assert data["reason_code"] == "INVALID_PURPOSE"


def test_10_unknown_users_or_missing_consent_handled_safely(app_client):
    """10. Unknown users or missing consent are handled safely without crashing (HTTP 403 NO_CONSENT)."""
    res = request_data(app_client, "unknown-synthetic-user-999", "Analytics")
    assert res.status_code == 403
    data = res.get_json()
    assert data["allowed"] is False
    assert data["reason_code"] == "NO_CONSENT"
    assert "No consent decision" in data["reason"]


def test_11_audit_records_created_for_important_actions(app_client):
    """11. Audit records are created for all grants, withdrawals, denials, and access decisions."""
    record_consent(app_client, "user1", "Analytics", "grant", source="test")
    request_data(app_client, "user1", "Analytics", source="test")
    record_consent(app_client, "user1", "Analytics", "withdraw", source="test")
    request_data(app_client, "user1", "Analytics", source="test")

    audit_res = app_client.get("/api/audit?user_id=user1")
    assert audit_res.status_code == 200
    events = audit_res.get_json()
    assert len(events) >= 4

    actions = [e["action"] for e in events]
    assert "grant" in actions
    assert "data_access_allowed" in actions
    assert "withdraw" in actions
    assert "data_access_denied" in actions

    for e in events:
        assert e["http_status"] in (200, 201, 403)
        assert e["reason_code"] is not None
        assert e["source"] == "test"
        assert len(e["row_hash"]) == 64
        assert len(e["prev_hash"]) == 64


def test_12_notice_hashes_calculated_and_verified_correctly(app_client):
    """12. Notice hashes are calculated deterministically from actual notice content."""
    notice_res = app_client.get("/api/notice")
    assert notice_res.status_code == 200
    data = notice_res.get_json()

    # Re-calculate hash independently from content
    expected_hash = hashlib.sha256(data["notice_text"].encode("utf-8")).hexdigest()
    assert data["notice_hash"] == expected_hash
    assert len(data["notice_hash"]) == 64


def test_13_repeated_access_requests_enforce_latest_consent_state(app_client):
    """13. Repeated access requests enforce the latest consent state dynamically."""
    # 1. Initially no consent -> 403
    assert request_data(app_client, "user1", "Analytics").status_code == 403
    assert request_data(app_client, "user1", "Analytics").status_code == 403

    # 2. Grant -> 200
    record_consent(app_client, "user1", "Analytics", "grant")
    assert request_data(app_client, "user1", "Analytics").status_code == 200
    assert request_data(app_client, "user1", "Analytics").status_code == 200

    # 3. Withdraw -> 403 immediately
    record_consent(app_client, "user1", "Analytics", "withdraw")
    assert request_data(app_client, "user1", "Analytics").status_code == 403
    assert request_data(app_client, "user1", "Analytics").status_code == 403

    # 4. Re-grant -> 200 immediately
    record_consent(app_client, "user1", "Analytics", "grant")
    assert request_data(app_client, "user1", "Analytics").status_code == 200


def test_14_audit_export_returns_valid_records(app_client):
    """14. Audit export returns valid CSV and JSON records containing all metadata."""
    record_consent(app_client, "user1", "Analytics", "grant", source="test")
    request_data(app_client, "user1", "Analytics", source="test")

    # CSV Export
    csv_res = app_client.get("/api/audit/export?format=csv")
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.content_type
    csv_text = csv_res.data.decode("utf-8")
    assert "user_id,purpose,action" in csv_text or "id,user_id" in csv_text
    assert "notice_version" in csv_text
    assert "row_hash" in csv_text

    # JSON Export
    json_res = app_client.get("/api/audit/export?format=json")
    assert json_res.status_code == 200
    assert "application/json" in json_res.content_type
    items = json.loads(json_res.data.decode("utf-8"))
    assert len(items) >= 2
    first = items[0]
    assert "http_status" in first
    assert "reason_code" in first
    assert "notice_hash" in first
    assert "prev_hash" in first
    assert "row_hash" in first


def test_15_audit_hash_chain_intact_and_verifiable(app_client):
    """15. Append-only audit chain is cryptographically intact across all operations."""
    record_consent(app_client, "user1", "Analytics", "grant", source="test")
    request_data(app_client, "user1", "Analytics", source="test")
    record_consent(app_client, "user1", "Analytics", "withdraw", source="test")
    request_data(app_client, "user1", "Analytics", source="test")

    verify_res = app_client.get("/api/audit/verify")
    assert verify_res.status_code == 200
    result = verify_res.get_json()
    assert result["status"] == "intact"
    assert result["verified_count"] >= 4


def test_16_notice_invalidation_lifecycle_and_withdrawal_isolation(app_client):
    """16. Verify complete notice invalidation, re-consent, withdrawal, reset isolation, and audit logging."""
    # 1. Grant consent under v1.0 and access permitted data
    grant_res = record_consent(app_client, "user_lifecycle", "Service Improvement", "grant", source="test")
    assert grant_res.status_code == 201
    assert grant_res.get_json()["granted"] is True
    assert grant_res.get_json()["notice_version"] == "1.0"

    access_res = request_data(app_client, "user_lifecycle", "Service Improvement", source="test")
    assert access_res.status_code == 200
    assert access_res.get_json()["allowed"] is True
    assert "app_performance_ms" in access_res.get_json()["data"]

    # 2. Change notice to v2.0
    update_res = app_client.post("/api/notice/update", json={"notice_version": "2.0", "source": "test"})
    assert update_res.status_code == 200

    # 3 & 4. Previous v1.0 consent is now invalid -> HTTP 403 NOTICE_MISMATCH
    stale_access = request_data(app_client, "user_lifecycle", "Service Improvement", source="test")
    assert stale_access.status_code == 403
    stale_data = stale_access.get_json()
    assert stale_data["allowed"] is False
    assert stale_data["reason_code"] == "NOTICE_MISMATCH"
    assert "NOTICE_OUTDATED_RECONSENT_REQUIRED" in (stale_data.get("reason", "") + stale_data.get("error_code", ""))

    # 5. Database state reflects notice v1.0 while active notice is v2.0
    consents_res = app_client.get("/api/consents?user_id=user_lifecycle")
    assert consents_res.status_code == 200
    user_consents = consents_res.get_json()
    assert len(user_consents) == 1
    assert user_consents[0]["notice_version"] == "1.0"
    assert user_consents[0]["granted"] == 1  # Persisted DB record is preserved

    # 6. Grant fresh consent under v2.0
    fresh_grant = record_consent(app_client, "user_lifecycle", "Service Improvement", "grant", source="test")
    assert fresh_grant.status_code == 201
    assert fresh_grant.get_json()["notice_version"] == "2.0"

    # 7. Access is allowed again
    fresh_access = request_data(app_client, "user_lifecycle", "Service Improvement", source="test")
    assert fresh_access.status_code == 200
    assert fresh_access.get_json()["allowed"] is True

    # 8. Withdraw the new consent
    withdraw_res = record_consent(app_client, "user_lifecycle", "Service Improvement", "withdraw", source="test")
    assert withdraw_res.status_code == 201
    blocked_access = request_data(app_client, "user_lifecycle", "Service Improvement", source="test")
    assert blocked_access.status_code == 403
    assert blocked_access.get_json()["reason_code"] == "WITHDRAWN"

    # 9. Reset notice to v1.0: previously withdrawn consent is NOT automatically restored
    reset_res = app_client.post("/api/notice/reset", json={"source": "test"})
    assert reset_res.status_code == 200
    after_reset_access = request_data(app_client, "user_lifecycle", "Service Improvement", source="test")
    assert after_reset_access.status_code == 403
    assert after_reset_access.get_json()["reason_code"] == "WITHDRAWN"

    # 10. Confirm audit log recorded every transition with full detail
    audit_res = app_client.get("/api/audit?user_id=user_lifecycle")
    assert audit_res.status_code == 200
    events = audit_res.get_json()
    actions = [e["action"] for e in events]
    assert "grant" in actions
    assert "withdraw" in actions
    assert "data_access_allowed" in actions
    assert "data_access_denied" in actions

