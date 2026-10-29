import concurrent.futures
import sqlite3
import sys
from pathlib import Path
import pytest
from datetime import datetime, timezone

ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from database import (
    GENESIS_PREV_HASH,
    append_audit_event,
    compute_audit_hash,
    verify_audit_chain,
    DEFAULT_NOTICE_VERSION,
    DEFAULT_NOTICE_HASH,
)


@pytest.fixture
def test_db():
    """Creates an in-memory SQLite database for audit chain testing."""
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
    yield conn
    conn.close()


def test_01_valid_linear_chain(test_db):
    """Test 1: Normal linear append creates a valid, verifiable hash chain."""
    for i in range(5):
        append_audit_event(
            test_db,
            user_id=f"user_{i}",
            purpose="Analytics",
            action="grant",
            http_status=200,
            reason_code="CONSENT_RECORDED",
            notice_version=DEFAULT_NOTICE_VERSION,
            notice_hash=DEFAULT_NOTICE_HASH,
            source="test",
            details=f"Test event {i}",
        )

    result = verify_audit_chain(test_db, strict_linear=True)
    assert result["status"] == "intact"
    assert result["verified_count"] == 5
    assert result["total_count"] == 5
    assert result["branches_count"] == 0
    assert result["topology"] == "linear"


def test_02_modified_record_fails_tampered_hash(test_db):
    """Test 2: Modifying an existing record's contents triggers row_hash tampered."""
    for i in range(5):
        append_audit_event(
            test_db,
            user_id=f"user_{i}",
            purpose="Analytics",
            action="grant",
            http_status=200,
            reason_code="CONSENT_RECORDED",
            notice_version=DEFAULT_NOTICE_VERSION,
            notice_hash=DEFAULT_NOTICE_HASH,
            source="test",
        )

    # Tamper with record ID 3 (change action from 'grant' to 'deny' directly)
    test_db.execute("UPDATE audit_events SET action = 'deny' WHERE id = 3")

    result = verify_audit_chain(test_db)
    assert result["status"] == "broken"
    assert result["broken_at_id"] == 3
    assert "row_hash tampered" in result["message"]
    assert result["verified_count"] == 2  # records 1 and 2 passed before failure


def test_03_missing_record_fails_prev_hash_mismatch(test_db):
    """Test 3: Deleting an intermediate record breaks parent linkage."""
    for i in range(5):
        append_audit_event(
            test_db,
            user_id=f"user_{i}",
            purpose="Analytics",
            action="grant",
            http_status=200,
            reason_code="CONSENT_RECORDED",
            notice_version=DEFAULT_NOTICE_VERSION,
            notice_hash=DEFAULT_NOTICE_HASH,
            source="test",
        )

    # Delete record ID 3
    test_db.execute("DELETE FROM audit_events WHERE id = 3")

    result = verify_audit_chain(test_db)
    assert result["status"] == "broken"
    assert result["broken_at_id"] == 4  # Record 4's prev_hash points to deleted record 3
    assert "prev_hash mismatch" in result["message"]


def test_04_incorrect_prev_hash_fails(test_db):
    """Test 4: A record pointing to a non-existent / forged prev_hash fails verification."""
    append_audit_event(
        test_db,
        user_id="user_1",
        purpose="Analytics",
        action="grant",
        http_status=200,
        reason_code="CONSENT_RECORDED",
        notice_version=DEFAULT_NOTICE_VERSION,
        notice_hash=DEFAULT_NOTICE_HASH,
    )

    # Manually insert a record with a fake prev_hash
    bogus_prev = "f" * 64
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    row_hash = compute_audit_hash(
        bogus_prev, "user_2", "Analytics", "grant", 200, "CONSENT_RECORDED",
        DEFAULT_NOTICE_VERSION, DEFAULT_NOTICE_HASH, "test", now_str
    )
    test_db.execute("""
        INSERT INTO audit_events
            (user_id, purpose, action, http_status, reason_code, notice_version,
             notice_hash, short_notice_hash, source, prev_hash, row_hash, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, ("user_2", "Analytics", "grant", 200, "CONSENT_RECORDED", DEFAULT_NOTICE_VERSION,
          DEFAULT_NOTICE_HASH, "", "test", bogus_prev, row_hash, "", now_str))

    result = verify_audit_chain(test_db)
    assert result["status"] == "broken"
    assert result["broken_at_id"] == 2
    assert "prev_hash mismatch" in result["message"]


def test_05_genesis_record_verification(test_db):
    """Test 5: Genesis record must point to GENESIS_PREV_HASH."""
    append_audit_event(
        test_db,
        user_id="user_1",
        purpose="Analytics",
        action="grant",
        http_status=200,
        reason_code="CONSENT_RECORDED",
        notice_version=DEFAULT_NOTICE_VERSION,
        notice_hash=DEFAULT_NOTICE_HASH,
    )

    # Corrupt genesis prev_hash
    test_db.execute("UPDATE audit_events SET prev_hash = '1' * 64 WHERE id = 1")
    # Also recalculate row_hash so self-hash passes, testing genesis check specifically
    row = test_db.execute("SELECT * FROM audit_events WHERE id = 1").fetchone()
    new_h = compute_audit_hash(
        row["prev_hash"], row["user_id"], row["purpose"], row["action"],
        row["http_status"], row["reason_code"], row["notice_version"],
        row["notice_hash"], row["source"], row["created_at"]
    )
    test_db.execute("UPDATE audit_events SET row_hash = ? WHERE id = 1", (new_h,))

    result = verify_audit_chain(test_db)
    assert result["status"] == "broken"
    assert result["broken_at_id"] == 1
    assert "genesis prev_hash mismatch" in result["message"]


def test_06_concurrent_sibling_branches_dag_verification(test_db):
    """
    Test 6: Sibling branches created by concurrent writes off a common parent
    are recognized and verified in DAG mode, while detected in strict linear mode.
    """
    # Event 1 (Parent)
    h1 = append_audit_event(
        test_db, user_id="user_1", purpose="Analytics", action="grant",
        http_status=200, reason_code="OK", notice_version="1.0", notice_hash="hash1"
    )

    # Event 2 (Sibling A off Event 1)
    append_audit_event(
        test_db, user_id="user_2", purpose="Marketing", action="deny",
        http_status=200, reason_code="OK", notice_version="1.0", notice_hash="hash1"
    )

    # Event 3 (Sibling B concurrently created off Event 1, pointing to h1 instead of h2)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    h3 = compute_audit_hash(
        h1, "user_3", "Analytics", "grant", 200, "OK", "1.0", "hash1", "test", now_str
    )
    test_db.execute("""
        INSERT INTO audit_events
            (user_id, purpose, action, http_status, reason_code, notice_version,
             notice_hash, short_notice_hash, source, prev_hash, row_hash, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, ("user_3", "Analytics", "grant", 200, "OK", "1.0", "hash1", "", "test", h1, h3, "", now_str))

    # Event 4 (Child of Sibling B)
    now_str4 = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    h4 = compute_audit_hash(
        h3, "user_3", "Analytics", "grant", 200, "OK", "1.0", "hash1", "test", now_str4
    )
    test_db.execute("""
        INSERT INTO audit_events
            (user_id, purpose, action, http_status, reason_code, notice_version,
             notice_hash, short_notice_hash, source, prev_hash, row_hash, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, ("user_3", "Analytics", "grant", 200, "OK", "1.0", "hash1", "", "test", h3, h4, "", now_str4))

    # DAG verification should pass 100%
    dag_result = verify_audit_chain(test_db, strict_linear=False)
    assert dag_result["status"] == "intact"
    assert dag_result["verified_count"] == 4
    assert dag_result["branches_count"] == 1
    assert dag_result["branches"][0]["record_id"] == 3
    assert dag_result["branches"][0]["parent_record_id"] == 1

    # Strict linear verification should report the branch at ID 3
    strict_result = verify_audit_chain(test_db, strict_linear=True)
    assert strict_result["status"] == "broken"
    assert strict_result["broken_at_id"] == 3
    assert "concurrent write branch detected" in strict_result["message"]


def test_07_concurrent_append_locking(tmp_path):
    """
    Test 7: Multi-threaded concurrent appends use append_audit_event locking
    and produce a strictly linear, unbroken chain.
    """
    db_file = tmp_path / "concurrent_test.db"
    conn_main = sqlite3.connect(str(db_file), timeout=10.0)
    conn_main.row_factory = sqlite3.Row
    conn_main.execute("""
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
    conn_main.commit()

    def worker(idx):
        conn = sqlite3.connect(str(db_file), timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            append_audit_event(
                conn,
                user_id=f"concurrent_user_{idx}",
                purpose="Analytics",
                action="grant",
                http_status=200,
                reason_code="OK",
                notice_version="1.0",
                notice_hash="hash1",
                source="worker",
                details=f"Thread event {idx}",
            )
            conn.commit()
        finally:
            conn.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(worker, i) for i in range(15)]
        for f in concurrent.futures.as_completed(futures):
            f.result()

    result = verify_audit_chain(conn_main, strict_linear=True)
    conn_main.close()

    assert result["status"] == "intact"
    assert result["verified_count"] == 15
    assert result["branches_count"] == 0
    assert result["topology"] == "linear"


def test_08_user_scoped_verification(test_db):
    """Test 8: User-scoped verification checks row integrity for a specific user."""
    append_audit_event(test_db, "user_A", "Analytics", "grant", 200, "OK", "1.0", "h1")
    append_audit_event(test_db, "user_B", "Marketing", "deny", 200, "OK", "1.0", "h1")
    append_audit_event(test_db, "user_A", "Marketing", "grant", 200, "OK", "1.0", "h1")

    res_a = verify_audit_chain(test_db, user_id="user_A")
    assert res_a["status"] == "intact"
    assert res_a["verified_count"] == 2

    res_b = verify_audit_chain(test_db, user_id="user_B")
    assert res_b["status"] == "intact"
    assert res_b["verified_count"] == 1
