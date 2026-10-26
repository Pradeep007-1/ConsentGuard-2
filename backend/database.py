import hashlib
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

DATABASE_PATH = Path(__file__).parent / "consentguard.db"

GENESIS_PREV_HASH = "0" * 64

DEFAULT_NOTICE_VERSION = "1.0"
DEFAULT_NOTICE_TEXT = (
    "ConsentGuard Purpose-Based Consent Notice: User data is processed strictly for itemized, "
    "explicit purposes selected by the user. Consent may be revoked at any time. When this notice "
    "is updated, fresh consent must be recorded before downstream processing can continue."
)
DEFAULT_NOTICE_HASH = hashlib.sha256(DEFAULT_NOTICE_TEXT.encode("utf-8")).hexdigest()


@contextmanager
def get_connection():
    connection = sqlite3.connect(DATABASE_PATH, timeout=10.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode = WAL;")
    connection.execute("PRAGMA synchronous = NORMAL;")
    connection.execute("PRAGMA busy_timeout = 5000;")

    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def compute_audit_hash(
    prev_hash,
    user_id,
    purpose,
    action,
    http_status,
    reason_code,
    notice_version,
    notice_hash,
    source,
    created_at,
):
    raw = (
        f"{prev_hash}|{user_id}|{purpose}|{action}|{http_status}|"
        f"{reason_code}|{notice_version}|{notice_hash}|{source}|{created_at}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def append_audit_event(
    connection,
    user_id,
    purpose,
    action,
    http_status,
    reason_code,
    notice_version,
    notice_hash,
    source="user",
    details="",
):
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    last_row = connection.execute(
        "SELECT row_hash FROM audit_events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    prev_hash = last_row["row_hash"] if last_row and last_row["row_hash"] else GENESIS_PREV_HASH
    short_hash = notice_hash[:12] if notice_hash else ""

    row_hash = compute_audit_hash(
        prev_hash,
        user_id,
        purpose,
        action,
        http_status,
        reason_code,
        notice_version,
        notice_hash,
        source,
        created_at,
    )

    connection.execute(
        """
        INSERT INTO audit_events
            (user_id, purpose, action, http_status, reason_code,
             notice_version, notice_hash, short_notice_hash, source,
             prev_hash, row_hash, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            purpose,
            action,
            http_status,
            reason_code,
            notice_version,
            notice_hash,
            short_hash,
            source,
            prev_hash,
            row_hash,
            details,
            created_at,
        ),
    )
    return row_hash


def verify_audit_chain(connection):
    rows = connection.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
    expected_prev = GENESIS_PREV_HASH
    for idx, row in enumerate(rows):
        if row["prev_hash"] != expected_prev:
            return {
                "status": "broken",
                "verified_count": idx,
                "total_count": len(rows),
                "broken_at_id": row["id"],
                "message": f"Audit hash chain broken at record ID {row['id']}: prev_hash mismatch.",
            }

        expected_row_hash = compute_audit_hash(
            row["prev_hash"],
            row["user_id"],
            row["purpose"],
            row["action"],
            row["http_status"],
            row["reason_code"],
            row["notice_version"],
            row["notice_hash"],
            row["source"],
            row["created_at"],
        )

        if row["row_hash"] != expected_row_hash:
            return {
                "status": "broken",
                "verified_count": idx,
                "total_count": len(rows),
                "broken_at_id": row["id"],
                "message": f"Audit hash chain broken at record ID {row['id']}: row_hash tampered.",
            }

        expected_prev = row["row_hash"]

    return {
        "status": "intact",
        "verified_count": len(rows),
        "total_count": len(rows),
        "message": f"Audit hash chain is intact across all {len(rows)} events.",
    }


def get_active_notice_from_db():
    with get_connection() as connection:
        row = connection.execute(
            "SELECT version, text, hash FROM notice_versions ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row:
            return row["version"], row["text"], row["hash"]
        return DEFAULT_NOTICE_VERSION, DEFAULT_NOTICE_TEXT, DEFAULT_NOTICE_HASH


def initialize_database():
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS consents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                purpose TEXT NOT NULL,
                granted INTEGER NOT NULL CHECK (granted IN (0, 1)),
                notice_version TEXT NOT NULL,
                notice_hash TEXT NOT NULL DEFAULT '',
                last_action TEXT NOT NULL DEFAULT 'grant',
                updated_at TEXT NOT NULL DEFAULT (
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                ),
                UNIQUE (user_id, purpose)
            )
            """
        )

        # Check if last_action and notice_hash columns exist in consents
        consent_cols = [
            row["name"]
            for row in connection.execute("PRAGMA table_info(consents)").fetchall()
        ]
        if "last_action" not in consent_cols:
            connection.execute(
                "ALTER TABLE consents ADD COLUMN last_action TEXT NOT NULL DEFAULT 'grant'"
            )
        if "notice_hash" not in consent_cols:
            connection.execute(
                "ALTER TABLE consents ADD COLUMN notice_hash TEXT NOT NULL DEFAULT ''"
            )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                purpose TEXT NOT NULL,
                action TEXT NOT NULL,
                http_status INTEGER,
                reason_code TEXT,
                notice_version TEXT NOT NULL,
                notice_hash TEXT NOT NULL,
                short_notice_hash TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'user',
                prev_hash TEXT NOT NULL,
                row_hash TEXT NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL DEFAULT (
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                )
            )
            """
        )

        # Ensure all columns exist on audit_events
        audit_cols = [
            row["name"]
            for row in connection.execute("PRAGMA table_info(audit_events)").fetchall()
        ]
        required_audit_cols = {
            "http_status": "INTEGER",
            "reason_code": "TEXT",
            "notice_hash": "TEXT NOT NULL DEFAULT ''",
            "short_notice_hash": "TEXT NOT NULL DEFAULT ''",
            "source": "TEXT NOT NULL DEFAULT 'user'",
            "prev_hash": f"TEXT NOT NULL DEFAULT '{GENESIS_PREV_HASH}'",
            "row_hash": "TEXT NOT NULL DEFAULT ''",
        }
        for col, col_type in required_audit_cols.items():
            if col not in audit_cols:
                connection.execute(
                    f"ALTER TABLE audit_events ADD COLUMN {col} {col_type}"
                )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS notice_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version TEXT UNIQUE NOT NULL,
                text TEXT NOT NULL,
                hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                )
            )
            """
        )

        # Seed initial notice version if not present
        connection.execute(
            """
            INSERT OR IGNORE INTO notice_versions (version, text, hash, created_at)
            VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            """,
            (DEFAULT_NOTICE_VERSION, DEFAULT_NOTICE_TEXT, DEFAULT_NOTICE_HASH),
        )

        # Useful indexes for high-throughput reads
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_user_action ON audit_events(user_id, action)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_consents_user ON consents(user_id)"
        )


if __name__ == "__main__":
    initialize_database()
    print(f"Database initialized with WAL mode: {DATABASE_PATH}")
