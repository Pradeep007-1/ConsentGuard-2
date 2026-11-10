import hashlib
import json
import os
import re
import sqlite3
import ssl
import threading
import time
import urllib.parse
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from werkzeug.security import generate_password_hash

DATABASE_PATH = Path(__file__).parent / "consentguard.db"
_sqlite_audit_lock = threading.Lock()


def is_local_mode() -> bool:
    """
    Returns True if explicitly running in local/offline mode.
    Forces ConsentGuard to operate completely disconnected from cloud services,
    ensuring 100% reliability during offline hackathon demonstrations.
    """
    val = (os.environ.get("LOCAL_MODE") or os.environ.get("OFFLINE_MODE") or "").strip().lower()
    return val in ("1", "true", "yes", "on")


def get_database_url():
    """
    Returns database URL from environment variables, supporting Neon, Vercel Postgres, Supabase.
    If LOCAL_MODE=1 or OFFLINE_MODE=1, strictly returns an empty string to prevent any accidental
    cloud database network calls during offline demonstrations.
    """
    if is_local_mode():
        return ""

    url = (
        os.environ.get("DATABASE_URL")
        or os.environ.get("POSTGRES_URL")
        or os.environ.get("POSTGRES_PRISMA_URL")
        or os.environ.get("DATABASE_URL_UNPOOLED")
        or os.environ.get("POSTGRES_URL_NON_POOLING")
        or os.environ.get("NEON_DATABASE_URL")
        or ""
    ).strip()
    if not url:
        host = os.environ.get("PGHOST")
        user = os.environ.get("PGUSER")
        password = os.environ.get("PGPASSWORD")
        database_name = os.environ.get("PGDATABASE", "neondb")
        port = os.environ.get("PGPORT", "5432")
        if host and user and password:
            url = f"postgresql://{user}:{password}@{host}:{port}/{database_name}?sslmode=require"
    return url


GENESIS_PREV_HASH = "0" * 64

DEFAULT_NOTICE_VERSION = "1.0"
DEFAULT_NOTICE_TEXT = (
    "ConsentGuard Purpose-Based Consent Notice: User data is processed strictly for itemized, "
    "explicit purposes selected by the user. Consent may be revoked at any time. When this notice "
    "is updated, fresh consent must be recorded before downstream processing can continue."
)
DEFAULT_NOTICE_HASH = hashlib.sha256(DEFAULT_NOTICE_TEXT.encode("utf-8")).hexdigest()


def is_postgres():
    if is_local_mode():
        return False
    url = get_database_url()
    return url.startswith("postgres://") or url.startswith("postgresql://")


class PostgresCursorWrapper:
    """Wraps pg8000 cursor to provide dict-like rows and translate '?' to '%s'."""

    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, query, params=None):
        if params is None:
            params = ()
        # Convert ? to %s for PostgreSQL
        converted_query = query.replace("?", "%s")
        self._cursor.execute(converted_query, params)
        return self

    def fetchone(self):
        if not self._cursor.description:
            return None
        row = self._cursor.fetchone()
        if row is None:
            return None
        cols = [col[0] for col in self._cursor.description]
        return dict(zip(cols, row))

    def fetchall(self):
        if not self._cursor.description:
            return []
        rows = self._cursor.fetchall()
        if not rows:
            return []
        cols = [col[0] for col in self._cursor.description]
        return [dict(zip(cols, row)) for row in rows]

    def __getattr__(self, name):
        return getattr(self._cursor, name)


class PostgresConnectionWrapper:
    """Wraps pg8000 connection for context management."""

    def __init__(self, raw_conn):
        self._conn = raw_conn

    def execute(self, query, params=None):
        cursor = self._conn.cursor()
        wrapper = PostgresCursorWrapper(cursor)
        return wrapper.execute(query, params)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


@contextmanager
def get_connection():
    target_url = get_database_url()
    if target_url.startswith("postgres://") or target_url.startswith("postgresql://"):
        import pg8000.dbapi

        parsed = urllib.parse.urlparse(target_url)
        user = urllib.parse.unquote(parsed.username or "")
        password = urllib.parse.unquote(parsed.password or "")
        host = parsed.hostname or "localhost"
        port = parsed.port or 5432
        database_name = (parsed.path or "/").lstrip("/") or "postgres"

        ssl_ctx = None
        if "sslmode=require" in target_url.lower() or parsed.hostname not in ("localhost", "127.0.0.1"):
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        raw_conn = None
        last_err = None
        for attempt in range(3):
            try:
                raw_conn = pg8000.dbapi.connect(
                    user=user,
                    password=password,
                    host=host,
                    port=port,
                    database=database_name,
                    ssl_context=ssl_ctx,
                    timeout=15,
                )
                break
            except Exception as e:
                last_err = e
                if attempt < 2:
                    time.sleep(0.3 * (attempt + 1))

        if raw_conn is None:
            raise last_err

        wrapper = PostgresConnectionWrapper(raw_conn)
        try:
            yield wrapper
            wrapper.commit()
        except Exception:
            wrapper.rollback()
            raise
        finally:
            wrapper.close()
    else:
        connection = sqlite3.connect(DATABASE_PATH, timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode = WAL;")
        connection.execute("PRAGMA synchronous = NORMAL;")
        connection.execute("PRAGMA busy_timeout = 5000;")
        connection.execute("PRAGMA foreign_keys = ON;")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


def sanitize_audit_details(details: str) -> str:
    """Strips any sensitive credentials, tokens, or email addresses from audit details."""
    if not details:
        return ""
    text = str(details)
    # Redact email addresses
    text = re.sub(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "[REDACTED_EMAIL]", text)
    # Redact bearer tokens, API keys, and secrets
    text = re.sub(
        r"(Bearer\s+|api_key=|key=|secret=|token=|password=)[a-zA-Z0-9_\-\.]{8,}",
        r"\1[REDACTED_SECRET]",
        text,
        flags=re.IGNORECASE,
    )
    return text


def compute_canonical_audit_hash(
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
    details="",
):
    """
    Computes cryptographic SHA-256 hash using canonical JSON formatting
    (sort_keys=True, separators=(',', ':')) across ALL audit fields including details.
    """
    payload = {
        "action": str(action or ""),
        "created_at": str(created_at or ""),
        "details": str(details or ""),
        "http_status": int(http_status) if http_status is not None else None,
        "notice_hash": str(notice_hash or ""),
        "notice_version": str(notice_version or ""),
        "prev_hash": str(prev_hash or ""),
        "purpose": str(purpose or ""),
        "reason_code": str(reason_code or ""),
        "source": str(source or ""),
        "user_id": str(user_id or ""),
    }
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


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
    """Legacy pipe-delimited hash calculation preserved for historical record verification."""
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
    # Serialize concurrent transactions on PostgreSQL using transaction-level advisory locks
    if is_postgres():
        try:
            connection.execute("SELECT pg_advisory_xact_lock(7429184);")
        except Exception:
            try:
                connection.execute("LOCK TABLE audit_events IN EXCLUSIVE MODE;")
            except Exception:
                pass

    clean_details = sanitize_audit_details(details)

    with _sqlite_audit_lock:
        if not is_postgres():
            try:
                connection.execute("BEGIN IMMEDIATE")
            except Exception:
                pass

        created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        last_row = connection.execute(
            "SELECT row_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = last_row["row_hash"] if last_row and last_row["row_hash"] else GENESIS_PREV_HASH
        short_hash = notice_hash[:12] if notice_hash else ""

        # Use canonical JSON hashing covering all fields including details
        row_hash = compute_canonical_audit_hash(
            prev_hash=prev_hash,
            user_id=user_id,
            purpose=purpose,
            action=action,
            http_status=http_status,
            reason_code=reason_code,
            notice_version=notice_version,
            notice_hash=notice_hash,
            source=source,
            created_at=created_at,
            details=clean_details,
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
                clean_details,
                created_at,
            ),
        )
        return row_hash


def is_valid_row_hash(row) -> bool:
    """
    Validates row_hash against canonical JSON hashing first,
    falling back to legacy pipe-delimited format for historical record compatibility.
    """
    row_h = row["row_hash"]
    prev_h = row["prev_hash"]
    user_id = row["user_id"]
    purpose = row["purpose"]
    action = row["action"]
    http_status = row["http_status"]
    reason_code = row["reason_code"]
    notice_version = row["notice_version"]
    notice_hash = row["notice_hash"]
    source = row["source"]
    created_at = row["created_at"]
    
    details = ""
    try:
        details = row["details"] or ""
    except (IndexError, KeyError, TypeError):
        pass

    # 1. Canonical JSON (new standard)
    canon = compute_canonical_audit_hash(
        prev_hash=prev_h,
        user_id=user_id,
        purpose=purpose,
        action=action,
        http_status=http_status,
        reason_code=reason_code,
        notice_version=notice_version,
        notice_hash=notice_hash,
        source=source,
        created_at=created_at,
        details=details,
    )
    if row_h == canon:
        return True

    # 2. Legacy pipe-delimited (historical records)
    legacy = compute_audit_hash(
        prev_h,
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
    if row_h == legacy:
        return True

    return False


def verify_audit_chain(connection, user_id=None, strict_linear=False):
    """
    Cryptographically verifies the append-only audit ledger.

    Verifications:
    1. Every record's self-hash matches sha256(prev_hash + payload) exactly (detects payload or hash tampering).
    2. The genesis record's prev_hash matches GENESIS_PREV_HASH ('0' * 64).
    3. Every subsequent record points to a cryptographically verified prior record in the ledger.
    4. If strict_linear=True, enforces strict single-parent sequential linearity (row[i].prev_hash == row[i-1].row_hash).
       If strict_linear=False (default for multi-instance serverless deployments), validates Merkle DAG topology,
       confirming that every record is cryptographically anchored to a verified ancestor, while detecting and
       reporting any concurrent sibling write branches.
    """
    if user_id:
        user_rows = connection.execute(
            "SELECT * FROM audit_events WHERE user_id = ? ORDER BY id ASC",
            (user_id,),
        ).fetchall()

        for idx, row in enumerate(user_rows):
            if not is_valid_row_hash(row):
                return {
                    "status": "broken",
                    "reason_code": "ROW_HASH_TAMPERED",
                    "verified_count": idx,
                    "total_count": len(user_rows),
                    "broken_at_id": row["id"],
                    "message": f"Audit hash chain broken at record ID {row['id']}: row_hash tampered.",
                }
        return {
            "status": "intact",
            "verified_count": len(user_rows),
            "total_count": len(user_rows),
            "message": f"User audit records intact across all {len(user_rows)} events.",
        }

    rows = connection.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
    if not rows:
        return {
            "status": "intact",
            "verified_count": 0,
            "total_count": 0,
            "branches_count": 0,
            "branches": [],
            "topology": "linear",
            "message": "Audit log is empty.",
        }

    known_hashes = {GENESIS_PREV_HASH: 0}  # maps row_hash -> record id (0 = genesis)
    branches = []
    expected_prev = GENESIS_PREV_HASH

    for idx, row in enumerate(rows):
        cur_id = row["id"]
        prev_h = row["prev_hash"]
        row_h = row["row_hash"]

        # 1. Verify self-hash integrity (canonical JSON + legacy pipe fallback)
        if not is_valid_row_hash(row):
            return {
                "status": "broken",
                "reason_code": "ROW_HASH_TAMPERED",
                "verified_count": idx,
                "total_count": len(rows),
                "broken_at_id": cur_id,
                "message": f"Audit hash chain broken at record ID {cur_id}: row_hash tampered.",
            }

        # 2. Check parent linkage
        if idx == 0:
            if prev_h != GENESIS_PREV_HASH:
                return {
                    "status": "broken",
                    "reason_code": "GENESIS_PREV_HASH_MISMATCH",
                    "verified_count": 0,
                    "total_count": len(rows),
                    "broken_at_id": cur_id,
                    "message": f"Audit hash chain broken at record ID {cur_id}: genesis prev_hash mismatch.",
                }
            expected_prev = row_h
        else:
            if prev_h == expected_prev:
                # Direct linear continuation
                expected_prev = row_h
            elif prev_h in known_hashes:
                # Sibling branch off a verified preceding ancestor (concurrent write)
                parent_id = known_hashes[prev_h]
                branch_info = {
                    "record_id": cur_id,
                    "parent_record_id": parent_id,
                    "parent_hash": prev_h,
                    "created_at": row["created_at"],
                }
                branches.append(branch_info)
                if strict_linear:
                    return {
                        "status": "broken",
                        "reason_code": "BRANCH_DETECTED",
                        "verified_count": idx,
                        "total_count": len(rows),
                        "broken_at_id": cur_id,
                        "message": (
                            f"Audit hash chain broken at record ID {cur_id}: prev_hash mismatch "
                            f"(concurrent write branch detected off record {parent_id})."
                        ),
                    }
                expected_prev = row_h
            else:
                # Unknown ancestor - genuine break or missing record
                return {
                    "status": "broken",
                    "reason_code": "BROKEN_ANCESTOR_LINK",
                    "verified_count": idx,
                    "total_count": len(rows),
                    "broken_at_id": cur_id,
                    "message": f"Audit hash chain broken at record ID {cur_id}: prev_hash mismatch.",
                }

        known_hashes[row_h] = cur_id

    branch_msg = f" ({len(branches)} concurrent sibling branches verified)" if branches else ""
    return {
        "status": "intact",
        "verified_count": len(rows),
        "total_count": len(rows),
        "branches_count": len(branches),
        "branches": branches,
        "topology": "linear" if not branches else "dag",
        "message": f"Audit hash chain is cryptographically intact across all {len(rows)} events{branch_msg}.",
    }


def hash_api_key(api_key: str) -> str:
    """Computes SHA-256 hash of an API key for secure storage."""
    if not api_key:
        return ""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


DEFAULT_PURPOSES = [
    {
        "id": "Analytics",
        "name": "Analytics",
        "description": "Collects page view frequencies, navigation journeys, and feature performance metrics.",
        "allowed_fields": ["page_views", "feature_usage"],
        "mock_data": {
            "page_views": 1420,
            "feature_usage": {"dashboard": 58, "export": 12, "audit_view": 34},
        },
    },
    {
        "id": "Marketing",
        "name": "Marketing",
        "description": "Enables tailored product recommendations, periodic digests, and customized campaign offers.",
        "allowed_fields": ["email_preferences", "offers_enabled"],
        "mock_data": {
            "email_preferences": "weekly_digest",
            "offers_enabled": True,
            "preferred_category": "security_tools",
        },
    },
    {
        "id": "Service Improvement",
        "name": "Service Improvement",
        "description": "Helps improve application performance by analyzing crash reports, technical errors, and response times.",
        "allowed_fields": ["app_performance_ms", "recent_error_count"],
        "mock_data": {
            "app_performance_ms": 145,
            "recent_error_count": 0,
            "uptime_percent": 99.98,
        },
    },
]

DEFAULT_PARTNER_ALL_KEY = "key_partner_all_enterprise"
DEFAULT_PARTNER_LIMITED_KEY = "key_partner_limited_research"

PARTNER_ALL_KEY = os.environ.get("PARTNER_ALL_KEY", DEFAULT_PARTNER_ALL_KEY)
PARTNER_LIMITED_KEY = os.environ.get("PARTNER_LIMITED_KEY", DEFAULT_PARTNER_LIMITED_KEY)


def seed_purposes_and_consumers(connection):
    """Idempotently seeds baseline database-driven purposes and consumer partner credentials."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    # 1. Seed Purposes
    for p in DEFAULT_PURPOSES:
        try:
            existing = connection.execute(
                "SELECT id FROM purposes WHERE id = ?",
                (p["id"],),
            ).fetchone()
            if existing:
                connection.execute(
                    """
                    UPDATE purposes SET
                        name = ?,
                        description = ?,
                        allowed_fields = ?,
                        mock_data = ?
                    WHERE id = ?
                    """,
                    (
                        p["name"],
                        p["description"],
                        json.dumps(p["allowed_fields"]),
                        json.dumps(p["mock_data"]),
                        p["id"],
                    ),
                )
            else:
                connection.execute(
                    """
                    INSERT INTO purposes (id, name, description, allowed_fields, mock_data, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        p["id"],
                        p["name"],
                        p["description"],
                        json.dumps(p["allowed_fields"]),
                        json.dumps(p["mock_data"]),
                        now_str,
                    ),
                )
        except Exception:
            pass

    # 2. Seed Consumers
    consumers = [
        (
            "partner-all",
            "Partner All-Access Enterprise",
            hash_api_key(PARTNER_ALL_KEY),
            json.dumps(["Analytics", "Marketing", "Service Improvement"]),
            1,
            now_str,
        ),
        (
            "partner-limited",
            "Partner Limited Research",
            hash_api_key(PARTNER_LIMITED_KEY),
            json.dumps(["Analytics"]),
            1,
            now_str,
        ),
    ]

    for cid, name, key_h, allowed_purp, active, c_at in consumers:
        try:
            existing = connection.execute(
                "SELECT id FROM consumers WHERE consumer_id = ?",
                (cid,),
            ).fetchone()
            if existing:
                connection.execute(
                    """
                    UPDATE consumers SET
                        name = ?,
                        api_key_hash = ?,
                        allowed_purposes = ?,
                        is_active = ?
                    WHERE consumer_id = ?
                    """,
                    (name, key_h, allowed_purp, active, cid),
                )
            else:
                connection.execute(
                    """
                    INSERT INTO consumers (consumer_id, name, api_key_hash, allowed_purposes, is_active, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (cid, name, key_h, allowed_purp, active, c_at),
                )
        except Exception:
            pass


def get_active_notice_from_db():
    with get_connection() as connection:
        try:
            row = connection.execute(
                "SELECT version, text, hash FROM notice_versions WHERE is_active = 1 ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if row:
                return row["version"], row["text"], row["hash"]
        except Exception:
            pass

        row = connection.execute(
            "SELECT version, text, hash FROM notice_versions ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row:
            return row["version"], row["text"], row["hash"]
        return DEFAULT_NOTICE_VERSION, DEFAULT_NOTICE_TEXT, DEFAULT_NOTICE_HASH


def seed_demo_users(connection):
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    demo_password_hash = generate_password_hash("demo123")
    demo_accounts = [
        ("demo-user", "Demo User", "demo@consentguard.local", demo_password_hash, 1, 0),
        ("user1", "User 1 (Demo)", "user1@consentguard.local", demo_password_hash, 1, 0),
        ("user2", "User 2 (Demo)", "user2@consentguard.local", demo_password_hash, 1, 0),
        ("user3", "User 3 (Demo)", "user3@consentguard.local", demo_password_hash, 1, 0),
        ("user-regular", "Synthetic Regular User", "user@consentguard.local", generate_password_hash("UserPass123!"), 0, 0),
        ("admin-user", "Security Administrator", "admin@consentguard.local", generate_password_hash("AdminPass123!"), 0, 1),
    ]
    for uid, name, email, pw_hash, is_demo, is_admin in demo_accounts:
        try:
            connection.execute(
                """
                INSERT INTO users (id, name, email, password_hash, is_demo, is_admin, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (id) DO UPDATE SET
                    name = excluded.name,
                    email = excluded.email,
                    password_hash = excluded.password_hash,
                    is_demo = excluded.is_demo,
                    is_admin = excluded.is_admin
                """,
                (uid, name, email, pw_hash, is_demo, is_admin, now_str),
            )
        except Exception:
            try:
                connection.execute(
                    """
                    INSERT INTO users (id, name, email, password_hash, is_demo, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT (id) DO NOTHING
                    """,
                    (uid, name, email, pw_hash, is_demo, now_str),
                )
            except Exception:
                pass

    # Seed initial baseline consents for demo-user under DEFAULT_NOTICE_VERSION (v1.0)
    demo_consents = [
        ("demo-user", "Analytics", 1, DEFAULT_NOTICE_VERSION, DEFAULT_NOTICE_HASH, "grant"),
        ("demo-user", "Marketing", 1, DEFAULT_NOTICE_VERSION, DEFAULT_NOTICE_HASH, "grant"),
        ("demo-user", "Service Improvement", 1, DEFAULT_NOTICE_VERSION, DEFAULT_NOTICE_HASH, "grant"),
    ]
    for uid, purpose, granted, ver, h, action in demo_consents:
        connection.execute(
            """
            INSERT INTO consents (user_id, purpose, granted, notice_version, notice_hash, last_action, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (user_id, purpose) DO NOTHING
            """,
            (uid, purpose, granted, ver, h, action, now_str),
        )

    # Ensure baseline seeded consents also generate audit trail if none exists
    existing_seed_audit = connection.execute(
        "SELECT id FROM audit_events WHERE user_id = 'demo-user' AND source = 'system_seed' LIMIT 1"
    ).fetchone()
    if not existing_seed_audit:
        for uid, purpose, granted, ver, h, action in demo_consents:
            append_audit_event(
                connection,
                user_id=uid,
                purpose=purpose,
                action=action,
                http_status=200,
                reason_code="CONSENT_RECORDED",
                notice_version=ver,
                notice_hash=h,
                source="system_seed",
                details=f"Baseline system seed consent for {purpose}",
            )


def initialize_database():
    with get_connection() as connection:
        pg = is_postgres()
        id_primary = "id SERIAL PRIMARY KEY" if pg else "id INTEGER PRIMARY KEY AUTOINCREMENT"

        # 1. Users Table
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_demo INTEGER NOT NULL DEFAULT 0,
                is_admin INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """
        )

        if pg:
            try:
                connection.execute(
                    "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin INTEGER NOT NULL DEFAULT 0;"
                )
            except Exception:
                pass
        else:
            user_cols = [
                row["name"]
                for row in connection.execute("PRAGMA table_info(users)").fetchall()
            ]
            if "is_admin" not in user_cols:
                connection.execute(
                    "ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0"
                )

        # 2. Consents Table
        connection.execute(
            f"""
            CREATE TABLE IF NOT EXISTS consents (
                {id_primary},
                user_id TEXT NOT NULL,
                purpose TEXT NOT NULL,
                granted INTEGER NOT NULL CHECK (granted IN (0, 1)),
                notice_version TEXT NOT NULL,
                notice_hash TEXT NOT NULL DEFAULT '',
                last_action TEXT NOT NULL DEFAULT 'grant',
                updated_at TEXT NOT NULL,
                UNIQUE (user_id, purpose)
            )
            """
        )

        if not pg:
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

        # 3. Audit Events Table
        connection.execute(
            f"""
            CREATE TABLE IF NOT EXISTS audit_events (
                {id_primary},
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
                created_at TEXT NOT NULL
            )
            """
        )

        # Immutability triggers for audit_events (SQLite & PostgreSQL)
        if not pg:
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trg_prevent_audit_update
                BEFORE UPDATE ON audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'Audit events are cryptographically immutable: UPDATE is blocked.');
                END;
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trg_prevent_audit_delete
                BEFORE DELETE ON audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'Audit events are cryptographically immutable: DELETE is blocked.');
                END;
                """
            )
        else:
            try:
                connection.execute(
                    """
                    CREATE OR REPLACE RULE no_update_audit AS ON UPDATE TO audit_events DO INSTEAD NOTHING;
                    """
                )
                connection.execute(
                    """
                    CREATE OR REPLACE RULE no_delete_audit AS ON DELETE TO audit_events DO INSTEAD NOTHING;
                    """
                )
            except Exception:
                pass

        # 4. Notice Versions Table
        connection.execute(
            f"""
            CREATE TABLE IF NOT EXISTS notice_versions (
                {id_primary},
                version TEXT UNIQUE NOT NULL,
                text TEXT NOT NULL,
                hash TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
            """
        )

        if pg:
            try:
                connection.execute(
                    "ALTER TABLE notice_versions ADD COLUMN IF NOT EXISTS is_active INTEGER NOT NULL DEFAULT 1;"
                )
            except Exception:
                pass
        else:
            notice_cols = [
                row["name"]
                for row in connection.execute("PRAGMA table_info(notice_versions)").fetchall()
            ]
            if "is_active" not in notice_cols:
                connection.execute(
                    "ALTER TABLE notice_versions ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1"
                )

        # 5. Purposes Table (Database-driven configuration)
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS purposes (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL,
                allowed_fields TEXT NOT NULL,
                mock_data TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )

        if pg:
            try:
                connection.execute(
                    "ALTER TABLE purposes ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT '';"
                )
            except Exception:
                pass
        else:
            purp_cols = [
                row["name"]
                for row in connection.execute("PRAGMA table_info(purposes)").fetchall()
            ]
            if "name" not in purp_cols:
                connection.execute(
                    "ALTER TABLE purposes ADD COLUMN name TEXT NOT NULL DEFAULT ''"
                )

        # 6. Consumers Table (Database-driven downstream API clients)
        connection.execute(
            f"""
            CREATE TABLE IF NOT EXISTS consumers (
                {id_primary},
                consumer_id TEXT NOT NULL DEFAULT '',
                name TEXT NOT NULL,
                api_key_hash TEXT NOT NULL,
                allowed_purposes TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
            """
        )

        if pg:
            try:
                connection.execute(
                    "ALTER TABLE consumers ADD COLUMN IF NOT EXISTS consumer_id TEXT NOT NULL DEFAULT '';"
                )
            except Exception:
                pass
        else:
            cons_cols = [
                row["name"]
                for row in connection.execute("PRAGMA table_info(consumers)").fetchall()
            ]
            if "consumer_id" not in cons_cols:
                connection.execute(
                    "ALTER TABLE consumers ADD COLUMN consumer_id TEXT NOT NULL DEFAULT ''"
                )

        # Seed initial notice version if not present
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        try:
            connection.execute(
                """
                INSERT INTO notice_versions (version, text, hash, is_active, created_at)
                VALUES (?, ?, ?, 1, ?)
                ON CONFLICT (version) DO NOTHING
                """,
                (DEFAULT_NOTICE_VERSION, DEFAULT_NOTICE_TEXT, DEFAULT_NOTICE_HASH, now_str),
            )
        except Exception:
            try:
                connection.execute(
                    """
                    INSERT INTO notice_versions (version, text, hash, created_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT (version) DO NOTHING
                    """,
                    (DEFAULT_NOTICE_VERSION, DEFAULT_NOTICE_TEXT, DEFAULT_NOTICE_HASH, now_str),
                )
            except Exception:
                pass

        # Seed purposes and consumers
        seed_purposes_and_consumers(connection)

        # Seed initial demo accounts
        seed_demo_users(connection)

        # Useful indexes
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_user_action ON audit_events(user_id, action)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_consents_user ON consents(user_id)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_consumers_key_hash ON consumers(api_key_hash)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_action_created ON audit_events(action, created_at)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_user_created ON audit_events(user_id, created_at)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_notice_version_active ON notice_versions(is_active, version)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_consents_user_purpose ON consents(user_id, purpose)"
        )


def get_consent_history(connection, user_id=None, limit=100):
    """
    Retrieves chronological consent lifecycle events (grant, withdraw, deny, re-consent)
    with cryptographic audit verification metadata.
    """
    consent_actions = (
        "grant",
        "withdraw",
        "deny",
        "consent_rejected_stale",
        "CONSENT_RECORDED",
        "CONSENT_GRANTED",
        "CONSENT_WITHDRAWN",
        "CONSENT_DENIED",
    )
    placeholders = ",".join(["?"] * len(consent_actions))
    query = f"SELECT * FROM audit_events WHERE (action IN ({placeholders}) OR reason_code IN ({placeholders}))"
    params = list(consent_actions) + list(consent_actions)
    if user_id:
        query += " AND user_id = ?"
        params.append(str(user_id))
    query += " ORDER BY id DESC"
    if limit and int(limit) > 0:
        query += f" LIMIT {int(limit)}"
    rows = connection.execute(query, tuple(params)).fetchall()
    return [dict(r) for r in rows]


def get_data_access_request_logs(connection, user_id=None, limit=100):
    """
    Retrieves data access request evaluation events (allowed and denied, internal and downstream share)
    from the immutable audit trail.
    """
    access_actions = (
        "data_access_allowed",
        "data_access_denied",
        "data_share_allowed",
        "data_share_denied",
    )
    placeholders = ",".join(["?"] * len(access_actions))
    query = f"SELECT * FROM audit_events WHERE action IN ({placeholders})"
    params = list(access_actions)
    if user_id:
        query += " AND user_id = ?"
        params.append(str(user_id))
    query += " ORDER BY id DESC"
    if limit and int(limit) > 0:
        query += f" LIMIT {int(limit)}"
    rows = connection.execute(query, tuple(params)).fetchall()
    return [dict(r) for r in rows]


def compute_dashboard_stats(connection, user_id=None):
    """
    Computes exact real-time aggregate metrics directly from database tables:
    - active_consents: granted=1 and matching active notice version/hash.
    - withdrawn_consents: granted=0 (withdrawn or denied).
    - reconsent_required: granted=1 but notice version or hash is outdated.
    - allowed_requests: data_access_allowed + data_share_allowed.
    - blocked_requests: data_access_denied + data_share_denied.
    - total_requests: allowed + blocked.
    - total_audit_events: total audit events in database.
    """
    active_ver, _, active_h = get_active_notice_from_db()

    # Consents statistics
    if user_id:
        consent_rows = connection.execute(
            "SELECT purpose, granted, notice_version, notice_hash, last_action FROM consents WHERE user_id = ?",
            (str(user_id),),
        ).fetchall()
    else:
        consent_rows = connection.execute(
            "SELECT purpose, granted, notice_version, notice_hash, last_action FROM consents"
        ).fetchall()

    active_consents = 0
    withdrawn_consents = 0
    reconsent_required = 0

    for r in consent_rows:
        g = r["granted"]
        nv = r["notice_version"]
        nh = r["notice_hash"] or ""
        if g == 1:
            if nv == active_ver and (not nh or not active_h or nh == active_h):
                active_consents += 1
            else:
                reconsent_required += 1
        else:
            withdrawn_consents += 1

    # Access request counts
    if user_id:
        allowed_row = connection.execute(
            """
            SELECT COUNT(*) as c FROM audit_events
            WHERE user_id = ? AND action IN ('data_access_allowed', 'data_share_allowed')
            """,
            (str(user_id),),
        ).fetchone()
        blocked_row = connection.execute(
            """
            SELECT COUNT(*) as c FROM audit_events
            WHERE user_id = ? AND action IN ('data_access_denied', 'data_share_denied')
            """,
            (str(user_id),),
        ).fetchone()
        total_audit_row = connection.execute(
            "SELECT COUNT(*) as c FROM audit_events WHERE user_id = ?",
            (str(user_id),),
        ).fetchone()
    else:
        allowed_row = connection.execute(
            """
            SELECT COUNT(*) as c FROM audit_events
            WHERE action IN ('data_access_allowed', 'data_share_allowed')
            """
        ).fetchone()
        blocked_row = connection.execute(
            """
            SELECT COUNT(*) as c FROM audit_events
            WHERE action IN ('data_access_denied', 'data_share_denied')
            """
        ).fetchone()
        total_audit_row = connection.execute(
            "SELECT COUNT(*) as c FROM audit_events"
        ).fetchone()

    allowed_requests = int(allowed_row["c"]) if allowed_row and allowed_row["c"] is not None else 0
    blocked_requests = int(blocked_row["c"]) if blocked_row and blocked_row["c"] is not None else 0
    total_audit_events = int(total_audit_row["c"]) if total_audit_row and total_audit_row["c"] is not None else 0

    return {
        "active_consents": active_consents,
        "withdrawn_consents": withdrawn_consents,
        "reconsent_required": reconsent_required,
        "allowed_requests": allowed_requests,
        "blocked_requests": blocked_requests,
        "total_requests": allowed_requests + blocked_requests,
        "total_audit_events": total_audit_events,
        "active_notice_version": active_ver,
        "active_notice_hash": active_h,
    }


if __name__ == "__main__":
    initialize_database()
    print(f"Database initialized: {DATABASE_PATH}")
