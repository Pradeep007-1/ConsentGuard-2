import hashlib
import os
import sqlite3
import ssl
import urllib.parse
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from werkzeug.security import generate_password_hash

DATABASE_PATH = Path(__file__).parent / "consentguard.db"


def get_database_url():
    """Returns database URL from environment variables, supporting Neon, Vercel Postgres, Supabase."""
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


_cached_pg_raw_conn = None


def get_raw_pg_connection():
    global _cached_pg_raw_conn
    target_url = get_database_url()

    if _cached_pg_raw_conn is not None:
        try:
            cur = _cached_pg_raw_conn.cursor()
            cur.execute("SELECT 1")
            cur.close()
            return _cached_pg_raw_conn
        except Exception:
            try:
                _cached_pg_raw_conn.close()
            except Exception:
                pass
            _cached_pg_raw_conn = None

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

    raw_conn = pg8000.dbapi.connect(
        user=user,
        password=password,
        host=host,
        port=port,
        database=database_name,
        ssl_context=ssl_ctx,
        timeout=10,
    )
    _cached_pg_raw_conn = raw_conn
    return raw_conn


@contextmanager
def get_connection():
    global _cached_pg_raw_conn
    target_url = get_database_url()
    if target_url.startswith("postgres://") or target_url.startswith("postgresql://"):
        raw_conn = get_raw_pg_connection()
        wrapper = PostgresConnectionWrapper(raw_conn)
        try:
            yield wrapper
            wrapper.commit()
        except Exception:
            if _cached_pg_raw_conn is not None:
                try:
                    _cached_pg_raw_conn.rollback()
                except Exception:
                    try:
                        _cached_pg_raw_conn.close()
                    except Exception:
                        pass
                    _cached_pg_raw_conn = None
            raise
    else:
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


def verify_audit_chain(connection, user_id=None):
    if user_id:
        rows = connection.execute(
            "SELECT * FROM audit_events WHERE user_id = ? ORDER BY id ASC",
            (user_id,),
        ).fetchall()
    else:
        rows = connection.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()

    expected_prev = GENESIS_PREV_HASH
    for idx, row in enumerate(rows):
        # When checking global chain
        if not user_id and row["prev_hash"] != expected_prev:
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


def seed_demo_users(connection):
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    demo_password_hash = generate_password_hash("demo123")
    demo_accounts = [
        ("demo-user", "Demo User", "demo@consentguard.local", demo_password_hash, 1),
        ("user1", "User 1 (Demo)", "user1@consentguard.local", demo_password_hash, 1),
        ("user2", "User 2 (Demo)", "user2@consentguard.local", demo_password_hash, 1),
        ("user3", "User 3 (Demo)", "user3@consentguard.local", demo_password_hash, 1),
    ]
    for uid, name, email, pw_hash, is_demo in demo_accounts:
        connection.execute(
            """
            INSERT INTO users (id, name, email, password_hash, is_demo, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (id) DO NOTHING
            """,
            (uid, name, email, pw_hash, is_demo, now_str),
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
                created_at TEXT NOT NULL
            )
            """
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

        # 4. Notice Versions Table
        connection.execute(
            f"""
            CREATE TABLE IF NOT EXISTS notice_versions (
                {id_primary},
                version TEXT UNIQUE NOT NULL,
                text TEXT NOT NULL,
                hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )

        # Seed initial notice version if not present
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        connection.execute(
            """
            INSERT INTO notice_versions (version, text, hash, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT (version) DO NOTHING
            """,
            (DEFAULT_NOTICE_VERSION, DEFAULT_NOTICE_TEXT, DEFAULT_NOTICE_HASH, now_str),
        )

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


if __name__ == "__main__":
    initialize_database()
    print(f"Database initialized: {DATABASE_PATH}")
