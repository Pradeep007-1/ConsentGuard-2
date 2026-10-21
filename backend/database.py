
import sqlite3
from pathlib import Path

DATABASE_PATH = Path(__file__).parent / "consentguard.db"



from contextlib import contextmanager


@contextmanager
def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS consents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                purpose TEXT NOT NULL,
                granted INTEGER NOT NULL CHECK (granted IN (0, 1)),
                notice_version TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT (
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                ),
                UNIQUE (user_id, purpose)
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                purpose TEXT NOT NULL,
                action TEXT NOT NULL,
                notice_version TEXT NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL DEFAULT (
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                )
            )
        """)


if __name__ == "__main__":
    initialize_database()
    print(f"Database initialized: {DATABASE_PATH}")
