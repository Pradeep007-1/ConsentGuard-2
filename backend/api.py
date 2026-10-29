import csv
import hashlib
import io
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_file, session
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

from database import (
    DEFAULT_NOTICE_HASH,
    DEFAULT_NOTICE_TEXT,
    DEFAULT_NOTICE_VERSION,
    append_audit_event,
    get_active_notice_from_db,
    get_connection,
    initialize_database,
    verify_audit_chain,
)

ROOT_DIR = Path(__file__).resolve().parent.parent

app = Flask(__name__)
# Configure secret key for session management
app.secret_key = os.environ.get(
    "SECRET_KEY", "consentguard-production-secret-key-change-in-production"
)

# Secure cookie configuration
is_production = bool(os.environ.get("VERCEL") or os.environ.get("PRODUCTION"))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="None" if is_production else "Lax",
    SESSION_COOKIE_SECURE=is_production,
    PERMANENT_SESSION_LIFETIME=86400 * 7,  # 7 days persistent session
)

CORS(app, supports_credentials=True)


@app.after_request
def add_security_and_cors_headers(response):
    origin = request.headers.get("Origin")
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Test-Source"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PUT, DELETE"
    return response


@app.route("/api/<path:subpath>", methods=["OPTIONS"])
@app.route("/<path:subpath>", methods=["OPTIONS"])
def handle_options(subpath):
    response = Response("", status=204)
    origin = request.headers.get("Origin")
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Test-Source"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PUT, DELETE"
    return response

PURPOSES = {"Analytics", "Marketing", "Service Improvement", "Third-Party Sharing"}

NOTICE_VERSION = DEFAULT_NOTICE_VERSION
NOTICE_TEXT = DEFAULT_NOTICE_TEXT
NOTICE_HASH = DEFAULT_NOTICE_HASH


def load_active_notice():
    global NOTICE_VERSION, NOTICE_TEXT, NOTICE_HASH
    try:
        ver, text, h = get_active_notice_from_db()
        NOTICE_VERSION, NOTICE_TEXT, NOTICE_HASH = ver, text, h
    except Exception:
        pass
    return NOTICE_VERSION, NOTICE_TEXT, NOTICE_HASH


MOCK_DATA = {
    "Analytics": {"page_views": 12, "feature_usage": ["dashboard", "search"]},
    "Marketing": {"email_preferences": "weekly_updates", "offers_enabled": True},
    "Service Improvement": {
        "app_performance_ms": 184,
        "recent_error_count": 0,
    },
    "Third-Party Sharing": {
        "partner_service": "SecurePartner",
        "shared_fields": ["user_id", "preferences"],
    },
}


# ============================================================================
# Authentication & User Isolation Helpers
# ============================================================================
def get_authenticated_user(existing_conn=None):
    """Returns the verified user dict from the Authorization header or server-side session."""
    user_id = None
    auth_header = request.headers.get("Authorization", "").strip()
    if auth_header.startswith("Bearer "):
        token_candidate = auth_header[7:].strip()
        if token_candidate and token_candidate.lower() not in ("null", "undefined", "none", ""):
            user_id = token_candidate

    def _query(conn):
        nonlocal user_id
        if user_id:
            row = conn.execute(
                "SELECT id, name, email, is_demo, created_at FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
            if row:
                return dict(row)

        session_uid = session.get("user_id")
        if session_uid and session_uid != user_id:
            row = conn.execute(
                "SELECT id, name, email, is_demo, created_at FROM users WHERE id = ?",
                (session_uid,),
            ).fetchone()
            if row:
                return dict(row)
        return None

    try:
        if existing_conn is not None:
            return _query(existing_conn)
        with get_connection() as connection:
            return _query(connection)
    except Exception:
        return None


def is_registered_user(user_id):
    """
    Checks whether a user_id corresponds to an existing registered or demo account.
    """
    if not user_id or str(user_id).lower() in ("null", "undefined", "none", ""):
        return False
    try:
        with get_connection() as connection:
            row = connection.execute(
                "SELECT id FROM users WHERE id = ?",
                (str(user_id),),
            ).fetchone()
            return bool(row)
    except Exception:
        return False


def resolve_subject(req_user=None, source="user"):
    """
    Derives the subject user_id with server-side validation.
    Returns (user_id, error_response).
    """
    auth_user = get_authenticated_user()
    is_test_source = bool(
        source == "test"
        or request.args.get("source") == "test"
        or request.headers.get("X-Test-Source") == "test"
    )
    is_testing_env = bool(app.config.get("TESTING") or is_test_source)

    # Normalize client-side empty/null string representations
    if req_user in ("null", "undefined", "None", ""):
        req_user = None

    # 1. If user is authenticated via server session or verified bearer token:
    if auth_user:
        auth_id = auth_user["id"]

        # Case A: Explicit test invocation (e.g. from in-browser diagnostic runner)
        if is_test_source:
            if req_user and req_user != auth_id:
                # Security boundary: If req_user is another registered real user,
                # block tampering with real user accounts even if source='test' is claimed.
                if is_registered_user(req_user):
                    return None, (
                        jsonify({
                            "error": "Forbidden: Cannot access or modify data for another user.",
                            "reason_code": "FORBIDDEN_CROSS_USER_ACCESS",
                        }),
                        403,
                    )
                # Legitimate synthetic test identity (e.g. suite-user-*, test-user, etc.)
                return req_user, None
            return req_user or auth_id, None

        # Case B: Normal application request from authenticated user:
        if req_user and req_user != auth_id:
            return None, (
                jsonify({
                    "error": "Forbidden: Cannot access or modify data for another user.",
                    "reason_code": "FORBIDDEN_CROSS_USER_ACCESS",
                }),
                403,
            )
        return auth_id, None

    # 2. If running within automated test suite or diagnostic tests without auth session:
    if is_testing_env:
        effective = req_user or "test-user"
        return effective, None

    # 3. Unauthenticated visitor attempting normal access:
    return None, (
        jsonify({
            "error": "Authentication required. Please sign in or register.",
            "reason_code": "UNAUTHENTICATED",
        }),
        401,
    )


# ============================================================================
# Static Files & Health
# ============================================================================
@app.get("/")
def home():
    return send_file(ROOT_DIR / "index.html")


@app.get("/dashboard")
def dashboard():
    return send_file(ROOT_DIR / "index.html")


@app.get("/dashboard.html")
def dashboard_html():
    return send_file(ROOT_DIR / "index.html")


@app.get("/privacy-illustration.png")
def illustration():
    return send_file(ROOT_DIR / "privacy-illustration.png")


@app.get("/api/health")
def health():
    try:
        from database import is_postgres
        with get_connection() as connection:
            connection.execute("SELECT 1").fetchone()
        db_type = "postgresql" if is_postgres() else "sqlite"
        is_persistent = is_postgres() or not is_production
        resp_data = {
            "status": "ok",
            "service": "ConsentGuard API",
            "database": "connected",
            "database_type": db_type,
            "is_persistent": is_persistent,
        }
        if not is_persistent and is_production:
            resp_data["storage_warning"] = (
                "Running on ephemeral SQLite (/tmp) in production. Data will not persist across serverless instances. "
                "Configure DATABASE_URL with a persistent PostgreSQL instance (e.g. Neon.tech)."
            )
        return jsonify(resp_data), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "service": "ConsentGuard API",
            "error": str(e),
        }), 503


# ============================================================================
# Authentication API (Signup, Login, Demo Login, Logout, Me)
# ============================================================================
@app.post("/api/auth/signup")
def signup():
    load_active_notice()
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if not name or len(name) < 2:
        return jsonify({
            "error": "Please provide a valid full name (at least 2 characters).",
            "reason_code": "INVALID_NAME",
        }), 400

    email_regex = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    if not re.match(email_regex, email):
        return jsonify({
            "error": "Please provide a valid email address.",
            "reason_code": "INVALID_EMAIL",
        }), 400

    if not password or len(password) < 6:
        return jsonify({
            "error": "Password must be at least 6 characters long.",
            "reason_code": "WEAK_PASSWORD",
        }), 400

    with get_connection() as connection:
        # Check if email is already registered
        existing = connection.execute(
            "SELECT id FROM users WHERE LOWER(email) = LOWER(?)",
            (email,),
        ).fetchone()
        if existing:
            return jsonify({
                "error": "An account with this email address already exists. Please log in.",
                "reason_code": "EMAIL_ALREADY_EXISTS",
            }), 409

        user_id = f"user_{uuid.uuid4().hex[:12]}"
        password_hash = generate_password_hash(password)
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        connection.execute(
            """
            INSERT INTO users (id, name, email, password_hash, is_demo, created_at)
            VALUES (?, ?, ?, ?, 0, ?)
            """,
            (user_id, name, email, password_hash, now_str),
        )

        append_audit_event(
            connection=connection,
            user_id=user_id,
            purpose="Authentication",
            action="user_registered",
            http_status=201,
            reason_code="REGISTRATION_SUCCESS",
            notice_version=NOTICE_VERSION,
            notice_hash=NOTICE_HASH,
            source="auth",
            details=f"New user registered: {name} <{email}>.",
        )

    # Establish session
    session.permanent = True
    session["user_id"] = user_id
    session["user_name"] = name
    session["user_email"] = email
    session["is_demo"] = False

    return jsonify({
        "success": True,
        "message": "Account created successfully.",
        "token": user_id,
        "user": {
            "id": user_id,
            "name": name,
            "email": email,
            "is_demo": False,
        },
    }), 201


@app.post("/api/auth/login")
def login():
    load_active_notice()
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if not email or not password:
        return jsonify({
            "error": "Email and password are required.",
            "reason_code": "MISSING_CREDENTIALS",
        }), 400

    with get_connection() as connection:
        user_row = connection.execute(
            "SELECT id, name, email, password_hash, is_demo FROM users WHERE LOWER(email) = LOWER(?)",
            (email,),
        ).fetchone()

        if not user_row or not check_password_hash(user_row["password_hash"], password):
            return jsonify({
                "error": "Invalid email or password.",
                "reason_code": "INVALID_CREDENTIALS",
            }), 401

        user = dict(user_row)
        append_audit_event(
            connection=connection,
            user_id=user["id"],
            purpose="Authentication",
            action="user_login",
            http_status=200,
            reason_code="LOGIN_SUCCESS",
            notice_version=NOTICE_VERSION,
            notice_hash=NOTICE_HASH,
            source="auth",
            details=f"User signed in: {user['name']} <{user['email']}>.",
        )

    session.permanent = True
    session["user_id"] = user["id"]
    session["user_name"] = user["name"]
    session["user_email"] = user["email"]
    session["is_demo"] = bool(user["is_demo"])

    return jsonify({
        "success": True,
        "message": "Logged in successfully.",
        "token": user["id"],
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "is_demo": bool(user["is_demo"]),
        },
    }), 200


@app.post("/api/auth/demo-login")
def demo_login():
    load_active_notice()
    data = request.get_json(silent=True) or {}
    demo_id = str(data.get("user_id", "demo-user")).strip()

    valid_demos = {"demo-user", "user1", "user2", "user3"}
    if demo_id not in valid_demos:
        return jsonify({
            "error": f"Invalid demo account. Allowed demo accounts: {sorted(valid_demos)}",
            "reason_code": "INVALID_DEMO_ACCOUNT",
        }), 400

    with get_connection() as connection:
        user_row = connection.execute(
            "SELECT id, name, email, is_demo FROM users WHERE id = ?",
            (demo_id,),
        ).fetchone()

        if not user_row:
            return jsonify({
                "error": "Demo account not found in database.",
                "reason_code": "DEMO_ACCOUNT_NOT_FOUND",
            }), 404

        user = dict(user_row)
        append_audit_event(
            connection=connection,
            user_id=user["id"],
            purpose="Authentication",
            action="demo_login",
            http_status=200,
            reason_code="DEMO_LOGIN_SUCCESS",
            notice_version=NOTICE_VERSION,
            notice_hash=NOTICE_HASH,
            source="demo",
            details=f"Switched to demo subject: {user['id']}.",
        )

    session.permanent = True
    session["user_id"] = user["id"]
    session["user_name"] = user["name"]
    session["user_email"] = user["email"]
    session["is_demo"] = True

    return jsonify({
        "success": True,
        "message": f"Logged into demo account {user['name']}.",
        "token": user["id"],
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "is_demo": True,
        },
    }), 200


@app.post("/api/auth/logout")
def logout():
    auth_user = get_authenticated_user()
    if auth_user:
        with get_connection() as connection:
            append_audit_event(
                connection=connection,
                user_id=auth_user["id"],
                purpose="Authentication",
                action="user_logout",
                http_status=200,
                reason_code="LOGOUT_SUCCESS",
                notice_version=NOTICE_VERSION,
                notice_hash=NOTICE_HASH,
                source="auth",
                details=f"User signed out: {auth_user['name']}.",
            )
    session.clear()
    return jsonify({
        "success": True,
        "message": "Logged out successfully.",
    }), 200


@app.get("/api/auth/me")
def get_current_session():
    auth_user = get_authenticated_user()
    if auth_user:
        return jsonify({
            "authenticated": True,
            "user": {
                "id": auth_user["id"],
                "name": auth_user["name"],
                "email": auth_user["email"],
                "is_demo": bool(auth_user["is_demo"]),
            },
        })
    return jsonify({
        "authenticated": False,
        "user": None,
    })


# ============================================================================
# Privacy Notice Management
# ============================================================================
@app.get("/api/notice")
def get_notice():
    load_active_notice()
    return jsonify({
        "notice_version": NOTICE_VERSION,
        "notice_text": NOTICE_TEXT,
        "notice_hash": NOTICE_HASH,
    })


@app.get("/api/notices")
def get_notices():
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT id, version, text, hash, created_at FROM notice_versions ORDER BY id ASC"
        ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.post("/api/notice/update")
def update_notice():
    global NOTICE_VERSION, NOTICE_TEXT, NOTICE_HASH
    data = request.get_json(silent=True) or {}
    new_version = str(data.get("notice_version", "2.0")).strip()
    new_text = str(
        data.get(
            "notice_text",
            (
                f"ConsentGuard v{new_version} Privacy Notice: Revised itemized purpose inventory. "
                "Enhanced telemetry boundaries and mandatory re-consent verification for downstream consumers."
            ),
        )
    ).strip()
    source = data.get("source", "user")

    NOTICE_VERSION = new_version
    NOTICE_TEXT = new_text
    NOTICE_HASH = hashlib.sha256(NOTICE_TEXT.encode("utf-8")).hexdigest()

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO notice_versions (version, text, hash, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(version) DO UPDATE SET
                text = excluded.text,
                hash = excluded.hash,
                created_at = excluded.created_at
            """,
            (NOTICE_VERSION, NOTICE_TEXT, NOTICE_HASH, now_str),
        )

        append_audit_event(
            connection=connection,
            user_id="system",
            purpose="Notice Administration",
            action="notice_version_changed",
            http_status=200,
            reason_code="NOTICE_UPDATED",
            notice_version=NOTICE_VERSION,
            notice_hash=NOTICE_HASH,
            source=source,
            details=f"Privacy notice upgraded to v{NOTICE_VERSION}.",
        )

    return jsonify({
        "notice_version": NOTICE_VERSION,
        "notice_text": NOTICE_TEXT,
        "notice_hash": NOTICE_HASH,
        "message": f"Privacy notice updated to v{NOTICE_VERSION}",
    })


@app.post("/api/notice/reset")
def reset_notice():
    global NOTICE_VERSION, NOTICE_TEXT, NOTICE_HASH
    data = request.get_json(silent=True) or {}
    source = data.get("source", "user")

    NOTICE_VERSION = DEFAULT_NOTICE_VERSION
    NOTICE_TEXT = DEFAULT_NOTICE_TEXT
    NOTICE_HASH = DEFAULT_NOTICE_HASH

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    with get_connection() as connection:
        connection.execute(
            "DELETE FROM notice_versions WHERE version != ?",
            (DEFAULT_NOTICE_VERSION,),
        )
        connection.execute(
            """
            INSERT INTO notice_versions (version, text, hash, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT (version) DO NOTHING
            """,
            (DEFAULT_NOTICE_VERSION, DEFAULT_NOTICE_TEXT, DEFAULT_NOTICE_HASH, now_str),
        )
        append_audit_event(
            connection=connection,
            user_id="system",
            purpose="Notice Administration",
            action="notice_version_reset",
            http_status=200,
            reason_code="NOTICE_RESET",
            notice_version=NOTICE_VERSION,
            notice_hash=NOTICE_HASH,
            source=source,
            details=f"Privacy notice reset to default v{NOTICE_VERSION}.",
        )

    return jsonify({
        "notice_version": NOTICE_VERSION,
        "notice_text": NOTICE_TEXT,
        "notice_hash": NOTICE_HASH,
        "message": "Privacy notice reset to default version 1.0",
    })


# ============================================================================
# Consent Management & Data Access (PEP)
# ============================================================================
@app.get("/api/consents")
def get_consents():
    source = request.args.get("source", "user")
    req_user = request.args.get("user_id")
    user_id, err = resolve_subject(req_user=req_user, source=source)
    if err:
        return err

    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM consents WHERE user_id = ? ORDER BY purpose",
            (user_id,),
        ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.post("/api/consents")
def record_consent():
    load_active_notice()
    data = request.get_json(silent=True) or {}
    source = data.get("source", "user")
    req_user = data.get("user_id")
    purpose = data.get("purpose")
    action = data.get("action")

    # 1. Parameter Validation FIRST
    if purpose not in PURPOSES:
        return jsonify({
            "error": "Invalid purpose",
            "reason_code": "INVALID_PURPOSE",
            "valid_purposes": sorted(PURPOSES),
        }), 400

    if action not in {"grant", "withdraw", "deny"}:
        return jsonify({
            "error": "Invalid action. Allowed actions: grant, withdraw, deny",
            "reason_code": "INVALID_ACTION",
        }), 400

    # 2. Authorization & Ownership Validation SECOND
    user_id, err = resolve_subject(req_user=req_user, source=source)
    if err:
        return err

    granted = 1 if action == "grant" else 0
    if action == "grant":
        reason_code = "CONSENT_GRANTED"
    elif action == "withdraw":
        reason_code = "CONSENT_WITHDRAWN"
    else:
        reason_code = "CONSENT_DENIED"

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO consents
                (user_id, purpose, granted, notice_version, notice_hash, last_action, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, purpose) DO UPDATE SET
                granted = excluded.granted,
                notice_version = excluded.notice_version,
                notice_hash = excluded.notice_hash,
                last_action = excluded.last_action,
                updated_at = excluded.updated_at
            """,
            (user_id, purpose, granted, NOTICE_VERSION, NOTICE_HASH, action, now_str),
        )

        append_audit_event(
            connection=connection,
            user_id=user_id,
            purpose=purpose,
            action=action,
            http_status=201,
            reason_code=reason_code,
            notice_version=NOTICE_VERSION,
            notice_hash=NOTICE_HASH,
            source=source,
            details=f"Consent decision '{action}' recorded for {purpose}.",
        )

    return jsonify({
        "user_id": user_id,
        "purpose": purpose,
        "action": action,
        "granted": bool(granted),
        "notice_version": NOTICE_VERSION,
        "notice_hash": NOTICE_HASH,
        "reason_code": reason_code,
        "source": source,
    }), 201


@app.post("/api/data-access")
def data_access():
    load_active_notice()
    data = request.get_json(silent=True) or {}
    source = data.get("source", "user")
    req_user = data.get("user_id")
    purpose = data.get("purpose")

    # 1. Parameter Validation FIRST
    if purpose not in PURPOSES:
        reason_code = "INVALID_PURPOSE"
        http_status = 400
        reason = "Invalid purpose"
        auth_user = get_authenticated_user()
        audit_uid = req_user or (auth_user["id"] if auth_user else "unknown")
        try:
            with get_connection() as connection:
                append_audit_event(
                    connection=connection,
                    user_id=str(audit_uid),
                    purpose=str(purpose),
                    action="data_access_denied",
                    http_status=http_status,
                    reason_code=reason_code,
                    notice_version=NOTICE_VERSION,
                    notice_hash=NOTICE_HASH,
                    source=source,
                    details="Request rejected: unrecognized data processing purpose.",
                )
        except Exception:
            pass
        return jsonify({
            "allowed": False,
            "http_status": 400,
            "reason_code": reason_code,
            "reason": reason,
            "error": "Invalid purpose",
            "valid_purposes": sorted(PURPOSES),
        }), 400

    # 2. Authorization & Ownership Validation SECOND
    user_id, err = resolve_subject(req_user=req_user, source=source)
    if err:
        return err

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT granted, notice_version, notice_hash, last_action FROM consents
            WHERE user_id = ? AND purpose = ?
            """,
            (user_id, purpose),
        ).fetchone()

        if row is None:
            allowed = False
            http_status = 403
            reason_code = "NO_CONSENT"
            reason = "No consent decision on record. Explicit opt-in required."
        elif row["granted"] != 1:
            allowed = False
            http_status = 403
            if row["last_action"] == "deny":
                reason_code = "DENIED"
                reason = "Consent was explicitly denied by user."
            else:
                reason_code = "WITHDRAWN"
                reason = "Consent is currently withdrawn or revoked."
        elif row["notice_version"] != NOTICE_VERSION or (
            row["notice_hash"] and NOTICE_HASH and row["notice_hash"] != NOTICE_HASH
        ):
            allowed = False
            http_status = 403
            reason_code = "NOTICE_MISMATCH"
            reason = (
                f"Consent was granted under notice v{row['notice_version']}. "
                f"Active notice is now v{NOTICE_VERSION}. A notice change requires fresh consent (NOTICE_OUTDATED_RECONSENT_REQUIRED)."
            )
        else:
            allowed = True
            http_status = 200
            reason_code = "ACTIVE_CONSENT"
            reason = f"Active valid consent verified under Notice v{NOTICE_VERSION}."

        append_audit_event(
            connection=connection,
            user_id=user_id,
            purpose=purpose,
            action="data_access_allowed" if allowed else "data_access_denied",
            http_status=http_status,
            reason_code=reason_code,
            notice_version=NOTICE_VERSION,
            notice_hash=NOTICE_HASH,
            source=source,
            details=f"Downstream PEP policy evaluation: {reason}",
        )

    if not allowed:
        return jsonify({
            "allowed": False,
            "http_status": http_status,
            "reason_code": reason_code,
            "reason": reason,
            "error_code": "NOTICE_OUTDATED_RECONSENT_REQUIRED"
            if reason_code == "NOTICE_MISMATCH"
            else reason_code,
            "message": "Request denied: current active consent is required.",
            "user_id": user_id,
            "purpose": purpose,
            "user_notice_version": row["notice_version"] if row else None,
            "active_notice_version": NOTICE_VERSION,
            "notice_version": NOTICE_VERSION,
            "notice_hash": NOTICE_HASH,
        }), http_status

    return jsonify({
        "allowed": True,
        "http_status": 200,
        "reason_code": reason_code,
        "reason": reason,
        "message": "Mock data access permitted.",
        "user_id": user_id,
        "purpose": purpose,
        "notice_version": NOTICE_VERSION,
        "notice_hash": NOTICE_HASH,
        "data": MOCK_DATA[purpose],
    }), 200


# ============================================================================
# Audit Log & Verification
# ============================================================================
@app.get("/api/audit")
def get_audit():
    source = request.args.get("source", "")
    req_user = request.args.get("user_id")
    if req_user in ("null", "undefined", "None", ""):
        req_user = None

    auth_user = get_authenticated_user()
    is_test_source = bool(
        source == "test"
        or request.args.get("source") == "test"
        or request.headers.get("X-Test-Source") == "test"
    )
    is_test_mode = bool(app.config.get("TESTING") or is_test_source)

    if not auth_user and not is_test_mode:
        return jsonify({
            "error": "Authentication required. Please sign in.",
            "reason_code": "UNAUTHENTICATED",
        }), 401

    hide_test = request.args.get("hide_test", "false").lower() in ("true", "1")
    limit = request.args.get("limit")

    query = "SELECT * FROM audit_events WHERE 1=1"
    params = []

    # Enforce user boundary
    if auth_user:
        auth_id = auth_user["id"]
        # If test mode and req_user is a synthetic test subject:
        if is_test_mode and req_user and req_user != auth_id:
            if is_registered_user(req_user):
                return jsonify({
                    "error": "Forbidden: Cannot view audit logs for another user.",
                    "reason_code": "FORBIDDEN_CROSS_USER_ACCESS",
                }), 403
            query += " AND user_id = ?"
            params.append(req_user)
        elif req_user and req_user != auth_id and req_user.lower() != "all":
            return jsonify({
                "error": "Forbidden: Cannot view audit logs for another user.",
                "reason_code": "FORBIDDEN_CROSS_USER_ACCESS",
            }), 403
        else:
            query += " AND user_id = ?"
            params.append(auth_id)
    elif req_user and req_user.lower() != "all":
        query += " AND user_id = ?"
        params.append(req_user)

    if hide_test:
        query += " AND source != 'test'"
    elif source:
        query += " AND source = ?"
        params.append(source)

    query += " ORDER BY id DESC"

    if limit and limit.isdigit():
        query += f" LIMIT {int(limit)}"

    with get_connection() as connection:
        rows = connection.execute(query, tuple(params)).fetchall()

    return jsonify([dict(row) for row in rows])


@app.get("/api/audit/verify")
def verify_audit():
    source = request.args.get("source", "")
    auth_user = get_authenticated_user()
    is_test_mode = bool(app.config.get("TESTING") or source == "test")

    with get_connection() as connection:
        # If user is authenticated, verify full ledger
        result = verify_audit_chain(connection)
    status_code = 200 if result["status"] == "intact" else 409
    return jsonify(result), status_code


@app.get("/api/audit/export")
def export_audit():
    auth_user = get_authenticated_user()
    is_test_mode = bool(app.config.get("TESTING") or request.args.get("source") == "test")

    if not auth_user and not is_test_mode:
        return jsonify({
            "error": "Authentication required to export audit log.",
            "reason_code": "UNAUTHENTICATED",
        }), 401

    export_format = request.args.get("format", "csv").lower()

    query = "SELECT * FROM audit_events"
    params = []
    if auth_user:
        query += " WHERE user_id = ?"
        params.append(auth_user["id"])
    query += " ORDER BY id ASC"

    with get_connection() as connection:
        rows = connection.execute(query, tuple(params)).fetchall()

    row_dicts = [dict(row) for row in rows]

    if export_format == "json":
        json_output = json.dumps(row_dicts, indent=2)
        return Response(
            json_output,
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=audit.json"},
        )

    # CSV export
    output = io.StringIO()
    fieldnames = [
        "id",
        "user_id",
        "purpose",
        "action",
        "http_status",
        "reason_code",
        "notice_version",
        "notice_hash",
        "short_notice_hash",
        "source",
        "prev_hash",
        "row_hash",
        "details",
        "created_at",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for item in row_dicts:
        writer.writerow(item)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit.csv"},
    )


@app.post("/api/audit/reset")
@app.post("/api/demo/reset")
def reset_demo():
    global NOTICE_VERSION, NOTICE_TEXT, NOTICE_HASH
    NOTICE_VERSION = DEFAULT_NOTICE_VERSION
    NOTICE_TEXT = DEFAULT_NOTICE_TEXT
    NOTICE_HASH = DEFAULT_NOTICE_HASH

    auth_user = get_authenticated_user()
    data = request.get_json(silent=True) or {}
    source = data.get("source", "user")

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    with get_connection() as connection:
        # If authenticated as a specific user, only reset that user's consents and audits
        if auth_user:
            connection.execute("DELETE FROM consents WHERE user_id = ?", (auth_user["id"],))
            connection.execute("DELETE FROM audit_events WHERE user_id = ?", (auth_user["id"],))
            target_user = auth_user["id"]
        else:
            target_user = "demo-user"
            connection.execute("DELETE FROM consents WHERE user_id = 'demo-user'")

        append_audit_event(
            connection=connection,
            user_id=target_user,
            purpose="System Administration",
            action="demo_reset",
            http_status=200,
            reason_code="SYSTEM_RESET",
            notice_version=NOTICE_VERSION,
            notice_hash=NOTICE_HASH,
            source=source,
            details=f"User {target_user} consent and audit records reset to default state.",
        )

    return jsonify({
        "message": "Data reset successfully",
        "notice_version": NOTICE_VERSION,
        "notice_hash": NOTICE_HASH,
    })


if __name__ == "__main__":
    initialize_database()
    load_active_notice()
    app.run(host="0.0.0.0", port=5001, debug=False, threaded=True)
