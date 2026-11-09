import csv
import hashlib
import hmac
import io
import json
import os
import re
import time
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
    hash_api_key,
    initialize_database,
    verify_audit_chain,
)

ROOT_DIR = Path(__file__).resolve().parent.parent

app = Flask(__name__)
# Configure secret key for session management
app.secret_key = os.environ.get(
    "SECRET_KEY", "consentguard-production-secret-key-change-in-production"
)

# Administrative secret key for secure infrastructure operations
ADMIN_KEY = os.environ.get("ADMIN_KEY", "cg_admin_secret_key_hackathon")

# Secure cookie configuration
is_production = bool(os.environ.get("VERCEL") or os.environ.get("PRODUCTION"))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="None" if is_production else "Lax",
    SESSION_COOKIE_SECURE=is_production,
    PERMANENT_SESSION_LIFETIME=86400 * 7,  # 7 days persistent session
)

CORS(app, supports_credentials=True)

ALLOWED_CORS_HEADERS = (
    "Content-Type, Authorization, X-Test-Source, X-Admin-Key, X-API-Key, X-Notice-Version"
)


@app.after_request
def add_security_and_cors_headers(response):
    origin = request.headers.get("Origin")
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = ALLOWED_CORS_HEADERS
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
        response.headers["Access-Control-Allow-Headers"] = ALLOWED_CORS_HEADERS
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PUT, DELETE"
    return response


# ============================================================================
# Uniform Leak-Proof Error Handlers (400, 401, 403, 404, 405, 409, 500)
# ============================================================================
@app.errorhandler(400)
def handle_bad_request(e):
    return jsonify({
        "error": "Bad Request",
        "message": getattr(e, "description", "The client sent a request that could not be understood."),
        "reason_code": "BAD_REQUEST",
    }), 400


@app.errorhandler(401)
def handle_unauthorized(e):
    return jsonify({
        "error": "Unauthorized",
        "message": getattr(e, "description", "Authentication required to access this resource."),
        "reason_code": "UNAUTHORIZED",
    }), 401


@app.errorhandler(403)
def handle_forbidden(e):
    return jsonify({
        "error": "Forbidden",
        "message": getattr(e, "description", "You do not have permission to access this resource."),
        "reason_code": "FORBIDDEN",
    }), 403


@app.errorhandler(404)
def handle_not_found(e):
    return jsonify({
        "error": "Not Found",
        "message": getattr(e, "description", "The requested endpoint or resource was not found."),
        "reason_code": "NOT_FOUND",
    }), 404


@app.errorhandler(405)
def handle_method_not_allowed(e):
    return jsonify({
        "error": "Method Not Allowed",
        "message": getattr(e, "description", "The HTTP method is not allowed for the requested URL."),
        "reason_code": "METHOD_NOT_ALLOWED",
    }), 405


@app.errorhandler(409)
def handle_conflict(e):
    return jsonify({
        "error": "Conflict",
        "message": getattr(e, "description", "Conflict with current resource state."),
        "reason_code": "CONFLICT",
    }), 409


@app.errorhandler(500)
def handle_server_error(e):
    app.logger.error(f"Internal server error: {e}")
    return jsonify({
        "error": "Internal Server Error",
        "message": "An internal server error occurred. Access denied by fail-closed policy.",
        "reason_code": "INTERNAL_SERVER_ERROR",
    }), 500


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


def get_purpose_config(purpose: str, connection=None):
    """
    Queries database-driven purpose configuration dynamically.
    Enables new purposes to be registered in the database without modifying backend code.
    Falls back to static defaults if purpose exists in legacy fallback set.
    """
    def _query(conn):
        row = conn.execute(
            "SELECT id, description, allowed_fields, mock_data FROM purposes WHERE id = ?",
            (purpose,),
        ).fetchone()
        if row:
            try:
                allowed_fields = json.loads(row["allowed_fields"])
            except Exception:
                allowed_fields = []
            try:
                mock_data = json.loads(row["mock_data"])
            except Exception:
                mock_data = {}
            return {
                "id": row["id"],
                "description": row["description"],
                "allowed_fields": allowed_fields,
                "mock_data": mock_data,
            }
        if purpose in PURPOSES:
            fields = list(MOCK_DATA.get(purpose, {}).keys())
            return {
                "id": purpose,
                "description": f"Static purpose {purpose}",
                "allowed_fields": fields,
                "mock_data": MOCK_DATA.get(purpose, {}),
            }
        return None

    if connection is not None:
        return _query(connection)
    try:
        with get_connection() as conn:
            return _query(conn)
    except Exception:
        return None


def check_admin_auth():
    """
    Constant-time administrative authorization.
    1. If X-Admin-Key is provided, verifies using constant-time comparison.
    2. Allows logged-in authenticated users to preserve dashboard controls.
    3. Allows automated test runners (TESTING config or X-Test-Source).
    """
    current_admin_key = os.environ.get("ADMIN_KEY", ADMIN_KEY)
    admin_header = request.headers.get("X-Admin-Key", "").strip()
    if admin_header:
        if hmac.compare_digest(admin_header.encode("utf-8"), current_admin_key.encode("utf-8")):
            return True, None
        return False, (
            jsonify({
                "error": "Forbidden: Invalid Admin Key.",
                "reason_code": "INVALID_ADMIN_KEY",
            }),
            403,
        )

    # Allow authenticated users (dashboard session or Bearer token)
    auth_user = get_authenticated_user()
    if auth_user:
        return True, None

    # Allow automated test environment
    is_test_mode = bool(
        app.config.get("TESTING")
        or request.headers.get("X-Test-Source") == "test"
        or request.args.get("source") == "test"
    )
    if is_test_mode:
        return True, None

    return False, (
        jsonify({
            "error": "Admin authorization or active session required.",
            "reason_code": "ADMIN_AUTH_REQUIRED",
        }),
        401,
    )


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

    if existing_conn is not None:
        try:
            return _query(existing_conn)
        except Exception:
            return None

    for attempt in range(2):
        try:
            with get_connection() as connection:
                return _query(connection)
        except Exception:
            if attempt == 0:
                time.sleep(0.3)
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
        if demo_id == "demo-user":
            now_str_demo = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            for p in ["Analytics", "Marketing", "Service Improvement"]:
                connection.execute(
                    """
                    INSERT INTO consents (user_id, purpose, granted, notice_version, notice_hash, last_action, updated_at)
                    VALUES (?, ?, 1, ?, ?, 'grant', ?)
                    ON CONFLICT (user_id, purpose) DO NOTHING
                    """,
                    ("demo-user", p, DEFAULT_NOTICE_VERSION, DEFAULT_NOTICE_HASH, now_str_demo),
                )
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
# Centralized Policy Enforcement Point (PEP)
# ============================================================================
def evaluate_policy_and_consent(
    connection,
    user_id: str,
    purpose: str,
    consumer: dict = None,
    requested_fields: list = None,
    source: str = "pep",
) -> dict:
    """
    Centralized Policy Enforcement Point (PEP) for ConsentGuard.
    Reused across /api/share/request and /api/data-access.

    Order of evaluation:
    1. Consumer authorization (if consumer provided) -> 403
    2. Purpose validity -> 400
    3. User existence -> 404
    4. Active consent verification -> 403 (NO_CONSENT, WITHDRAWN, DENIED, NOTICE_MISMATCH)
    5. Field authorization (if requested_fields provided) -> 403
    6. Permitted data release -> 200 ALLOW

    Fail closed: Any unexpected exception returns DENY with 403/500.
    """
    try:
        load_active_notice()
        now_ver = NOTICE_VERSION
        now_hash = NOTICE_HASH

        # 1. Purpose Validity Check (Database-driven)
        purpose_cfg = get_purpose_config(purpose, connection=connection)
        if not purpose_cfg:
            reason = f"Invalid purpose '{purpose}'."
            action_name = "data_share_denied" if consumer else "data_access_denied"
            append_audit_event(
                connection=connection,
                user_id=user_id or "unknown",
                purpose=str(purpose),
                action=action_name,
                http_status=400,
                reason_code="INVALID_PURPOSE",
                notice_version=now_ver,
                notice_hash=now_hash,
                source=source,
                details=f"PEP validation rejected: {reason}",
            )
            return {
                "allowed": False,
                "http_status": 400,
                "reason_code": "INVALID_PURPOSE",
                "reason": reason,
                "error": reason,
                "valid_purposes": sorted(PURPOSES),
            }

        # 2. Consumer Purpose Authorization Check
        if consumer:
            allowed_purposes = consumer.get("allowed_purposes") or []
            if isinstance(allowed_purposes, str):
                try:
                    allowed_purposes = json.loads(allowed_purposes)
                except Exception:
                    allowed_purposes = []
            if purpose not in allowed_purposes:
                reason = f"Consumer '{consumer.get('consumer_id')}' is not authorized for purpose '{purpose}'."
                append_audit_event(
                    connection=connection,
                    user_id=user_id or "unknown",
                    purpose=purpose,
                    action="data_share_denied",
                    http_status=403,
                    reason_code="CONSUMER_NOT_AUTHORIZED",
                    notice_version=now_ver,
                    notice_hash=now_hash,
                    source=source,
                    details=f"PEP authorization rejected: {reason}",
                )
                return {
                    "allowed": False,
                    "http_status": 403,
                    "reason_code": "CONSUMER_NOT_AUTHORIZED",
                    "reason": reason,
                    "error": reason,
                }

        # 3. User Existence Check
        user_row = connection.execute(
            "SELECT id FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()

        if consumer and not user_row:
            reason = f"User '{user_id}' not found."
            append_audit_event(
                connection=connection,
                user_id=str(user_id or "unknown"),
                purpose=purpose,
                action="data_share_denied",
                http_status=404,
                reason_code="USER_NOT_FOUND",
                notice_version=now_ver,
                notice_hash=now_hash,
                source=source,
                details=f"PEP request rejected: {reason}",
            )
            return {
                "allowed": False,
                "http_status": 404,
                "reason_code": "USER_NOT_FOUND",
                "reason": reason,
                "error": reason,
            }

        # 4. Consent Decision on Record
        consent_row = connection.execute(
            """
            SELECT granted, notice_version, notice_hash, last_action FROM consents
            WHERE user_id = ? AND purpose = ?
            """,
            (user_id, purpose),
        ).fetchone()

        action_name = "data_share_denied" if consumer else "data_access_denied"

        if consent_row is None:
            reason = "No consent decision on record. Explicit opt-in required."
            append_audit_event(
                connection=connection,
                user_id=user_id,
                purpose=purpose,
                action=action_name,
                http_status=403,
                reason_code="NO_CONSENT",
                notice_version=now_ver,
                notice_hash=now_hash,
                source=source,
                details=f"PEP evaluation: {reason}",
            )
            return {
                "allowed": False,
                "http_status": 403,
                "reason_code": "NO_CONSENT",
                "reason": reason,
                "error": reason,
                "message": "Request denied: current active consent is required.",
                "user_id": user_id,
                "purpose": purpose,
                "notice_version": now_ver,
            }

        if consent_row["granted"] != 1:
            if consent_row["last_action"] == "deny":
                rc = "DENIED"
                reason = "Consent was explicitly denied by user."
            else:
                rc = "WITHDRAWN"
                reason = "Consent is currently withdrawn or revoked."
            append_audit_event(
                connection=connection,
                user_id=user_id,
                purpose=purpose,
                action=action_name,
                http_status=403,
                reason_code=rc,
                notice_version=now_ver,
                notice_hash=now_hash,
                source=source,
                details=f"PEP evaluation: {reason}",
            )
            return {
                "allowed": False,
                "http_status": 403,
                "reason_code": rc,
                "reason": reason,
                "error": reason,
                "message": "Request denied: current active consent is required.",
                "user_id": user_id,
                "purpose": purpose,
                "notice_version": now_ver,
            }

        # Check Notice Version & Hash
        if consent_row["notice_version"] != now_ver or (
            consent_row["notice_hash"] and now_hash and consent_row["notice_hash"] != now_hash
        ):
            reason = (
                f"Consent was granted under notice v{consent_row['notice_version']}. "
                f"Active notice is now v{now_ver}. A notice change requires fresh consent (NOTICE_OUTDATED_RECONSENT_REQUIRED)."
            )
            append_audit_event(
                connection=connection,
                user_id=user_id,
                purpose=purpose,
                action=action_name,
                http_status=403,
                reason_code="NOTICE_MISMATCH",
                notice_version=now_ver,
                notice_hash=now_hash,
                source=source,
                details=f"PEP evaluation: {reason}",
            )
            return {
                "allowed": False,
                "http_status": 403,
                "reason_code": "NOTICE_MISMATCH",
                "reason": reason,
                "error": reason,
                "error_code": "NOTICE_OUTDATED_RECONSENT_REQUIRED",
                "message": "Request denied: current active consent is required.",
                "user_id": user_id,
                "purpose": purpose,
                "user_notice_version": consent_row["notice_version"],
                "active_notice_version": now_ver,
                "notice_version": now_ver,
                "notice_hash": now_hash,
            }

        # 5. Field Authorization Check
        allowed_fields = purpose_cfg.get("allowed_fields") or []
        mock_data = purpose_cfg.get("mock_data") or {}

        if requested_fields:
            unauthorized = [f for f in requested_fields if f not in allowed_fields]
            if unauthorized:
                reason = f"Requested fields not permitted for purpose '{purpose}': {unauthorized}"
                append_audit_event(
                    connection=connection,
                    user_id=user_id,
                    purpose=purpose,
                    action=action_name,
                    http_status=403,
                    reason_code="UNAUTHORIZED_FIELDS",
                    notice_version=now_ver,
                    notice_hash=now_hash,
                    source=source,
                    details=f"PEP evaluation: {reason}",
                )
                return {
                    "allowed": False,
                    "http_status": 403,
                    "reason_code": "UNAUTHORIZED_FIELDS",
                    "reason": reason,
                    "error": reason,
                    "allowed_fields": allowed_fields,
                    "unauthorized_fields": unauthorized,
                }
            released_data = {k: v for k, v in mock_data.items() if k in requested_fields}
        else:
            released_data = {k: v for k, v in mock_data.items() if k in allowed_fields}

        # 6. Permitted Access
        reason = f"Active valid consent verified under Notice v{now_ver}."
        allowed_action_name = "data_share_allowed" if consumer else "data_access_allowed"
        append_audit_event(
            connection=connection,
            user_id=user_id,
            purpose=purpose,
            action=allowed_action_name,
            http_status=200,
            reason_code="ACTIVE_CONSENT",
            notice_version=now_ver,
            notice_hash=now_hash,
            source=source,
            details=f"Downstream PEP policy evaluation: {reason}",
        )

        return {
            "allowed": True,
            "http_status": 200,
            "reason_code": "ACTIVE_CONSENT",
            "reason": reason,
            "message": "Mock data access permitted.",
            "user_id": user_id,
            "purpose": purpose,
            "notice_version": now_ver,
            "notice_hash": now_hash,
            "data": released_data,
            "allowed_fields": allowed_fields,
        }

    except Exception as e:
        # FAIL CLOSED: Any unexpected error must result in DENY
        app.logger.error(f"PEP evaluation exception: {e}")
        try:
            append_audit_event(
                connection=connection,
                user_id=user_id or "system",
                purpose=purpose or "Unknown",
                action="data_access_denied",
                http_status=500,
                reason_code="PEP_INTERNAL_ERROR",
                notice_version=NOTICE_VERSION,
                notice_hash=NOTICE_HASH,
                source=source,
                details=f"Fail-closed on internal PEP exception: {str(e)}",
            )
        except Exception:
            pass
        return {
            "allowed": False,
            "http_status": 500,
            "reason_code": "PEP_INTERNAL_ERROR",
            "reason": "Internal PEP evaluation error. Access denied by fail-closed policy.",
            "error": "Access denied by fail-closed policy.",
        }


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
            "SELECT id, version, text, hash, is_active, created_at FROM notice_versions ORDER BY id ASC"
        ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.post("/api/notice/update")
def update_notice():
    global NOTICE_VERSION, NOTICE_TEXT, NOTICE_HASH

    # Constant-time admin authorization / active user session
    is_auth, err_resp = check_admin_auth()
    if not is_auth:
        return err_resp

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

    new_hash = hashlib.sha256(new_text.encode("utf-8")).hexdigest()
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    with get_connection() as connection:
        existing = connection.execute(
            "SELECT version, text, hash FROM notice_versions WHERE version = ?",
            (new_version,),
        ).fetchone()

        if existing and existing["hash"] != new_hash:
            return jsonify({
                "error": f"Conflict: Notice version '{new_version}' already exists with different text/hash.",
                "reason_code": "VERSION_EXISTS",
                "existing_hash": existing["hash"],
                "requested_hash": new_hash,
            }), 409

        # Atomic notice activation
        connection.execute("UPDATE notice_versions SET is_active = 0")
        connection.execute(
            """
            INSERT INTO notice_versions (version, text, hash, is_active, created_at)
            VALUES (?, ?, ?, 1, ?)
            ON CONFLICT(version) DO UPDATE SET
                text = excluded.text,
                hash = excluded.hash,
                is_active = 1,
                created_at = excluded.created_at
            """,
            (new_version, new_text, new_hash, now_str),
        )

        NOTICE_VERSION = new_version
        NOTICE_TEXT = new_text
        NOTICE_HASH = new_hash

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

    is_auth, err_resp = check_admin_auth()
    if not is_auth:
        return err_resp

    data = request.get_json(silent=True) or {}
    source = data.get("source", "user")

    NOTICE_VERSION = DEFAULT_NOTICE_VERSION
    NOTICE_TEXT = DEFAULT_NOTICE_TEXT
    NOTICE_HASH = DEFAULT_NOTICE_HASH

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    with get_connection() as connection:
        # Atomic reset preserving historical notice records
        connection.execute("UPDATE notice_versions SET is_active = 0")
        connection.execute(
            """
            INSERT INTO notice_versions (version, text, hash, is_active, created_at)
            VALUES (?, ?, ?, 1, ?)
            ON CONFLICT (version) DO UPDATE SET is_active = 1
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

    active_ver, _, active_h = load_active_notice()

    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM consents WHERE user_id = ? ORDER BY purpose",
            (user_id,),
        ).fetchall()

    results = []
    for row in rows:
        r = dict(row)
        r["active_notice_version"] = active_ver
        r["active_notice_hash"] = active_h
        r["needs_reconsent"] = bool(
            r["granted"] == 1
            and (
                r["notice_version"] != active_ver
                or (r.get("notice_hash") and active_h and r["notice_hash"] != active_h)
            )
        )
        results.append(r)

    return jsonify(results)


@app.post("/api/consents")
def record_consent():
    load_active_notice()
    data = request.get_json(silent=True) or {}
    source = data.get("source", "user")
    req_user = data.get("user_id")
    purpose = data.get("purpose")
    action = data.get("action")
    req_notice_version = data.get("notice_version")
    req_notice_hash = data.get("notice_hash")

    # 1. Parameter Validation FIRST
    purpose_cfg = get_purpose_config(purpose)
    if not purpose_cfg and purpose not in PURPOSES:
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

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    with get_connection() as connection:
        existing_row = connection.execute(
            "SELECT granted, notice_version, notice_hash, last_action FROM consents WHERE user_id = ? AND purpose = ?",
            (user_id, purpose),
        ).fetchone()

        # Idempotent withdrawal
        if action == "withdraw" and existing_row and existing_row["granted"] == 0 and existing_row["last_action"] == "withdraw":
            return jsonify({
                "user_id": user_id,
                "purpose": purpose,
                "action": "withdraw",
                "granted": False,
                "notice_version": existing_row["notice_version"],
                "notice_hash": existing_row["notice_hash"],
                "reason_code": "CONSENT_ALREADY_WITHDRAWN",
                "message": "Consent is already withdrawn (idempotent).",
                "source": source,
            }), 200

        # Outdated notice check on grant
        if action == "grant":
            if (req_notice_hash and req_notice_hash != NOTICE_HASH) or (
                req_notice_version and req_notice_version != NOTICE_VERSION
            ):
                append_audit_event(
                    connection=connection,
                    user_id=user_id,
                    purpose=purpose,
                    action="consent_rejected_stale",
                    http_status=409,
                    reason_code="STALE_NOTICE",
                    notice_version=req_notice_version or NOTICE_VERSION,
                    notice_hash=req_notice_hash or NOTICE_HASH,
                    source=source,
                    details=f"Grant rejected: Client attempted consent with outdated notice hash {req_notice_hash[:12] if req_notice_hash else ''}.",
                )
                return jsonify({
                    "error": "Conflict: Consent grant rejected because notice is stale.",
                    "reason_code": "STALE_NOTICE",
                    "active_notice_version": NOTICE_VERSION,
                    "active_notice_hash": NOTICE_HASH,
                    "provided_notice_version": req_notice_version,
                    "provided_notice_hash": req_notice_hash,
                }), 409

        granted = 1 if action == "grant" else 0
        if action == "grant":
            reason_code = "CONSENT_GRANTED"
        elif action == "withdraw":
            reason_code = "CONSENT_WITHDRAWN"
        else:
            reason_code = "CONSENT_DENIED"

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
    purpose_cfg = get_purpose_config(purpose)
    if not purpose_cfg and purpose not in PURPOSES:
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
        decision = evaluate_policy_and_consent(
            connection=connection,
            user_id=user_id,
            purpose=purpose,
            consumer=None,
            requested_fields=None,
            source=source,
        )

    return jsonify(decision), decision["http_status"]


# ============================================================================
# Downstream Purpose-Based Authorization Endpoint (POST /api/share/request)
# ============================================================================
@app.post("/api/share/request")
def share_request():
    """
    Downstream consumer data sharing endpoint.
    Validation sequence:
    1. Invalid/missing API key -> 401
    2. Consumer not authorized for purpose -> 403
    3. Invalid purpose -> 400
    4. Unknown user -> 404
    5. Missing, withdrawn, or stale consent -> 403
    6. Unauthorized fields -> 403
    7. Valid request -> 200 ALLOW with permitted fields
    """
    load_active_notice()
    data = request.get_json(silent=True) or {}
    api_key = (
        request.headers.get("X-API-Key", "").strip()
        or str(data.get("api_key", "")).strip()
        or str(data.get("consumer_key", "")).strip()
    )
    user_id = str(data.get("user_id", "")).strip()
    purpose = str(data.get("purpose", "")).strip()
    requested_fields = data.get("requested_fields")
    if requested_fields is not None and not isinstance(requested_fields, list):
        requested_fields = [str(requested_fields)]

    source = data.get("source") or request.headers.get("X-Test-Source") or "partner_api"

    # Step 1: Validate Consumer API Key
    if not api_key:
        return jsonify({
            "allowed": False,
            "http_status": 401,
            "reason_code": "INVALID_API_KEY",
            "error": "Unauthorized: Consumer API key is missing or invalid.",
        }), 401

    key_hash = hash_api_key(api_key)

    with get_connection() as connection:
        consumer_row = connection.execute(
            "SELECT id, consumer_id, name, api_key_hash, allowed_purposes, is_active FROM consumers WHERE api_key_hash = ? AND is_active = 1",
            (key_hash,),
        ).fetchone()

        if not consumer_row:
            append_audit_event(
                connection=connection,
                user_id=user_id or "unknown",
                purpose=purpose or "Unknown",
                action="data_share_denied",
                http_status=401,
                reason_code="INVALID_API_KEY",
                notice_version=NOTICE_VERSION,
                notice_hash=NOTICE_HASH,
                source=source,
                details="Downstream request rejected: invalid or inactive API key.",
            )
            return jsonify({
                "allowed": False,
                "http_status": 401,
                "reason_code": "INVALID_API_KEY",
                "error": "Unauthorized: Consumer API key is invalid or inactive.",
            }), 401

        consumer = dict(consumer_row)

        decision = evaluate_policy_and_consent(
            connection=connection,
            user_id=user_id,
            purpose=purpose,
            consumer=consumer,
            requested_fields=requested_fields,
            source=source,
        )

    decision["consumer_id"] = consumer["consumer_id"]
    return jsonify(decision), decision["http_status"]


@app.get("/api/consumers")
def list_consumers():
    """Lists registered downstream consumer profiles without exposing API key hashes."""
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT id, consumer_id, name, allowed_purposes, is_active, created_at FROM consumers ORDER BY id ASC"
        ).fetchall()
    results = []
    for r in rows:
        d = dict(r)
        try:
            d["allowed_purposes"] = json.loads(d["allowed_purposes"])
        except Exception:
            pass
        results.append(d)
    return jsonify(results)


@app.get("/api/purposes")
def list_purposes():
    """Lists database-driven purpose configurations."""
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT id, description, allowed_fields, mock_data, created_at FROM purposes ORDER BY id ASC"
        ).fetchall()
    results = []
    for r in rows:
        d = dict(r)
        try:
            d["allowed_fields"] = json.loads(d["allowed_fields"])
        except Exception:
            pass
        try:
            d["mock_data"] = json.loads(d["mock_data"])
        except Exception:
            pass
        results.append(d)
    return jsonify(results)


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
    strict = request.args.get("strict", "false").lower() == "true"
    auth_user = get_authenticated_user()
    is_test_mode = bool(app.config.get("TESTING") or source == "test")

    with get_connection() as connection:
        result = verify_audit_chain(connection, strict_linear=strict)
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

    is_auth, err_resp = check_admin_auth()
    if not is_auth:
        return err_resp

    NOTICE_VERSION = DEFAULT_NOTICE_VERSION
    NOTICE_TEXT = DEFAULT_NOTICE_TEXT
    NOTICE_HASH = DEFAULT_NOTICE_HASH

    auth_user = get_authenticated_user()
    data = request.get_json(silent=True) or {}
    source = data.get("source", "user")

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    with get_connection() as connection:
        # Reset consents without destroying immutable audit history
        if auth_user:
            connection.execute("DELETE FROM consents WHERE user_id = ?", (auth_user["id"],))
            target_user = auth_user["id"]
        else:
            target_user = "demo-user"
            connection.execute("DELETE FROM consents WHERE user_id = 'demo-user'")
            for p in ["Analytics", "Marketing", "Service Improvement"]:
                connection.execute(
                    """
                    INSERT INTO consents (user_id, purpose, granted, notice_version, notice_hash, last_action, updated_at)
                    VALUES (?, ?, 1, ?, ?, 'grant', ?)
                    """,
                    ("demo-user", p, DEFAULT_NOTICE_VERSION, DEFAULT_NOTICE_HASH, now_str),
                )

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
            details=f"User {target_user} consent state reset to defaults. Audit history preserved.",
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
