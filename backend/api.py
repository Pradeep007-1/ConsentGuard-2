import csv
import hashlib
import io
import json
import os
from pathlib import Path
from flask import Flask, Response, jsonify, request, send_file
from flask_cors import CORS

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
CORS(app)

PURPOSES = {"Analytics", "Marketing", "Service Improvement", "Third-Party Sharing"}

NOTICE_VERSION = DEFAULT_NOTICE_VERSION
NOTICE_TEXT = DEFAULT_NOTICE_TEXT
NOTICE_HASH = DEFAULT_NOTICE_HASH


def load_active_notice():
    global NOTICE_VERSION, NOTICE_TEXT, NOTICE_HASH
    NOTICE_VERSION, NOTICE_TEXT, NOTICE_HASH = get_active_notice_from_db()


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
        with get_connection() as connection:
            connection.execute("SELECT 1").fetchone()
        return jsonify({"status": "ok", "service": "ConsentGuard API", "database": "connected"})
    except Exception as e:
        return jsonify({"status": "error", "service": "ConsentGuard API", "error": str(e)}), 503


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


@app.get("/api/consents")
def get_consents():
    user_id = request.args.get("user_id", "demo-user")
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
    user_id = str(data.get("user_id", "demo-user")).strip()
    purpose = data.get("purpose")
    action = data.get("action")
    source = data.get("source", "user")

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

    granted = 1 if action == "grant" else 0
    if action == "grant":
        reason_code = "CONSENT_GRANTED"
    elif action == "withdraw":
        reason_code = "CONSENT_WITHDRAWN"
    else:
        reason_code = "CONSENT_DENIED"

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO consents
                (user_id, purpose, granted, notice_version, last_action, updated_at)
            VALUES (?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            ON CONFLICT(user_id, purpose) DO UPDATE SET
                granted = excluded.granted,
                notice_version = excluded.notice_version,
                last_action = excluded.last_action,
                updated_at = excluded.updated_at
            """,
            (user_id, purpose, granted, NOTICE_VERSION, action),
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
    user_id = str(data.get("user_id", "demo-user")).strip()
    purpose = data.get("purpose")
    source = data.get("source", "user")

    if purpose not in PURPOSES:
        reason_code = "INVALID_PURPOSE"
        http_status = 400
        allowed = False
        reason = "Invalid purpose"
        with get_connection() as connection:
            append_audit_event(
                connection=connection,
                user_id=user_id,
                purpose=str(purpose),
                action="data_access_denied",
                http_status=http_status,
                reason_code=reason_code,
                notice_version=NOTICE_VERSION,
                notice_hash=NOTICE_HASH,
                source=source,
                details="Request rejected: unrecognized data processing purpose.",
            )
        return jsonify({
            "allowed": False,
            "http_status": 400,
            "reason_code": reason_code,
            "reason": reason,
            "error": "Invalid purpose",
            "valid_purposes": sorted(PURPOSES),
        }), 400

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT granted, notice_version, last_action FROM consents
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
        elif row["notice_version"] != NOTICE_VERSION:
            allowed = False
            http_status = 403
            reason_code = "NOTICE_MISMATCH"
            reason = (
                f"Consent was granted under notice v{row['notice_version']}. "
                f"Active notice is now v{NOTICE_VERSION}. A notice change requires fresh consent."
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


@app.post("/api/notice/update")
def update_notice():
    global NOTICE_VERSION, NOTICE_TEXT, NOTICE_HASH
    data = request.get_json(silent=True) or {}
    new_version = str(data.get("notice_version", "2.0")).strip()
    new_text = str(data.get("notice_text", (
        f"ConsentGuard v{new_version} Privacy Notice: Revised itemized purpose inventory. "
        "Enhanced telemetry boundaries and mandatory re-consent verification for downstream consumers."
    ))).strip()
    source = data.get("source", "user")

    NOTICE_VERSION = new_version
    NOTICE_TEXT = new_text
    NOTICE_HASH = hashlib.sha256(NOTICE_TEXT.encode("utf-8")).hexdigest()

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO notice_versions (version, text, hash, created_at)
            VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            ON CONFLICT(version) DO UPDATE SET
                text = excluded.text,
                hash = excluded.hash,
                created_at = excluded.created_at
            """,
            (NOTICE_VERSION, NOTICE_TEXT, NOTICE_HASH),
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

    with get_connection() as connection:
        connection.execute(
            "DELETE FROM notice_versions WHERE version != ?",
            (DEFAULT_NOTICE_VERSION,),
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO notice_versions (version, text, hash, created_at)
            VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            """,
            (DEFAULT_NOTICE_VERSION, DEFAULT_NOTICE_TEXT, DEFAULT_NOTICE_HASH),
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


@app.get("/api/audit")
def get_audit():
    user_id = request.args.get("user_id")
    hide_test = request.args.get("hide_test", "false").lower() in ("true", "1")
    source = request.args.get("source")
    limit = request.args.get("limit")

    query = "SELECT * FROM audit_events WHERE 1=1"
    params = []

    if user_id and user_id.lower() != "all":
        query += " AND user_id = ?"
        params.append(user_id)

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
    with get_connection() as connection:
        result = verify_audit_chain(connection)
    status_code = 200 if result["status"] == "intact" else 409
    return jsonify(result), status_code


@app.get("/api/audit/export")
def export_audit():
    export_format = request.args.get("format", "csv").lower()

    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM audit_events ORDER BY id ASC"
        ).fetchall()

    row_dicts = [dict(row) for row in rows]

    if export_format == "json":
        json_output = json.dumps(row_dicts, indent=2)
        return Response(
            json_output,
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=audit.json"},
        )

    # Default CSV export
    output = io.StringIO()
    if row_dicts:
        fieldnames = list(row_dicts[0].keys())
    else:
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

    with get_connection() as connection:
        connection.execute("DELETE FROM consents")
        connection.execute("DELETE FROM audit_events")
        connection.execute("DELETE FROM notice_versions")
        connection.execute(
            """
            INSERT INTO notice_versions (version, text, hash, created_at)
            VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            """,
            (DEFAULT_NOTICE_VERSION, DEFAULT_NOTICE_TEXT, DEFAULT_NOTICE_HASH),
        )

        append_audit_event(
            connection=connection,
            user_id="system",
            purpose="System Administration",
            action="demo_reset",
            http_status=200,
            reason_code="SYSTEM_RESET",
            notice_version=NOTICE_VERSION,
            notice_hash=NOTICE_HASH,
            source="demo",
            details="Demo database initialized to default notice v1.0 and empty state.",
        )

    return jsonify({
        "message": "Demo data reset successfully",
        "notice_version": NOTICE_VERSION,
        "notice_hash": NOTICE_HASH,
    })


if __name__ == "__main__":
    initialize_database()
    load_active_notice()
    app.run(host="0.0.0.0", port=5001, debug=False, threaded=True)
