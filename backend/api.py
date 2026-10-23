import hashlib
import os

from flask import Flask, Response, jsonify, request
from flask_cors import CORS

from database import get_connection, initialize_database

app = Flask(__name__)
CORS(app)

# These are the three purposes required by the PS-002 challenge.
PURPOSES = {"Analytics", "Marketing", "Service Improvement"}

NOTICE_VERSION = os.getenv("CONSENT_NOTICE_VERSION", "1.0")
NOTICE_TEXT = os.getenv(
    "CONSENT_NOTICE_TEXT",
    "ConsentGuard uses data only for the purpose selected by the user. "
    "Users may withdraw consent at any time. A notice change requires "
    "fresh consent before data access is allowed."
)
NOTICE_HASH = hashlib.sha256(NOTICE_TEXT.encode("utf-8")).hexdigest()

# Synthetic data returned only by the mock downstream consumer.
MOCK_DATA = {
    "Analytics": {"page_views": 12, "feature_usage": ["dashboard", "search"]},
    "Marketing": {"email_preferences": "weekly_updates", "offers_enabled": True},
    "Service Improvement": {
        "app_performance_ms": 184,
        "recent_error_count": 0
    },
}


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "ConsentGuard API"})


@app.get("/api/consents")
def get_consents():
    user_id = request.args.get("user_id", "demo-user")
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM consents WHERE user_id = ? ORDER BY purpose",
            (user_id,)
        ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.post("/api/consents")
def record_consent():
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id", "demo-user")
    purpose = data.get("purpose")
    action = data.get("action")

    if purpose not in PURPOSES:
        return jsonify({
            "error": "Invalid purpose",
            "valid_purposes": sorted(PURPOSES)
        }), 400
    if action not in {"grant", "deny", "withdraw"}:
        return jsonify({"error": "Action must be grant, deny, or withdraw"}), 400

    granted = 1 if action == "grant" else 0
    with get_connection() as connection:
        connection.execute("""
            INSERT INTO consents (user_id, purpose, granted, notice_version)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id, purpose) DO UPDATE SET
                granted = excluded.granted,
                notice_version = excluded.notice_version,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
        """, (user_id, purpose, granted, NOTICE_VERSION))
        connection.execute("""
            INSERT INTO audit_events
                (user_id, purpose, action, notice_version, details)
            VALUES (?, ?, ?, ?, ?)
        """, (
            user_id, purpose, action, NOTICE_VERSION,
            f"Consent state updated; notice_sha256={NOTICE_HASH}"
        ))

    return jsonify({
        "user_id": user_id,
        "purpose": purpose,
        "action": action,
        "granted": bool(granted),
        "notice_version": NOTICE_VERSION,
        "notice_hash": NOTICE_HASH
    }), 201


@app.post("/api/data-access")
def data_access():
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id", "demo-user")
    purpose = data.get("purpose")

    if purpose not in PURPOSES:
        return jsonify({
            "allowed": False,
            "error": "Invalid purpose",
            "valid_purposes": sorted(PURPOSES)
        }), 400

    with get_connection() as connection:
        row = connection.execute("""
            SELECT granted, notice_version FROM consents
            WHERE user_id = ? AND purpose = ?
        """, (user_id, purpose)).fetchone()

        allowed = (
            row is not None
            and row["granted"] == 1
            and row["notice_version"] == NOTICE_VERSION
        )

        connection.execute("""
            INSERT INTO audit_events
                (user_id, purpose, action, notice_version, details)
            VALUES (?, ?, ?, ?, ?)
        """, (
            user_id, purpose,
            "data_access_allowed" if allowed else "data_access_denied",
            NOTICE_VERSION,
            f"Mock downstream request; notice_sha256={NOTICE_HASH}"
        ))

    if not allowed:
        return jsonify({
            "allowed": False,
            "message": "Request denied: current active consent is required.",
            "user_id": user_id,
            "purpose": purpose,
            "notice_version": NOTICE_VERSION,
            "notice_hash": NOTICE_HASH
        }), 403

    return jsonify({
        "allowed": True,
        "message": "Mock data access permitted.",
        "user_id": user_id,
        "purpose": purpose,
        "notice_version": NOTICE_VERSION,
        "notice_hash": NOTICE_HASH,
        "data": MOCK_DATA[purpose]
    })


@app.post("/api/audit/reset")
def reset_audit():
    with get_connection() as connection:
        connection.execute("DELETE FROM audit_events")
    return jsonify({"message": "Activity history reset successfully"})


@app.get("/api/audit")
def get_audit():
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM audit_events ORDER BY id DESC"
        ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.get("/api/audit/export")
def export_audit():
    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "user_id", "purpose", "action",
        "notice_version", "details", "created_at"
    ])
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM audit_events ORDER BY id"
        ).fetchall()
    for row in rows:
        writer.writerow([row[key] for key in row.keys()])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=consentguard_audit.csv"}
    )


@app.get("/api/notice")
def get_notice():
    return jsonify({
        "notice_version": NOTICE_VERSION,
        "notice_text": NOTICE_TEXT,
        "notice_hash": NOTICE_HASH,
        "hash_algorithm": "SHA-256"
    })


if __name__ == "__main__":
    initialize_database()
    app.run(debug=True, port=5001)
