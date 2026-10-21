
from flask import Flask, jsonify, request
from flask_cors import CORS
from database import get_connection, initialize_database

app = Flask(__name__)
CORS(app) 

PURPOSES = {"Analytics", "Marketing", "Third-Party Sharing"}
import os

NOTICE_VERSION = os.getenv("CONSENT_NOTICE_VERSION", "1.0") 


@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "ConsentGuard API"
    })


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
        return jsonify({"error": "Invalid purpose"}), 400

    if action not in {"grant", "deny", "withdraw"}:
        return jsonify({
            "error": "Action must be grant, deny, or withdraw"
        }), 400

    granted = 1 if action == "grant" else 0

    with get_connection() as connection:
        connection.execute("""
            INSERT INTO consents
                (user_id, purpose, granted, notice_version)
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
            "Consent state updated"
        ))

    return jsonify({
        "user_id": user_id,
        "purpose": purpose,
        "action": action,
        "granted": bool(granted),
        "notice_version": NOTICE_VERSION
    }), 201


@app.post("/api/data-access")
def data_access():
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id", "demo-user")
    purpose = data.get("purpose")

    if purpose not in PURPOSES:
        return jsonify({"error": "Invalid purpose"}), 400

   
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
            "Mock downstream request"
        ))

    if not allowed:
        return jsonify({
            "allowed": False,
            "message": "Request denied: active consent is required."
        }), 403

    return jsonify({
        "allowed": True,
        "message": "Mock data access permitted."
    })

@app.post("/api/audit/reset")
def reset_audit():
    with get_connection() as connection:
        connection.execute("DELETE FROM audit_events")
    return jsonify({"message": "Activity history reset successfully"}) 

@app.get("/api/audit")
def get_audit():
    with get_connection() as connection:
        rows = connection.execute("""
            SELECT * FROM audit_events ORDER BY id DESC
        """).fetchall()

    return jsonify([dict(row) for row in rows])


@app.get("/api/audit/export")
def export_audit():
    import csv
    import io
    from flask import Response

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "user_id", "purpose", "action",
        "notice_version", "details", "created_at"
    ])

    with get_connection() as connection:
        rows = connection.execute("""
            SELECT * FROM audit_events ORDER BY id
        """).fetchall()

    for row in rows:
        writer.writerow([row[key] for key in row.keys()])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
                "attachment; filename=consentguard_audit.csv"
        }
    )



@app.get("/api/notice")
def get_notice():
    return jsonify({"notice_version": NOTICE_VERSION})

if __name__ == "__main__":
    initialize_database()
    app.run(debug=True, port=5001)

