
from flask import Flask, jsonify, send_file

app = Flask(__name__)


@app.route("/")
def home():
    return send_file("dashboard.html")


@app.route("/api/health")
def health():
    return jsonify({
        "status": "working",
        "project": "ConsentGuard"
    })
@app.route("/api/consent", methods=["POST"])
def save_consent():
    from flask import request

    data = request.get_json()

    if not data or data.get("purpose") not in [
        "Analytics", "Marketing", "Third-Party Sharing"
    ]:
        return jsonify({"error": "Invalid purpose"}), 400

    if data.get("status") not in ["Granted", "Denied", "Withdrawn"]:
        return jsonify({"error": "Invalid status"}), 400

    print("Consent decision:", data)

    return jsonify({
        "message": "Consent decision received",
        "purpose": data["purpose"],
        "status": data["status"]
    })




if __name__ == "__main__":
    app.run(debug=True)
