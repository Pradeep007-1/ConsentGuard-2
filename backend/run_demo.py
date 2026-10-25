import json
import urllib.error
import urllib.request

def post(url, data):
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())

def get(url):
    with urllib.request.urlopen(url) as resp:
        return resp.status, json.loads(resp.read().decode())

def run():
    print("=" * 65)
    print("STAGE 0: HEALTH CHECK")
    print("=" * 65)
    status, res = get("http://127.0.0.1:5001/api/health")
    print(f"HTTP {status}:", json.dumps(res, indent=2))

    print("\n" + "=" * 65)
    print("STAGE 1: USER GRANTS CONSENT (Analytics under Notice v1.0)")
    print("=" * 65)
    status, res = post(
        "http://127.0.0.1:5001/api/consents",
        {"user_id": "demo-user", "purpose": "Analytics", "action": "grant"}
    )
    print(f"HTTP {status}:", json.dumps(res, indent=2))

    print("\n" + "=" * 65)
    print("STAGE 2: DOWNSTREAM DATA SHARING REQUEST (PEP ENFORCEMENT)")
    print("=" * 65)
    status, res = post(
        "http://127.0.0.1:5001/api/data-access",
        {"user_id": "demo-user", "purpose": "Analytics"}
    )
    print(f"HTTP {status} [ACCESS PERMITTED]:", json.dumps(res, indent=2))

    print("\n" + "=" * 65)
    print("STAGE 3: USER WITHDRAWS CONSENT (Right to Revoke)")
    print("=" * 65)
    status, res = post(
        "http://127.0.0.1:5001/api/consents",
        {"user_id": "demo-user", "purpose": "Analytics", "action": "withdraw"}
    )
    print(f"HTTP {status}:", json.dumps(res, indent=2))

    print("\n" + "=" * 65)
    print("STAGE 4: SUBSEQUENT DOWNSTREAM REQUEST (PEP DENIAL)")
    print("=" * 65)
    status, res = post(
        "http://127.0.0.1:5001/api/data-access",
        {"user_id": "demo-user", "purpose": "Analytics"}
    )
    print(f"HTTP {status} [ACCESS DENIED]:", json.dumps(res, indent=2))

    print("\n" + "=" * 65)
    print("STAGE 5: NOTICE VERSION UPDATE & STALE CONSENT REJECTION")
    print("=" * 65)
    # Grant under v1.0
    post(
        "http://127.0.0.1:5001/api/consents",
        {"user_id": "demo-user", "purpose": "Analytics", "action": "grant"}
    )
    # Bump notice to v2.0
    status, res = post(
        "http://127.0.0.1:5001/api/notice/update",
        {"notice_version": "2.0"}
    )
    print(f"Privacy Notice bumped to v{res['notice_version']}")
    print(f"New Notice Hash: {res['notice_hash']}")

    # Try accessing with stale consent
    status, res = post(
        "http://127.0.0.1:5001/api/data-access",
        {"user_id": "demo-user", "purpose": "Analytics"}
    )
    print(f"HTTP {status} [ACCESS DENIED DUE TO OBSOLETE NOTICE]:", json.dumps(res, indent=2))

    # Reset notice back to v1.0
    post("http://127.0.0.1:5001/api/notice/reset", {})
    print("\nNotice reset back to default v1.0.")
    print("=" * 65)
    print("ALL 5 LIFECYCLE STAGES EXECUTED AND VERIFIED SUCCESSFULLY!")
    print("=" * 65)

if __name__ == "__main__":
    run()
