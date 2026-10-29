import urllib.request
import json
import http.cookiejar
import time

API = "http://127.0.0.1:5001/api"

print("--- Starting Full ConsentGuard Verification ---")

# 1. Health check
req = urllib.request.Request(API + "/health")
with urllib.request.urlopen(req) as res:
    health_data = json.loads(res.read().decode())
    assert health_data["status"] == "ok", "Health status failed"
    print("[PASS] Step 1: Health check OK (service connected, DB connected)")

# 2. Signup, Login, Logout, Session Persistence
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

unique_email = f"user_{int(time.time()*1000)}@example.com"
signup_payload = {"name": "Test User A", "email": unique_email, "password": "SecurePassword123!"}
req = urllib.request.Request(API + "/auth/signup", data=json.dumps(signup_payload).encode(), headers={"Content-Type": "application/json"})
with opener.open(req) as res:
    signup_data = json.loads(res.read().decode())
    assert res.status == 201
    user_a = signup_data["user"]
    assert user_a["email"] == unique_email
print(f"[PASS] Step 2a: User account created ({user_a['id']})")

req = urllib.request.Request(API + "/auth/me")
with opener.open(req) as res:
    me_data = json.loads(res.read().decode())
    assert me_data["authenticated"] is True
    assert me_data["user"]["id"] == user_a["id"]
print("[PASS] Step 2b: Session persistence verified (/api/auth/me returns authenticated user)")

# Logout
req = urllib.request.Request(API + "/auth/logout", data=b"{}", headers={"Content-Type": "application/json"})
with opener.open(req) as res:
    assert res.status == 200

req = urllib.request.Request(API + "/auth/me")
with opener.open(req) as res:
    me_logged_out = json.loads(res.read().decode())
    assert me_logged_out["authenticated"] is False
print("[PASS] Step 2c: Logout clears session")

# Login back in
login_payload = {"email": unique_email, "password": "SecurePassword123!"}
req = urllib.request.Request(API + "/auth/login", data=json.dumps(login_payload).encode(), headers={"Content-Type": "application/json"})
with opener.open(req) as res:
    login_data = json.loads(res.read().decode())
    assert res.status == 200
    assert login_data["user"]["id"] == user_a["id"]
print("[PASS] Step 2d: Re-login restores session and loads correct user identity")

# 3. Grant, Deny, Withdraw for all three purposes
purposes = ["Analytics", "Marketing", "Service Improvement"]
for p in purposes:
    # Grant
    grant_payload = {"purpose": p, "action": "grant", "source": "user"}
    req = urllib.request.Request(API + "/consents", data=json.dumps(grant_payload).encode(), headers={"Content-Type": "application/json"})
    with opener.open(req) as res:
        assert res.status == 201
        data = json.loads(res.read().decode())
        assert data["granted"] is True

    # Deny
    deny_payload = {"purpose": p, "action": "deny", "source": "user"}
    req = urllib.request.Request(API + "/consents", data=json.dumps(deny_payload).encode(), headers={"Content-Type": "application/json"})
    with opener.open(req) as res:
        assert res.status == 201
        data = json.loads(res.read().decode())
        assert data["granted"] is False
        assert data["reason_code"] == "CONSENT_DENIED"

    # Grant again then Withdraw
    grant_payload = {"purpose": p, "action": "grant", "source": "user"}
    req = urllib.request.Request(API + "/consents", data=json.dumps(grant_payload).encode(), headers={"Content-Type": "application/json"})
    with opener.open(req) as res: assert res.status == 201

    withdraw_payload = {"purpose": p, "action": "withdraw", "source": "user"}
    req = urllib.request.Request(API + "/consents", data=json.dumps(withdraw_payload).encode(), headers={"Content-Type": "application/json"})
    with opener.open(req) as res:
        assert res.status == 201
        data = json.loads(res.read().decode())
        assert data["granted"] is False
        assert data["reason_code"] == "CONSENT_WITHDRAWN"

print("[PASS] Step 3: Grant, Deny, and Withdraw work cleanly for all 3 purposes")

# 4. Consent refresh from database
req = urllib.request.Request(API + "/consents")
with opener.open(req) as res:
    consents_list = json.loads(res.read().decode())
    assert len(consents_list) == 3
    for c in consents_list:
        assert c["user_id"] == user_a["id"]
print("[PASS] Step 4: Consents refreshed accurately from live database")

# 5. Access Allowed (200) vs Access Blocked (403)
req = urllib.request.Request(API + "/consents", data=json.dumps({"purpose": "Analytics", "action": "grant", "source": "user"}).encode(), headers={"Content-Type": "application/json"})
with opener.open(req) as res: assert res.status == 201

req = urllib.request.Request(API + "/data-access", data=json.dumps({"purpose": "Analytics", "source": "user"}).encode(), headers={"Content-Type": "application/json"})
with opener.open(req) as res:
    data = json.loads(res.read().decode())
    assert res.status == 200
    assert data["allowed"] is True
    assert "page_views" in data["data"]
print("[PASS] Step 5a: Access Allowed (HTTP 200) with safe data payload")

req = urllib.request.Request(API + "/data-access", data=json.dumps({"purpose": "Marketing", "source": "user"}).encode(), headers={"Content-Type": "application/json"})
try:
    with opener.open(req) as res:
        assert False, "Expected HTTP 403"
except urllib.error.HTTPError as e:
    data = json.loads(e.read().decode())
    assert e.code == 403
    assert data["allowed"] is False
    assert data["reason_code"] == "WITHDRAWN"
print("[PASS] Step 5b: Access Blocked (HTTP 403 WITHDRAWN) with clear explanation")

# 6. Notice v1.0 -> v2.0 invalidation and re-consent
req = urllib.request.Request(API + "/notice/update", data=json.dumps({"notice_version": "2.0", "source": "user"}).encode(), headers={"Content-Type": "application/json"})
with opener.open(req) as res: assert res.status == 200

req = urllib.request.Request(API + "/data-access", data=json.dumps({"purpose": "Analytics", "source": "user"}).encode(), headers={"Content-Type": "application/json"})
try:
    with opener.open(req) as res: assert False, "Expected HTTP 403"
except urllib.error.HTTPError as e:
    data = json.loads(e.read().decode())
    assert e.code == 403
    assert data["reason_code"] == "NOTICE_MISMATCH"
print("[PASS] Step 6a: Notice upgrade invalidated prior consent (HTTP 403 NOTICE_MISMATCH)")

req = urllib.request.Request(API + "/consents", data=json.dumps({"purpose": "Analytics", "action": "grant", "source": "user"}).encode(), headers={"Content-Type": "application/json"})
with opener.open(req) as res: assert res.status == 201

req = urllib.request.Request(API + "/data-access", data=json.dumps({"purpose": "Analytics", "source": "user"}).encode(), headers={"Content-Type": "application/json"})
with opener.open(req) as res:
    data = json.loads(res.read().decode())
    assert res.status == 200
    assert data["allowed"] is True
print("[PASS] Step 6b: Fresh consent under active notice v2.0 restored access (HTTP 200)")

# Reset notice back to v1.0
req = urllib.request.Request(API + "/notice/reset", data=json.dumps({"source": "user"}).encode(), headers={"Content-Type": "application/json"})
with opener.open(req) as res: assert res.status == 200

# 7. Two accounts complete data isolation
cj_b = http.cookiejar.CookieJar()
opener_b = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj_b))

unique_email_b = f"user_b_{int(time.time()*1000)}@example.com"
signup_payload_b = {"name": "Test User B", "email": unique_email_b, "password": "SecurePassword123!"}
req = urllib.request.Request(API + "/auth/signup", data=json.dumps(signup_payload_b).encode(), headers={"Content-Type": "application/json"})
with opener_b.open(req) as res:
    user_b = json.loads(res.read().decode())["user"]

req = urllib.request.Request(API + "/consents")
with opener_b.open(req) as res:
    b_consents = json.loads(res.read().decode())
    assert len(b_consents) == 0
print(f"[PASS] Step 7a: New user B ({user_b['id']}) initialized with zero consents")

# User B cannot see User A's consents
req = urllib.request.Request(API + f"/consents?user_id={user_a['id']}")
try:
    with opener_b.open(req) as res: assert False, "Expected HTTP 403"
except urllib.error.HTTPError as e:
    assert e.code == 403
    assert json.loads(e.read().decode())["reason_code"] == "FORBIDDEN_CROSS_USER_ACCESS"

# User B cannot modify User A's consent
req = urllib.request.Request(API + "/consents", data=json.dumps({"user_id": user_a["id"], "purpose": "Analytics", "action": "grant", "source": "user"}).encode(), headers={"Content-Type": "application/json"})
try:
    with opener_b.open(req) as res: assert False, "Expected HTTP 403"
except urllib.error.HTTPError as e:
    assert e.code == 403
    assert json.loads(e.read().decode())["reason_code"] == "FORBIDDEN_CROSS_USER_ACCESS"

# User B cannot view User A's audit events
req = urllib.request.Request(API + f"/audit?user_id={user_a['id']}")
try:
    with opener_b.open(req) as res: assert False, "Expected HTTP 403"
except urllib.error.HTTPError as e:
    assert e.code == 403
    assert json.loads(e.read().decode())["reason_code"] == "FORBIDDEN_CROSS_USER_ACCESS"
print("[PASS] Step 7b: Strict cross-user boundary enforced across accounts (HTTP 403 FORBIDDEN_CROSS_USER_ACCESS)")

# 8. Run all 14 diagnostic tests
uid = f"suite-user-{int(time.time()*1000)}"

def post_test(path, payload):
    payload["source"] = "test"
    headers = {"Content-Type": "application/json", "X-Test-Source": "test"}
    req = urllib.request.Request(API + path, data=json.dumps(payload).encode(), headers=headers)
    try:
        with urllib.request.urlopen(req) as res: return res.status, json.loads(res.read().decode())
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read().decode())

def get_test(path):
    headers = {"X-Test-Source": "test"}
    req = urllib.request.Request(API + path, headers=headers)
    with urllib.request.urlopen(req) as res: return res.status, json.loads(res.read().decode())

t1_s, t1_d = get_test("/health")
assert t1_s == 200, f"T1 failed: {t1_s}"

t2_s, t2_d = get_test("/notice")
assert t2_s == 200 and len(t2_d.get("notice_hash", "")) == 64, f"T2 failed"

t3_s, t3_d = post_test("/consents", {"user_id": uid, "purpose": "Analytics", "action": "grant"})
assert t3_s == 201 and t3_d["granted"] is True, f"T3 failed: {t3_s} {t3_d}"

t4_s, t4_d = post_test("/data-access", {"user_id": uid, "purpose": "Analytics"})
assert t4_s == 200 and t4_d["allowed"] is True, f"T4 failed: {t4_s} {t4_d}"

t5_s, t5_d = post_test("/consents", {"user_id": uid, "purpose": "Analytics", "action": "withdraw"})
assert t5_s == 201 and t5_d["granted"] is False, f"T5 failed: {t5_s} {t5_d}"

t6_s, t6_d = post_test("/data-access", {"user_id": uid, "purpose": "Analytics"})
assert t6_s == 403 and t6_d["reason_code"] == "WITHDRAWN", f"T6 failed: {t6_s} {t6_d}"

post_test("/consents", {"user_id": uid, "purpose": "Marketing", "action": "deny"})
t7_s, t7_d = post_test("/data-access", {"user_id": uid, "purpose": "Marketing"})
assert t7_s == 403 and t7_d["reason_code"] == "DENIED", f"T7 failed: {t7_s} {t7_d}"

t8_s, t8_d = post_test("/data-access", {"user_id": uid, "purpose": "Service Improvement"})
assert t8_s == 403 and t8_d["reason_code"] == "NO_CONSENT", f"T8 failed: {t8_s} {t8_d}"

t9_s, t9_d = post_test("/data-access", {"user_id": uid, "purpose": "Biometric Profiling"})
assert t9_s == 400 and t9_d["reason_code"] == "INVALID_PURPOSE", f"T9 failed: {t9_s} {t9_d}"

t10_s, t10_d = post_test("/consents", {"user_id": uid, "purpose": "Analytics", "action": "temporary_permit"})
assert t10_s == 400 and t10_d["reason_code"] == "INVALID_ACTION", f"T10 failed: {t10_s} {t10_d}"

t11_s, t11_d = post_test("/data-access", {"user_id": uid + "-unauthorized", "purpose": "Analytics"})
assert t11_s == 403 and t11_d["reason_code"] == "NO_CONSENT", f"T11 failed: {t11_s} {t11_d}"

post_test("/notice/reset", {})
post_test("/consents", {"user_id": uid, "purpose": "Service Improvement", "action": "grant"})
post_test("/notice/update", {"notice_version": "2.0"})
t12_s, t12_d = post_test("/data-access", {"user_id": uid, "purpose": "Service Improvement"})
assert t12_s == 403 and t12_d["reason_code"] == "NOTICE_MISMATCH", f"T12 failed: {t12_s} {t12_d}"

post_test("/consents", {"user_id": uid, "purpose": "Service Improvement", "action": "grant"})
t13_s, t13_d = post_test("/data-access", {"user_id": uid, "purpose": "Service Improvement"})
assert t13_s == 200 and t13_d["allowed"] is True, f"T13 failed: {t13_s} {t13_d}"
post_test("/notice/reset", {})

t14_s, t14_d = get_test("/audit/verify")
assert t14_s == 200 and t14_d["status"] == "intact", f"T14 failed: {t14_s} {t14_d}"
print("[PASS] Step 8: All 14 Automated Diagnostic Tests PASSED (14/14)")

# 9. Verify cryptographic hash chain
req = urllib.request.Request(API + "/audit/verify")
with opener.open(req) as res:
    v_data = json.loads(res.read().decode())
    assert v_data["status"] == "intact"
    print(f"[PASS] Step 9: Append-only cryptographic hash chain 100% intact ({v_data['verified_count']} records verified)")

print("\n=======================================================")
print("  ALL 9 END-TO-END VERIFICATION CHECKS PASSED (100%)")
print("=======================================================")
