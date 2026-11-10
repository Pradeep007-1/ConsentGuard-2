import urllib.request, json, time, sys, os

def run_deep_audit(base_url, is_cloud=False):
    print(f"\n" + "="*70)
    print(f" DEEP AUDIT: {base_url} (Cloud: {is_cloud})")
    print("="*70)

    # We will test two users:
    # 1. A newly registered user through the live API (testing real signup/login flow)
    # 2. Existing demo-user (testing instant demo switching)
    test_email = f"audit_tester_{int(time.time()*1000)}@consentguard.org"
    test_password = "SecurePassword123!"
    test_name = "Deep Audit Inspector"

    passed = 0
    failed = 0

    def assert_check(name, condition, details=""):
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"  [PASS] {name}")
        else:
            failed += 1
            print(f"  [FAIL] {name} - {details}")

    def call_api(path, method="GET", payload=None, auth_token=None):
        url = base_url + "/api" + path
        hdrs = {"Content-Type": "application/json"}
        if auth_token:
            hdrs["Authorization"] = f"Bearer {auth_token}"
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                body = resp.read().decode("utf-8")
                try: return resp.status, json.loads(body)
                except: return resp.status, body
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8")
            try: return e.code, json.loads(body)
            except: return e.code, body
        except Exception as e:
            return 0, str(e)

    # -------------------------------------------------------------
    # STAGE 1: Full User Registration & Sign-In Journey
    # -------------------------------------------------------------
    st, signup_res = call_api("/auth/signup", method="POST", payload={
        "name": test_name,
        "email": test_email,
        "password": test_password
    })
    assert_check("1. Live Registration creates new account with HTTP 201", st == 201 and "token" in signup_res, str(signup_res))
    user_id = signup_res.get("user", {}).get("id") if isinstance(signup_res, dict) else None
    token = signup_res.get("token") if isinstance(signup_res, dict) else None

    # Sign in explicitly with credentials
    st, login_res = call_api("/auth/login", method="POST", payload={
        "email": test_email,
        "password": test_password
    })
    assert_check("2. Sign-In with verified credentials returns HTTP 200 + Signed Token", st == 200 and "token" in login_res, str(login_res))
    if isinstance(login_res, dict) and "token" in login_res:
        token = login_res["token"]

    # Verify session via /auth/me
    st, me_res = call_api("/auth/me", auth_token=token)
    assert_check("3. /api/auth/me verifies session identity correctly", st == 200 and me_res.get("authenticated") is True and me_res.get("user", {}).get("email") == test_email, str(me_res))

    # -------------------------------------------------------------
    # STAGE 2: Baseline Zero-State Verification
    # -------------------------------------------------------------
    st, initial_consents = call_api("/consents", auth_token=token)
    assert_check("4. Fresh user has zero pre-existing consents", st == 200 and isinstance(initial_consents, list) and len(initial_consents) == 0, str(initial_consents))

    st, initial_stats = call_api(f"/stats?user_id={user_id}", auth_token=token)
    assert_check("5. Fresh user has active_consents=0", st == 200 and initial_stats.get("active_consents") == 0, str(initial_stats))

    # -------------------------------------------------------------
    # STAGE 3: Granting Consents One by One (Full Lifecycle)
    # -------------------------------------------------------------
    # Grant 1: Analytics
    st, d = call_api("/consents", method="POST", payload={"purpose": "Analytics", "action": "grant", "source": "user"}, auth_token=token)
    assert_check("6. Grant Analytics consent", st in (200, 201) and d.get("granted") is True, str(d))

    st, stats_1 = call_api(f"/stats?user_id={user_id}", auth_token=token)
    assert_check("7. Active consents increments to 1", stats_1.get("active_consents") == 1, str(stats_1))

    # Grant 2: Marketing
    st, d = call_api("/consents", method="POST", payload={"purpose": "Marketing", "action": "grant", "source": "user"}, auth_token=token)
    assert_check("8. Grant Marketing consent", st in (200, 201) and d.get("granted") is True, str(d))

    st, stats_2 = call_api(f"/stats?user_id={user_id}", auth_token=token)
    assert_check("9. Active consents increments to 2", stats_2.get("active_consents") == 2, str(stats_2))

    # Grant 3: Service Improvement
    st, d = call_api("/consents", method="POST", payload={"purpose": "Service Improvement", "action": "grant", "source": "user"}, auth_token=token)
    assert_check("10. Grant Service Improvement consent", st in (200, 201) and d.get("granted") is True, str(d))

    st, stats_3 = call_api(f"/stats?user_id={user_id}", auth_token=token)
    assert_check("11. Active consents reaches exactly 3 / 3", stats_3.get("active_consents") == 3, str(stats_3))

    # -------------------------------------------------------------
    # STAGE 4: Policy Enforcement Point (PEP) Verification
    # -------------------------------------------------------------
    for p in ["Analytics", "Marketing", "Service Improvement"]:
        st, d = call_api("/data-access", method="POST", payload={"user_id": user_id, "purpose": p}, auth_token=token)
        assert_check(f"12. PEP releases payload for {p} (HTTP 200 ACTIVE_CONSENT)", st == 200 and d.get("allowed") is True and d.get("reason_code") == "ACTIVE_CONSENT", str(d))

    # -------------------------------------------------------------
    # STAGE 5: Explicit Withdrawal & Zero-Delay Blocking
    # -------------------------------------------------------------
    st, d = call_api("/consents", method="POST", payload={"purpose": "Marketing", "action": "withdraw", "source": "user"}, auth_token=token)
    assert_check("13. Withdraw Marketing consent", st in (200, 201) and d.get("granted") is False, str(d))

    st, d = call_api("/data-access", method="POST", payload={"user_id": user_id, "purpose": "Marketing"}, auth_token=token)
    assert_check("14. PEP immediately blocks Marketing (HTTP 403 WITHDRAWN)", st == 403 and d.get("allowed") is False and d.get("reason_code") == "WITHDRAWN", str(d))

    st, stats_withdrawn = call_api(f"/stats?user_id={user_id}", auth_token=token)
    assert_check("15. Stats reflect active_consents=2, withdrawn=1", stats_withdrawn.get("active_consents") == 2 and stats_withdrawn.get("withdrawn_consents") == 1, str(stats_withdrawn))

    # Re-grant Marketing
    call_api("/consents", method="POST", payload={"purpose": "Marketing", "action": "grant", "source": "user"}, auth_token=token)

    # -------------------------------------------------------------
    # STAGE 6: Privacy Notice Bump to v2.0 & Stale Invalidation
    # -------------------------------------------------------------
    # Log in as admin-user to bump the privacy notice
    st, admin_login = call_api("/auth/demo-login", method="POST", payload={"user_id": "admin-user"})
    admin_token = admin_login.get("token") if isinstance(admin_login, dict) else None

    st, bump_res = call_api("/notice/update", method="POST", payload={"notice_version": "2.0", "source": "user"}, auth_token=admin_token)
    assert_check("16. Administrator bumps Privacy Notice to v2.0", st == 200 and bump_res.get("notice_version") == "2.0", str(bump_res))

    st, d = call_api("/data-access", method="POST", payload={"user_id": user_id, "purpose": "Analytics"}, auth_token=token)
    assert_check("17. PEP blocks stale consent under v2.0 (HTTP 403 NOTICE_MISMATCH)", st == 403 and (d.get("reason_code") == "NOTICE_MISMATCH" or d.get("error_code") == "NOTICE_OUTDATED_RECONSENT_REQUIRED"), str(d))

    # Re-consent all 3 under v2.0
    for p in ["Analytics", "Marketing", "Service Improvement"]:
        st, d = call_api("/consents", method="POST", payload={"purpose": p, "action": "grant", "source": "user"}, auth_token=token)
        assert_check(f"18. Re-consent {p} under v2.0", st in (200, 201) and d.get("granted") is True, str(d))

    st, d = call_api("/data-access", method="POST", payload={"user_id": user_id, "purpose": "Analytics"}, auth_token=token)
    assert_check("19. PEP permits access under fresh v2.0 consent (HTTP 200)", st == 200 and d.get("allowed") is True, str(d))

    # Reset notice to v1.0 using admin session
    st, d = call_api("/notice/reset", method="POST", payload={"source": "user"}, auth_token=admin_token)
    assert_check("20. Notice reset back to v1.0 default", st == 200 and d.get("notice_version") == "1.0", str(d))

    # Re-grant all 3 under v1.0
    for p in ["Analytics", "Marketing", "Service Improvement"]:
        call_api("/consents", method="POST", payload={"purpose": p, "action": "grant", "source": "user"}, auth_token=token)

    # -------------------------------------------------------------
    # STAGE 7: Merkle DAG Ledger Verification & Export
    # -------------------------------------------------------------
    st, verify_res = call_api("/audit/verify", auth_token=token)
    assert_check("21. Merkle DAG audit chain verified intact (0 tampered)", st == 200 and verify_res.get("status") == "intact", str(verify_res))

    st, csv_export = call_api("/audit/export?format=csv", auth_token=token)
    assert_check("22. Authenticated CSV audit export succeeds", st == 200 and isinstance(csv_export, str) and ("id" in csv_export or "created_at" in csv_export), f"Status: {st}")

    st, json_export = call_api("/audit/export?format=json", auth_token=token)
    assert_check("23. Authenticated JSON audit export succeeds", st == 200 and isinstance(json_export, list), str(json_export))

    # -------------------------------------------------------------
    # STAGE 8: Cybersecurity Protections & Security Boundaries
    # -------------------------------------------------------------
    # Test A: SQL Injection attempt
    st, d = call_api("/data-access", method="POST", payload={"user_id": user_id, "purpose": "' OR 1=1; DROP TABLE users; --"}, auth_token=token)
    assert_check("24. SQL injection in purpose rejected safely with HTTP 400", st == 400, str(d))

    # Test B: XSS / Invalid JSON injection
    st, d = call_api("/consents", method="POST", payload={"purpose": "<script>alert(1)</script>", "action": "grant"}, auth_token=token)
    assert_check("25. Invalid purpose name rejected safely with HTTP 400", st == 400, str(d))

    # Test C: Cross-user boundary protection (using user1)
    st, demo_res = call_api("/auth/demo-login", method="POST", payload={"user_id": "user1"})
    user1_tok = demo_res.get("token") if isinstance(demo_res, dict) else None
    st, d = call_api(f"/consents?user_id={user_id}", auth_token=user1_tok)
    assert_check("26. User 1 cannot view other user's consents (HTTP 403 Forbidden)", st == 403, str(d))

    st, d = call_api(f"/consents", method="POST", payload={"user_id": user_id, "purpose": "Analytics", "action": "withdraw"}, auth_token=user1_tok)
    assert_check("27. User 1 cannot tamper with other user's consent (HTTP 403 Forbidden)", st == 403, str(d))

    print(f"\nRESULTS FOR {base_url}:")
    print(f"  Total Passed: {passed} / 27")
    print(f"  Total Failed: {failed}")
    return failed == 0

if __name__ == "__main__":
    print("\nSTARTING FULL DEEP AUDIT...")
    local_ok = run_deep_audit("http://127.0.0.1:5001", is_cloud=False)
    cloud_ok = run_deep_audit("https://consent-guard-2.vercel.app", is_cloud=True)

    print("\n" + "="*70)
    if local_ok and cloud_ok:
        print(" [ALL CLEAR] 100% OF DEEP AUDIT TESTS PASSED ON BOTH LOCAL AND VERCEL!")
        sys.exit(0)
    else:
        print(" [FAIL] Some checks failed.")
        sys.exit(1)
