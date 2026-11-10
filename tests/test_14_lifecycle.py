import urllib.request, json, time, sys

def test_14_checks(base_url):
    print(f"\n========================================================")
    print(f" RUNNING 14 DIAGNOSTIC CHECKS AGAINST: {base_url}")
    print(f"========================================================")
    
    uid = f"suite-user-{int(time.time()*1000)}"
    headers = {"Content-Type": "application/json", "X-Test-Source": "test"}

    def req(path, payload=None, method="POST"):
        url = base_url + "/api" + path
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        r = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                body = resp.read().decode("utf-8")
                try: return resp.status, json.loads(body)
                except: return resp.status, body
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8")
            try: return e.code, json.loads(body)
            except: return e.code, body
        except Exception as e:
            return 0, str(e)

    results = []
    def check(num, name, condition, details=""):
        if condition:
            print(f"  [PASS] {num}. {name}")
            results.append(True)
        else:
            print(f"  [FAIL] {num}. {name} - {details}")
            results.append(False)

    try:
        # 1. Health check
        st, d = req("/health", method="GET")
        check(1, "Health check responds", st == 200, str(d))

        # 2. Notice SHA-256
        st, d = req("/notice", method="GET")
        h = d.get("notice_hash", "") if isinstance(d, dict) else ""
        check(2, "Notice provides SHA-256 fingerprint", st == 200 and len(h) == 64, str(d))

        # 3. Grant Analytics
        st, d = req("/consents", {"user_id": uid, "purpose": "Analytics", "action": "grant", "source": "test"})
        check(3, "Grant Analytics consent", st == 201 and d.get("granted") is True, str(d))

        # 4. PEP Analytics allowed
        st, d = req("/data-access", {"user_id": uid, "purpose": "Analytics", "source": "test"})
        check(4, "Granted Analytics data access allowed", st == 200 and d.get("allowed") is True and d.get("reason_code") == "ACTIVE_CONSENT", str(d))

        # 5. Withdrawal
        st, d = req("/consents", {"user_id": uid, "purpose": "Analytics", "action": "withdraw", "source": "test"})
        check(5, "Withdrawal flips consent state", st in (200, 201) and d.get("granted") is False and d.get("reason_code") == "CONSENT_WITHDRAWN", str(d))

        # 6. PEP blocked after withdrawal
        st, d = req("/data-access", {"user_id": uid, "purpose": "Analytics", "source": "test"})
        check(6, "Data access immediately blocked after withdrawal", st == 403 and d.get("reason_code") == "WITHDRAWN", str(d))

        # 7. Deny blocks marketing
        req("/consents", {"user_id": uid, "purpose": "Marketing", "action": "deny", "source": "test"})
        st, d = req("/data-access", {"user_id": uid, "purpose": "Marketing", "source": "test"})
        check(7, "Explicit deny blocks Marketing access", st == 403 and d.get("reason_code") == "DENIED", str(d))

        # 8. Service improvement blocked without consent
        st, d = req("/data-access", {"user_id": uid, "purpose": "Service Improvement", "source": "test"})
        check(8, "Purpose isolation: Service Improvement blocked without consent", st == 403 and d.get("reason_code") == "NO_CONSENT", str(d))

        # 9. Unregistered purpose strictly rejected
        st, d = req("/data-access", {"user_id": uid, "purpose": "Biometric Profiling", "source": "test"})
        check(9, "Unregistered purpose strictly rejected", st == 400 and d.get("reason_code") == "INVALID_PURPOSE", str(d))

        # 10. Invalid action verb rejected
        st, d = req("/consents", {"user_id": uid, "purpose": "Analytics", "action": "temporary_permit", "source": "test"})
        check(10, "Invalid action verb rejected", st == 400, str(d))

        # 11. User boundary isolation
        st, d = req("/data-access", {"user_id": uid + "-unauthorized", "purpose": "Analytics", "source": "test"})
        check(11, "User boundary isolation", st == 403 and d.get("reason_code") == "NO_CONSENT", str(d))

        # 12. Notice change causes NOTICE_MISMATCH
        req("/notice/reset", {"source": "test"})
        req("/consents", {"user_id": uid, "purpose": "Service Improvement", "action": "grant", "source": "test"})
        req("/notice/update", {"notice_version": "2.0", "source": "test"})
        st, d = req("/data-access", {"user_id": uid, "purpose": "Service Improvement", "source": "test"})
        check(12, "Notice change causes NOTICE_MISMATCH", st == 403 and d.get("reason_code") == "NOTICE_MISMATCH", str(d))

        # 13. Re-consent on updated notice v2.0 restores access
        req("/consents", {"user_id": uid, "purpose": "Service Improvement", "action": "grant", "source": "test"})
        st, d = req("/data-access", {"user_id": uid, "purpose": "Service Improvement", "source": "test"})
        check(13, "Re-consent on updated notice v2.0 restores access", st == 200 and d.get("allowed") is True, str(d))
        req("/notice/reset", {"source": "test"})

        # 14. Cryptographic hash chain is intact
        st, d = req("/audit/verify", method="GET")
        check(14, "Cryptographic hash chain is intact", st == 200 and d.get("status") == "intact", str(d))

    finally:
        req("/notice/reset", {"source": "test"})

    passed = sum(results)
    total = len(results)
    print(f"\nResult: {passed}/{total} Passed")
    return passed == total

if __name__ == "__main__":
    local_ok = test_14_checks("http://127.0.0.1:5001")
    cloud_ok = test_14_checks("https://consent-guard-2.vercel.app")
    if local_ok and cloud_ok:
        print("\n[PERFECT] ALL 14 LIFECYCLE CHECKS PASSED 100% ON BOTH LOCAL AND VERCEL!")
        sys.exit(0)
    else:
        print("\n[FAIL] Some lifecycle checks failed.")
        sys.exit(1)
