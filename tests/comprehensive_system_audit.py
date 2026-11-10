import urllib.request, urllib.parse, json, sys

def test_suite(base_url, is_cloud=False):
    print(f"\n========================================================")
    print(f" TESTING: {base_url} (Cloud: {is_cloud})")
    print(f"========================================================")

    session_cookie = None
    bearer_token = None
    passed = 0
    failed = 0

    def request(path, method='GET', data=None, headers=None):
        nonlocal session_cookie, bearer_token
        url = base_url + path
        hdrs = dict(headers or {})
        if bearer_token and 'Authorization' not in hdrs:
            hdrs['Authorization'] = f'Bearer {bearer_token}'
        if session_cookie and 'Cookie' not in hdrs:
            hdrs['Cookie'] = session_cookie

        body = None
        if data is not None:
            body = json.dumps(data).encode('utf-8')
            hdrs['Content-Type'] = 'application/json'

        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
                resp_body = resp.read().decode('utf-8')
                new_cookie = resp.headers.get('Set-Cookie')
                if new_cookie:
                    session_cookie = new_cookie.split(';')[0]
                try:
                    parsed = json.loads(resp_body)
                except Exception:
                    parsed = resp_body
                return status, parsed
        except urllib.error.HTTPError as e:
            err_body = e.read().decode('utf-8')
            try:
                parsed = json.loads(err_body)
            except Exception:
                parsed = err_body
            return e.code, parsed
        except Exception as e:
            return 0, str(e)

    def check(name, condition, details=""):
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"  [PASS] {name}")
        else:
            failed += 1
            print(f"  [FAIL] {name} - {details}")

    # 1. Health Endpoint
    st, res = request('/api/health')
    check("Health Check Returns 200", st == 200 and res.get('status') == 'ok', str(res))

    # 2. Public Notice & Purposes
    st, res = request('/api/notice')
    check("Notice Check Returns 200", st == 200 and 'notice_version' in res, str(res))
    current_ver = res.get('notice_version', '1.0') if isinstance(res, dict) else '1.0'

    st, res = request('/api/purposes')
    check("Purposes Check Returns 200", st == 200 and isinstance(res, list) and len(res) >= 3, str(res))

    # 3. Demo Login
    st, res = request('/api/auth/demo-login', method='POST', data={'user_id': 'demo-user'})
    check("Demo Login Success", st == 200 and 'token' in res, str(res))
    if isinstance(res, dict) and 'token' in res:
        bearer_token = res['token']

    # 4. Auth Me
    st, res = request('/api/auth/me')
    check("Auth Me Returns Current User", st == 200 and res.get('authenticated') is True and res.get('user', {}).get('id') == 'demo-user', str(res))

    # 5. Invalid Demo Account Rejection
    st, res = request('/api/auth/demo-login', method='POST', data={'user_id': 'malicious-hacker'})
    check("Invalid Demo Login Blocked with 400", st == 400, str(res))

    # 6. Grant All 3 Consents
    for p in ["Analytics", "Marketing", "Service Improvement"]:
        st, res = request('/api/consents', method='POST', data={'purpose': p, 'action': 'grant', 'source': 'user'})
        check(f"Grant {p} Consent Returns 201/200", st in (200, 201), str(res))

    # 7. Verify Consents
    st, res = request('/api/consents')
    core_purposes = {"Analytics", "Marketing", "Service Improvement"}
    granted_core = [r for r in res if r.get('purpose') in core_purposes and r.get('granted') == 1]
    check("All 3 Core Consents Granted in State", len(granted_core) == 3, str(res))

    # 8. Verify Stats
    st, res = request('/api/stats?user_id=demo-user')
    check("Stats Active Consents Equals 3", isinstance(res, dict) and res.get('active_consents') == 3, str(res))

    # 9. PEP Simulator: Granted Purpose
    st, res = request('/api/data-access', method='POST', data={'user_id': 'demo-user', 'purpose': 'Analytics'})
    check("PEP Allows Granted Access (HTTP 200)", st == 200 and res.get('allowed') is True, str(res))

    # 10. Withdraw Marketing Consent
    st, res = request('/api/consents', method='POST', data={'purpose': 'Marketing', 'action': 'withdraw', 'source': 'user'})
    check("Withdraw Marketing Consent Returns 201/200", st in (200, 201), str(res))

    # 11. PEP Simulator: Withdrawn Purpose
    st, res = request('/api/data-access', method='POST', data={'user_id': 'demo-user', 'purpose': 'Marketing'})
    check("PEP Blocks Withdrawn Access (HTTP 403)", st == 403 and res.get('allowed') is False, str(res))

    # 12. PEP Simulator: Invalid Purpose
    st, res = request('/api/data-access', method='POST', data={'user_id': 'demo-user', 'purpose': 'Malicious_Exfiltration'})
    check("PEP Blocks Unknown Purpose (HTTP 400)", st == 400, str(res))

    # 13. Re-grant Marketing
    st, res = request('/api/consents', method='POST', data={'purpose': 'Marketing', 'action': 'grant', 'source': 'user'})
    check("Re-grant Marketing Consent Returns 201/200", st in (200, 201), str(res))

    # 14. Notice Bump to v2.0
    st, res = request('/api/notice/update', method='POST', data={'notice_version': '2.0', 'source': 'user'})
    check("Bump Notice to v2.0 Returns 200", st == 200 and res.get('notice_version') == '2.0', str(res))

    # 15. Verify Outdated Notice Causes Needs Reconsent
    st, res = request('/api/consents')
    check("Consents Flag needs_reconsent after Bump", isinstance(res, list) and any(r.get('needs_reconsent') for r in res), str(res))

    # 16. PEP Simulator Blocks Access on Stale Consent
    st, res = request('/api/data-access', method='POST', data={'user_id': 'demo-user', 'purpose': 'Analytics'})
    check("PEP Blocks Stale Notice Access (HTTP 403)", st == 403 and res.get('allowed') is False, str(res))

    # 17. Re-consent under v2.0
    st, res = request('/api/consents', method='POST', data={'purpose': 'Analytics', 'action': 'grant', 'source': 'user'})
    check("Re-consent under v2.0 Returns 201/200", st in (200, 201), str(res))

    # 18. PEP Simulator Allows Access under v2.0
    st, res = request('/api/data-access', method='POST', data={'user_id': 'demo-user', 'purpose': 'Analytics'})
    check("PEP Allows Fresh v2.0 Access (HTTP 200)", st == 200 and res.get('allowed') is True, str(res))

    # 19. Notice Reset to v1.0
    st, res = request('/api/notice/reset', method='POST', data={'source': 'user'})
    check("Notice Reset to v1.0 Returns 200", st == 200 and res.get('notice_version') == '1.0', str(res))

    # 20. Re-grant All under v1.0
    for p in ["Analytics", "Marketing", "Service Improvement"]:
        request('/api/consents', method='POST', data={'purpose': p, 'action': 'grant', 'source': 'user'})

    # 21. Merkle DAG Ledger Verification
    st, res = request('/api/audit/verify')
    check("Audit Ledger DAG Verification Passes", st == 200 and res.get('status') == 'intact', str(res))

    # 22. Audit Log Retrieval
    st, res = request('/api/audit?limit=10')
    check("Audit Log Returns Array of Events", st == 200 and isinstance(res, list) and len(res) > 0, str(res))

    # 23. Audit Export CSV
    st, res = request('/api/audit/export?format=csv')
    check("Audit CSV Export Returns Text Content", st == 200 and isinstance(res, str) and ('created_at' in res or 'id' in res), f"Status: {st}")

    # 24. Cross-User Privacy Isolation: User 1 vs User 2
    # Login as user1
    st_u1, res_u1 = request('/api/auth/demo-login', method='POST', data={'user_id': 'user1'})
    if isinstance(res_u1, dict) and 'token' in res_u1:
        bearer_token = res_u1['token']

    # Attempt to read demo-user consents using user1's session
    st, res = request('/api/consents?user_id=demo-user')
    check("Cross-User Consent Access Forbidden (HTTP 403)", st == 403, str(res))

    # Attempt to read demo-user audit log using user1's session
    st, res = request('/api/audit?user_id=demo-user')
    check("Cross-User Audit Log Access Forbidden (HTTP 403)", st == 403, str(res))

    # Attempt to modify demo-user consent using user1's session
    st, res = request('/api/consents', method='POST', data={'user_id': 'demo-user', 'purpose': 'Analytics', 'action': 'withdraw'})
    check("Cross-User Consent Tampering Forbidden (HTTP 403)", st == 403, str(res))

    # Switch back to demo-user
    st_demo, res_demo = request('/api/auth/demo-login', method='POST', data={'user_id': 'demo-user'})
    if isinstance(res_demo, dict) and 'token' in res_demo:
        bearer_token = res_demo['token']

    print(f"\nRESULTS FOR {base_url}:")
    print(f"  Total Passed: {passed}")
    print(f"  Total Failed: {failed}")
    return failed == 0

if __name__ == '__main__':
    local_ok = test_suite('http://127.0.0.1:5001', is_cloud=False)
    cloud_ok = test_suite('https://consent-guard-2.vercel.app', is_cloud=True)

    if not local_ok or not cloud_ok:
        print("\n[WARNING] Some tests failed!")
        sys.exit(1)
    else:
        print("\n[SUCCESS] ALL INTEGRATION TESTS PASSED 100% ACROSS LOCAL AND VERCEL!")
        sys.exit(0)
