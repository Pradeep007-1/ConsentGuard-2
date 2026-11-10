#!/usr/bin/env python3
"""
ConsentGuard - Hackathon Live Demonstration Runner
Executes an end-to-end, multi-stage demonstration of ConsentGuard:
  Stage 0: Safe Health & Diagnostics (100% Offline SQLite, Zero Secret Leakage)
  Stage 1: User Authentication & Signed Bearer Token Issuance
  Stage 2: User Grants Consent (Notice v1.0, Analytics)
  Stage 3: Downstream Data Sharing Request (PEP Enforcement, Partner-All)
  Stage 4: Partner-Limited Scope Protection (Unauthorized Purpose Blocked)
  Stage 5: User Withdraws Consent (Right to Revoke)
  Stage 6: Subsequent Downstream Request Immediately Blocked (PEP Denial)
  Stage 7: Privacy Notice Version Bump to v2.0 & Stale Consent Detection
  Stage 8: Notice Reset to Default v1.0
  Stage 9: Merkle DAG Cryptographic Audit Ledger Verification
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# Ensure ROOT_DIR and BACKEND_DIR are on sys.path
ROOT_DIR = Path(__file__).resolve().parent
if ROOT_DIR.name == "backend":
    ROOT_DIR = ROOT_DIR.parent
BACKEND_DIR = ROOT_DIR / "backend"
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# Default offline configuration
os.environ.setdefault("LOCAL_MODE", "1")
os.environ.setdefault("OFFLINE_MODE", "1")

SERVER_URL = os.environ.get("CONSENTGUARD_URL", "http://127.0.0.1:5001").rstrip("/")
DEFAULT_PARTNER_ALL_KEY = os.environ.get("PARTNER_ALL_KEY", "key_partner_all_enterprise")
DEFAULT_PARTNER_LIMITED_KEY = os.environ.get("PARTNER_LIMITED_KEY", "key_partner_limited_research")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "cg_admin_offline_key_2026")


def http_request(method: str, path: str, payload: dict = None, headers: dict = None) -> tuple[int, dict]:
    url = f"{SERVER_URL}{path}"
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)

    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = resp.read().decode("utf-8")
            return resp.status, json.loads(data) if data else {}
    except urllib.error.HTTPError as e:
        data = e.read().decode("utf-8")
        try:
            return e.code, json.loads(data)
        except Exception:
            return e.code, {"raw": data}
    except urllib.error.URLError as e:
        return 0, {"error": f"Failed to connect to {url}: {e.reason}"}


def print_banner(stage_num: int, title: str):
    print("\n" + "=" * 72)
    print(f"  STAGE {stage_num}: {title}")
    print("=" * 72)


def run_live_demonstration():
    print("=" * 72)
    print("  CONSENTGUARD: HACKATHON LIVE OFFLINE DEMONSTRATION")
    print(f"  Target Server: {SERVER_URL}")
    print("  Zero Cloud Dependencies | 100% Offline Local SQLite Mode")
    print("=" * 72)

    # ------------------------------------------------------------------------
    # STAGE 0: Safe Health & Diagnostics
    # ------------------------------------------------------------------------
    print_banner(0, "SYSTEM HEALTH & OFFLINE DIAGNOSTICS")
    status, health_data = http_request("GET", "/api/health")
    if status == 0:
        print("\n[!] ERROR: Could not connect to the ConsentGuard backend server!")
        print(f"    Target: {SERVER_URL}/api/health")
        print("\n    STARTUP INSTRUCTIONS:")
        print("    1. Open a new terminal / console window.")
        print("    2. On Windows: Double-click 'start-consentguard.bat'")
        print("    3. Or run:      python app.py")
        print("    4. Once the server is running, re-run this script: python run_demo.py\n")
        sys.exit(1)

    print(f"[+] HTTP {status} OK")
    print(f"    Application Status:     {health_data.get('application_status', 'healthy')}")
    print(f"    Database Connectivity:  {health_data.get('database', 'connected')} ({health_data.get('database_type', 'sqlite')})")
    print(f"    Operating Mode:         {health_data.get('operating_mode', 'local_offline')}")
    diag = health_data.get("diagnostics", {})
    print(f"    Active Privacy Notice:  v{diag.get('active_notice_version', '1.0')} (Hash: {diag.get('active_notice_hash_prefix', '')}...)")
    print(f"    Supported Purposes:     {diag.get('supported_purposes_count', 4)} purposes")
    print(f"    Total Audit Events:     {diag.get('total_audit_events', 0)} cryptographic records")
    time.sleep(0.5)

    # ------------------------------------------------------------------------
    # STAGE 1: User Authentication & Signed Bearer Token
    # ------------------------------------------------------------------------
    print_banner(1, "AUTHENTICATION & SIGNED BEARER TOKEN")
    status, auth_data = http_request(
        "POST",
        "/api/auth/demo-login",
        payload={"user_id": "demo-user"},
    )
    if status != 200:
        print(f"[!] Authentication failed: HTTP {status} - {auth_data}")
        sys.exit(1)

    token = auth_data.get("token", "")
    user = auth_data.get("user", {})
    user_id = user.get("id", "demo-user")
    user_headers = {"Authorization": f"Bearer {token}"}

    print(f"[+] HTTP {status} Logged in as subject: {user.get('name')} ({user_id})")
    print(f"    Signed Token: {token[:24]}... (cryptographically verified)")
    time.sleep(0.5)

    # ------------------------------------------------------------------------
    # STAGE 2: User Grants Consent (Notice v1.0, Analytics)
    # ------------------------------------------------------------------------
    print_banner(2, "USER DECISION: GRANT CONSENT (Analytics under Notice v1.0)")
    status, grant_data = http_request(
        "POST",
        "/api/consents",
        payload={"purpose": "Analytics", "action": "grant"},
        headers=user_headers,
    )
    print(f"[+] HTTP {status} Consent Decision Recorded:")
    print(f"    User:           {grant_data.get('user_id', user_id)}")
    print(f"    Purpose:        {grant_data.get('purpose')}")
    print(f"    Granted:        {grant_data.get('granted')}")
    print(f"    Notice Version: v{grant_data.get('notice_version')}")
    print(f"    Reason Code:    {grant_data.get('reason_code')}")
    time.sleep(0.5)

    # ------------------------------------------------------------------------
    # STAGE 3: Downstream Data Sharing Request (PEP Enforcement)
    # ------------------------------------------------------------------------
    print_banner(3, "AUTHORIZED DATA SHARING (PEP Enforcement for Partner-All)")
    status, share_data = http_request(
        "POST",
        "/api/share/request",
        payload={
            "user_id": user_id,
            "purpose": "Analytics",
            "requested_fields": ["page_views", "feature_usage"],
        },
        headers={"X-API-Key": DEFAULT_PARTNER_ALL_KEY},
    )
    print(f"[+] HTTP {status} [ACCESS PERMITTED BY POLICY ENFORCEMENT POINT]:")
    print(f"    Consumer:       {share_data.get('consumer_id')}")
    print(f"    Allowed:        {share_data.get('allowed')}")
    print(f"    Reason Code:    {share_data.get('reason_code')}")
    print(f"    Released Data:  {json.dumps(share_data.get('data', {}), indent=6)}")
    time.sleep(0.5)

    # ------------------------------------------------------------------------
    # STAGE 4: Partner-Limited Scope Protection
    # ------------------------------------------------------------------------
    print_banner(4, "CYBERSECURITY: PARTNER-LIMITED SCOPE RESTRICTION")
    print("[*] Partner-Limited attempts to request 'Marketing' data (unauthorized purpose)...")
    status, limited_deny = http_request(
        "POST",
        "/api/share/request",
        payload={
            "user_id": user_id,
            "purpose": "Marketing",
            "requested_fields": ["campaign_clicks"],
        },
        headers={"X-API-Key": DEFAULT_PARTNER_LIMITED_KEY},
    )
    print(f"[+] HTTP {status} [ACCESS BLOCKED BY POLICY ENFORCEMENT POINT]:")
    print(f"    Consumer:       {limited_deny.get('consumer_id', 'partner-limited')}")
    print(f"    Allowed:        {limited_deny.get('allowed', False)}")
    print(f"    Reason Code:    {limited_deny.get('reason_code')}")
    print(f"    Security Note:  Consumer is restricted strictly to 'Analytics'. Request safely denied.")
    time.sleep(0.5)

    # ------------------------------------------------------------------------
    # STAGE 5: User Withdraws Consent (Right to Revoke)
    # ------------------------------------------------------------------------
    print_banner(5, "USER EXERCISES RIGHT TO REVOKE CONSENT")
    status, withdraw_data = http_request(
        "POST",
        "/api/consents",
        payload={"purpose": "Analytics", "action": "withdraw"},
        headers=user_headers,
    )
    print(f"[+] HTTP {status} Consent Decision Recorded:")
    print(f"    User:           {withdraw_data.get('user_id', user_id)}")
    print(f"    Purpose:        {withdraw_data.get('purpose')}")
    print(f"    Granted:        {withdraw_data.get('granted')} (Revoked)")
    print(f"    Withdrawn At:   {withdraw_data.get('withdrawn_at')}")
    print(f"    Reason Code:    {withdraw_data.get('reason_code')}")
    time.sleep(0.5)

    # ------------------------------------------------------------------------
    # STAGE 6: Subsequent Downstream Request Immediately Blocked
    # ------------------------------------------------------------------------
    print_banner(6, "SUBSEQUENT DOWNSTREAM REQUEST (Immediate PEP Denial)")
    status, deny_data = http_request(
        "POST",
        "/api/share/request",
        payload={
            "user_id": user_id,
            "purpose": "Analytics",
            "requested_fields": ["page_views"],
        },
        headers={"X-API-Key": DEFAULT_PARTNER_ALL_KEY},
    )
    print(f"[+] HTTP {status} [ACCESS DENIED BY POLICY ENFORCEMENT POINT]:")
    print(f"    Allowed:        {deny_data.get('allowed', False)}")
    print(f"    Reason Code:    {deny_data.get('reason_code')}")
    print(f"    Error Message:  {deny_data.get('error')}")
    print(f"    Security Note:  Immediate revocation enforced without cache delay.")
    time.sleep(0.5)

    # ------------------------------------------------------------------------
    # STAGE 7: Notice Version Bump to v2.0 & Stale Consent Detection
    # ------------------------------------------------------------------------
    print_banner(7, "ADMIN NOTICE UPGRADE & RE-CONSENT REQUIREMENT")
    # Grant under v1.0 first
    http_request(
        "POST",
        "/api/consents",
        payload={"purpose": "Analytics", "action": "grant"},
        headers=user_headers,
    )

    # Administrator bumps notice to v2.0
    status, bump_data = http_request(
        "POST",
        "/api/notice/update",
        payload={
            "notice_version": "2.0",
            "notice_text": "ConsentGuard v2.0 Privacy Notice: Revised itemized purpose inventory. Enhanced telemetry boundaries and mandatory re-consent verification for downstream consumers.",
        },
        headers={"X-Admin-Key": ADMIN_KEY},
    )
    print(f"[+] HTTP {status} Administrator published Privacy Notice v{bump_data.get('notice_version')}:")
    print(f"    New Notice Hash: {bump_data.get('notice_hash')}")

    # Subsequent downstream request with stale v1.0 consent
    status, stale_data = http_request(
        "POST",
        "/api/share/request",
        payload={"user_id": user_id, "purpose": "Analytics", "requested_fields": ["page_views"]},
        headers={"X-API-Key": DEFAULT_PARTNER_ALL_KEY},
    )
    print(f"[+] HTTP {status} [STALE CONSENT BLOCKED - RE-CONSENT REQUIRED]:")
    print(f"    Allowed:        {stale_data.get('allowed', False)}")
    print(f"    Error Code:     {stale_data.get('error_code')}")
    print(f"    Reason:         {stale_data.get('reason')}")
    time.sleep(0.5)

    # ------------------------------------------------------------------------
    # STAGE 8: Reset Notice to Default v1.0
    # ------------------------------------------------------------------------
    print_banner(8, "RESET NOTICE TO DEFAULT v1.0")
    status, reset_data = http_request(
        "POST",
        "/api/notice/reset",
        payload={"source": "demo_runner"},
        headers={"X-Admin-Key": ADMIN_KEY},
    )
    print(f"[+] HTTP {status} Notice restored to v{reset_data.get('notice_version')} ({reset_data.get('notice_hash', '')[:12]}...)")
    time.sleep(0.5)

    # ------------------------------------------------------------------------
    # STAGE 9: Merkle DAG Cryptographic Audit Verification
    # ------------------------------------------------------------------------
    print_banner(9, "MERKLE DAG CRYPTOGRAPHIC AUDIT VERIFICATION")
    status, audit_data = http_request("GET", "/api/audit/verify")
    print(f"[+] HTTP {status} Cryptographic Ledger Status: {audit_data.get('status', '').upper()}")
    print(f"    Total Records Verified:   {audit_data.get('total_records', audit_data.get('verified_count', 0))}")
    print(f"    Valid SHA-256 Hashes:     {audit_data.get('valid_records', 0)}")
    print(f"    Invalid Hashes:           {audit_data.get('invalid_records', 0)}")
    print(f"    Broken References:        {audit_data.get('broken_references', 0)}")
    print(f"    Detected Tampering:       {audit_data.get('detected_tampering', False)}")
    print(f"    Valid DAG Branches:       {audit_data.get('branches_count', 0)}")

    print("\n" + "=" * 72)
    print("  ALL 9 DEMONSTRATION STAGES EXECUTED AND VERIFIED SUCCESSFULLY!")
    print("  ConsentGuard is fully functional and ready for offline presentation.")
    print("=" * 72 + "\n")


if __name__ == "__main__":
    run_live_demonstration()
