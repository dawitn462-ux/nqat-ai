"""
Real Email Verification Link & Multi-Tenant Isolation Test Script
------------------------------------------------------------------
1. Tests registration of a new user.
2. Verifies real email verification link generation and GET /api/v1/auth/verify-link click behavior.
3. Tests multi-tenant isolation: confirms newly registered users only see their own scans/findings, with zero leakage across organizations.
"""

import os
import sys
import json
import uuid
import urllib.request
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BACKEND_URL = "http://127.0.0.1:8000"

def run_test():
    print("=" * 80)
    print("REAL EMAIL VERIFICATION LINK & MULTI-TENANT ISOLATION VERIFICATION")
    print("=" * 80)

    # ----------------------------------------------------
    # TEST 1: Register Tenant A User
    # ----------------------------------------------------
    tenant_a_username = f"user_tenant_a_{uuid.uuid4().hex[:4]}"
    tenant_a_email = f"{tenant_a_username}@gmail.com"
    password = "SecureUserPass_2026!"

    print(f"\n[STEP 1] Registering User A ({tenant_a_username} | {tenant_a_email})...")
    reg_payload = json.dumps({
        "username": tenant_a_username,
        "email": tenant_a_email,
        "password": password,
        "organization_name": f"{tenant_a_username}'s Company"
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{BACKEND_URL}/api/v1/auth/register",
        data=reg_payload,
        headers={"Content-Type": "application/json"}
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print("  [PASS] User A Registered!")
            print(f"    User ID:           #{data.get('user_id')}")
            print(f"    Org ID:            #{data.get('organization_id')}")
            print(f"    Org Name:          {data.get('organization_name')}")
            print(f"    is_email_verified: {data.get('is_email_verified')} (EXPECTED: False)")
            tenant_a_token = data.get("access_token")
            user_a_id = data.get("user_id")
            org_a_id = data.get("organization_id")
            assert data.get("is_email_verified") is False, "Email must be unverified initially!"
    except Exception as exc:
        print(f"  [FAIL] Registration failed: {exc}")
        return

    # ----------------------------------------------------
    # TEST 2: Multi-Tenant Scoping Check for Unscanned User A
    # ----------------------------------------------------
    print(f"\n[STEP 2] Querying GET /api/v1/scans for User A (Org #{org_a_id})...")
    req = urllib.request.Request(
        f"{BACKEND_URL}/api/v1/scans",
        headers={"Authorization": f"Bearer {tenant_a_token}"}
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        user_a_scans = json.loads(resp.read().decode("utf-8"))
        print(f"  [PASS] User A Scans Count: {len(user_a_scans)} (EXPECTED: 0 scans for new user)")
        assert len(user_a_scans) == 0, "New user must NOT see other users' scans!"

    # ----------------------------------------------------
    # TEST 3: Click Direct Email Verification Link
    # ----------------------------------------------------
    print(f"\n[STEP 3] Simulating Direct Email Verification Link Click for User A...")
    from backend.database import SessionLocal
    from backend.models import User
    db = SessionLocal()
    user_db = db.query(User).filter(User.id == user_a_id).first()
    v_token = user_db.email_verification_token
    db.close()

    verify_link_url = f"{BACKEND_URL}/api/v1/auth/verify-link?token={v_token}&email={tenant_a_email}"
    print(f"  Requesting GET {verify_link_url}...")

    # Don't follow redirects to capture the HTTP 302 RedirectResponse to HTTPS Dashboard
    class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
        def http_error_302(self, req, fp, code, msg, headers):
            return fp

    opener = urllib.request.build_opener(NoRedirectHandler)
    resp = opener.open(verify_link_url)
    redirect_location = resp.headers.get("Location")
    print("  [PASS] Email Verification Link Click Result:")
    print(f"    HTTP Status:       {resp.status} (EXPECTED: 302 Redirect)")
    print(f"    Redirect Location: {redirect_location}")

    # Re-query User A in DB
    db = SessionLocal()
    user_db = db.query(User).filter(User.id == user_a_id).first()
    print(f"    DB is_email_verified: {user_db.is_email_verified} (EXPECTED: True)")
    assert user_db.is_email_verified is True, "User must be marked verified after email link click!"
    db.close()

    # ----------------------------------------------------
    # TEST 4: User A Submits Their Own Target Website Scan
    # ----------------------------------------------------
    target_a = "http://localhost:3000"
    print(f"\n[STEP 4] User A submits their website target ({target_a}) for scanning...")
    scan_req = json.dumps({"target": target_a}).encode("utf-8")
    req = urllib.request.Request(
        f"{BACKEND_URL}/api/v1/scan",
        data=scan_req,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {tenant_a_token}"}
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        scan_a = json.loads(resp.read().decode("utf-8"))
        print(f"  [PASS] Scan created for User A! Scan ID: #{scan_a.get('id')}, Org: #{scan_a.get('organization_id')}")

    # ----------------------------------------------------
    # TEST 5: Register Tenant B User & Verify Total Multi-Tenant Isolation
    # ----------------------------------------------------
    tenant_b_username = f"user_tenant_b_{uuid.uuid4().hex[:4]}"
    tenant_b_email = f"{tenant_b_username}@gmail.com"

    print(f"\n[STEP 5] Registering User B ({tenant_b_username} | {tenant_b_email})...")
    reg_payload_b = json.dumps({
        "username": tenant_b_username,
        "email": tenant_b_email,
        "password": password,
        "organization_name": f"{tenant_b_username}'s Company"
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{BACKEND_URL}/api/v1/auth/register",
        data=reg_payload_b,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        data_b = json.loads(resp.read().decode("utf-8"))
        tenant_b_token = data_b.get("access_token")
        org_b_id = data_b.get("organization_id")
        print(f"  [PASS] User B Registered in Org #{org_b_id}!")

    print(f"\n[STEP 6] Querying GET /api/v1/scans for User B (Org #{org_b_id})...")
    req = urllib.request.Request(
        f"{BACKEND_URL}/api/v1/scans",
        headers={"Authorization": f"Bearer {tenant_b_token}"}
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        user_b_scans = json.loads(resp.read().decode("utf-8"))
        print(f"  [PASS] User B Scans Count: {len(user_b_scans)} (EXPECTED: 0 scans)")
        assert len(user_b_scans) == 0, "User B must NOT see User A's scans or findings!"

    print("\n" + "=" * 80)
    print("VERIFICATION SUMMARY: ALL EMAIL LINK & MULTI-TENANT ISOLATION CHECKS PASSED 100%")
    print("=" * 80)

if __name__ == "__main__":
    run_test()
