"""
User Registration & DB Recording Test Script
---------------------------------------------
Registers a new test user account via POST /api/v1/auth/register,
verifies that:
1. User record is written to 'users' DB table.
2. Activity log entry is written to 'platform_activity_logs' DB table.
3. User appears on GET /api/v1/admin/users.
"""

import os
import sys
import json
import random
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE_URL = "http://127.0.0.1:8000"


def run_reg_test():
    print("=" * 70)
    print("USER REGISTRATION & DATABASE RECORDING TEST")
    print("=" * 70)

    rand_id = random.randint(1000, 9999)
    test_username = f"sec_analyst_{rand_id}"
    test_email = f"sec_analyst_{rand_id}@company.com"
    test_password = "SecurePassword2026!"

    # 1. Register new user
    reg_url = f"{BASE_URL}/api/v1/auth/register"
    payload = json.dumps({
        "username": test_username,
        "email": test_email,
        "password": test_password,
        "organization_name": "Acme Cybersecurity"
    }).encode("utf-8")

    print(f"[STEP 1] Registering new user account '{test_username}' via POST {reg_url}...")
    req = urllib.request.Request(reg_url, data=payload, headers={"Content-Type": "application/json"})
    reg_resp = None
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            reg_resp = json.loads(resp.read().decode("utf-8"))
            print(f"  [SUCCESS] Account Registered!")
            print(f"  User ID:         #{reg_resp.get('user_id')}")
            print(f"  Username:        {reg_resp.get('username')}")
            print(f"  Email:           {reg_resp.get('email')}")
            print(f"  Role:            {reg_resp.get('role')}")
            print(f"  Organization:    {reg_resp.get('organization_name')}\n")
    except Exception as exc:
        print(f"  [ERROR] Registration failed: {exc}")
        return

    user_id = reg_resp.get("user_id")

    # 2. Check SQLite Database Record directly
    print("[STEP 2] Verifying User Record in SQLite Database Table 'users'...")
    from backend.database import SessionLocal
    from backend.models import User, PlatformActivityLog

    db = SessionLocal()
    try:
        db_user = db.query(User).filter(User.id == user_id).first()
        if db_user:
            print("  [PASS] User Record verified directly in SQLite 'users' table!")
            print(f"    DB ID:          #{db_user.id}")
            print(f"    DB Username:    {db_user.username}")
            print(f"    DB Email:       {db_user.email}")
            print(f"    DB Created At:  {db_user.created_at}")
            has_db_user = True
        else:
            print("  [FAIL] User record NOT found in 'users' table.")
            has_db_user = False

        # Check Activity Log
        act = db.query(PlatformActivityLog).filter(
            PlatformActivityLog.user_id == user_id,
            PlatformActivityLog.action_type == "USER_REGISTER"
        ).first()

        if act:
            print("\n  [PASS] Registration Activity Log verified in 'platform_activity_logs' table!")
            print(f"    Log Action:     {act.action_type}")
            print(f"    Log Target:     {act.target_resource}")
            print(f"    Log Details:    {act.details}")
            has_act_log = True
        else:
            print("  [FAIL] Activity log entry NOT found.")
            has_act_log = False

    finally:
        db.close()

    # 3. Check Admin Users API
    print("\n[STEP 3] Verifying User Appears on Admin Users API (GET /api/v1/admin/users)...")
    users_url = f"{BASE_URL}/api/v1/admin/users"
    try:
        req = urllib.request.Request(users_url, headers={"X-API-Key": "nkat_secret_api_key_2026"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            users_list = json.loads(resp.read().decode("utf-8"))
            found = any(u.get("id") == user_id for u in users_list)
            print(f"    Total Users Count in DB: {len(users_list)}")
            print(f"    New User Found on Admin View: {'[PASS] YES' if found else '[FAIL] NO'}")
            has_admin_user = found
    except Exception as exc:
        print(f"    [ERROR] {exc}")
        has_admin_user = False

    all_pass = has_db_user and has_act_log and has_admin_user

    print("\n" + "=" * 70)
    print("USER REGISTRATION DATABASE VERIFICATION SUMMARY")
    print("=" * 70)
    print(f"Recorded in 'users' DB Table:      {'[PASS]' if has_db_user else '[FAIL]'}")
    print(f"Recorded in Activity Log Table:     {'[PASS]' if has_act_log else '[FAIL]'}")
    print(f"Visible in Admin User Management:  {'[PASS]' if has_admin_user else '[FAIL]'}")
    print(f"Overall Result:                    {'[PASS] ALL REGISTRATION DB CHECKS PASSED' if all_pass else '[FAIL] VERIFICATION FAILED'}")
    print("=" * 70)

if __name__ == "__main__":
    run_reg_test()
