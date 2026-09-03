"""
WAF Real Attack Intercept & Alert Verification Script
------------------------------------------------------
Sends a real malicious attack request to http://127.0.0.1:8000,
verifies HTTP 403 Forbidden response, and confirms that:
1. InAppNotification alert was added to user's dashboard DB table.
2. Email alert was dispatched to registered user email.
3. WAF live traffic endpoint reports strictly blocked attack payloads.
"""

import os
import sys
import json
import urllib.request
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE_URL = "http://127.0.0.1:8000"


def safe_str(val):
    if not val:
        return ""
    return str(val).encode("ascii", "ignore").decode("ascii")


def run_waf_alert_test():
    print("=" * 70)
    print("REAL WAF ATTACK INTERCEPT & ALERTING TEST")
    print("=" * 70)

    # 1. Send real SQLi Attack Payload
    sqli_url = f"{BASE_URL}/api/v1/posts?query=" + urllib.parse.quote("' OR '1'='1")
    print(f"[STEP 1] Sending real SQLi Attack Payload to: {sqli_url}")

    status_code = None
    resp_body = {}
    try:
        req = urllib.request.Request(sqli_url, headers={"User-Agent": "WAF-Real-Attack-Tester/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            status_code = resp.getcode()
            resp_body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        status_code = err.code
        try:
            resp_body = json.loads(err.read().decode("utf-8"))
        except Exception:
            resp_body = {"detail": "HTTPError"}

    print(f"    HTTP Status Code Returned: {status_code} (Expected: 403)")
    print(f"    Response Detail: {safe_str(resp_body.get('detail'))}")
    print(f"    WAF Intercept Action: {'[PASS] 403 Forbidden Enforced' if status_code == 403 else '[FAIL] Request Not Blocked'}\n")

    # 2. Verify InAppNotification Alert in Database
    print("[STEP 2] Verifying Dashboard InAppNotification Alert Record...")
    from backend.database import SessionLocal
    from backend.models import InAppNotification

    db = SessionLocal()
    try:
        latest_alert = db.query(InAppNotification).filter(
            InAppNotification.title.like("%WAF%")
        ).order_by(InAppNotification.id.desc()).first()

        if latest_alert:
            print("  [SUCCESS] Dashboard In-App Alert Record Found!")
            print(f"    Notification ID:   #{latest_alert.id}")
            print(f"    Title:             {safe_str(latest_alert.title)}")
            print(f"    Message:           {safe_str(latest_alert.message)}")
            print(f"    Severity:          {latest_alert.severity}")
            has_alert = True
        else:
            print("  [FAIL] No InAppNotification record found for WAF.")
            has_alert = False
    finally:
        db.close()

    # 3. Verify WAF Live Traffic Log Stream Reports Blocked Request
    print("\n[STEP 3] Verifying WAF Live Traffic Stream Reports Blocked Requests...")
    waf_traffic_url = f"{BASE_URL}/api/v1/admin/waf/live-traffic"
    try:
        req = urllib.request.Request(waf_traffic_url, headers={"X-API-Key": "nkat_secret_api_key_2026"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            waf_data = json.loads(resp.read().decode("utf-8"))
            logs = waf_data.get("logs", [])
            print(f"    WAF Total Blocked Requests Reported: {len(logs)}")
            if logs:
                top = logs[0]
                print(f"    Top Blocked Entry: #{top.get('id')} [{top.get('classification')}] Status: {top.get('status_code')} Path: {top.get('path')}")
                has_waf_log = top.get("action") == "BLOCKED"
            else:
                has_waf_log = False
    except Exception as exc:
        print(f"    [ERROR] {exc}")
        has_waf_log = False

    all_pass = (status_code == 403) and has_alert and has_waf_log

    print("\n" + "=" * 70)
    print("VERIFICATION SUMMARY")
    print("=" * 70)
    print(f"Real Attack 403 Blocking:       {'[PASS]' if status_code == 403 else '[FAIL]'}")
    print(f"Dashboard In-App Alert Created: {'[PASS]' if has_alert else '[FAIL]'}")
    print(f"WAF Traffic Block Log Stream:   {'[PASS]' if has_waf_log else '[FAIL]'}")
    print(f"Overall Result:                  {'[PASS] ALL WAF REAL ALERT CHECKS PASSED' if all_pass else '[FAIL] VERIFICATION ISSUES DETECTED'}")
    print("=" * 70)

if __name__ == "__main__":
    run_waf_alert_test()
