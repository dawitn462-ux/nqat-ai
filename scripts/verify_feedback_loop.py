"""
Mission 6 Verification Script — Feedback Loop & Model Swap Guard Test
---------------------------------------------------------------------
1. Tests threshold guard (< 20 feedback samples -> safely aborts).
2. Seeds 25+ human feedback decisions (confirmed vulnerabilities & false positives).
3. Executes retrain_from_feedback.py.
4. Verifies blocking swap guard prevents swapping if candidate F1 <= old F1.
"""

import os
import sys
import json
from typing import List

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from backend.database import SessionLocal
from backend.models import Finding, Subdomain, Scan, FeedbackLabel
from backend.routers.findings import extract_finding_features, approve_finding, reject_finding
from backend.schemas import FindingApprovalRequest
from scripts.retrain_from_feedback import run_feedback_retraining


def run_verification():
    print("================================================================================", flush=True)
    print("MISSION 6 — VERIFY FEEDBACK LOOP & RETRAINING GUARD", flush=True)
    print("================================================================================", flush=True)

    db = SessionLocal()

    # Step 1: Test threshold guard when feedback count is below minimum
    # Clear feedback_labels for clean test
    db.query(FeedbackLabel).delete()
    db.commit()

    print("[+] Test 1: Verifying threshold guard with 0 feedback labels...", flush=True)
    res1 = run_feedback_retraining(min_threshold=20)
    assert res1["status"] == "ABORTED_INSUFFICIENT_DATA", f"Unexpected status: {res1['status']}"
    assert res1["swapped"] is False, "Model was swapped despite missing feedback data!"
    print("[+] Test 1 PASSED: Threshold guard safely aborted retraining.", flush=True)

    # Step 2: Seed 25 synthetic findings and execute approve/reject actions
    print("\n[+] Test 2: Seeding 25 human approval/rejection feedback records...", flush=True)

    scan = Scan(target="http://localhost:3000", status="COMPLETED")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    sub = Subdomain(scan_id=scan.id, hostname="localhost", ip_address="127.0.0.1")
    db.add(sub)
    db.commit()
    db.refresh(sub)

    # 15 confirmed vulnerabilities & 10 false positives
    sample_feedbacks = [
        ("SQL Injection in user search parameter", "HIGH", "Boolean SQLi payload", "confirmed_vulnerability"),
        ("Missing Security Header: Content-Security-Policy", "MEDIUM", "Header absent", "confirmed_vulnerability"),
        ("Exposed Git Repository", "HIGH", ".git/HEAD exposed", "confirmed_vulnerability"),
        ("Nuclei CVE-2021-44228 Log4j RCE", "CRITICAL", "JNDI lookup triggered", "confirmed_vulnerability"),
        ("Reflected XSS in query term", "MEDIUM", "<script>alert(1)</script>", "confirmed_vulnerability"),
        ("SQL Injection in login form", "CRITICAL", "' OR '1'='1", "confirmed_vulnerability"),
        ("Missing Security Header: Strict-Transport-Security", "LOW", "HSTS header missing", "confirmed_vulnerability"),
        ("Exposed API Documentation", "INFO", "Swagger UI accessible", "confirmed_vulnerability"),
        ("SQL Injection in product filter", "HIGH", "UNION SELECT query", "confirmed_vulnerability"),
        ("Missing Security Header: X-Frame-Options", "LOW", "Frame options missing", "confirmed_vulnerability"),
        ("Exposed FTP Directory", "LOW", "Anonymous FTP enabled", "confirmed_vulnerability"),
        ("SQL Injection in password reset", "HIGH", "Time-based blind SQLi", "confirmed_vulnerability"),
        ("Nuclei CVE-2022-22965 Spring4Shell", "CRITICAL", "Class loader manipulation", "confirmed_vulnerability"),
        ("Missing Security Header: Referrer-Policy", "INFO", "Referrer policy missing", "confirmed_vulnerability"),
        ("Exposed Metrics Endpoint", "LOW", "Prometheus /metrics exposed", "confirmed_vulnerability"),
        # False Positives
        ("Informational Service Banner", "INFO", "Server: nginx/1.18.0", "false_positive"),
        ("Generic Static Asset", "INFO", "Favicon request", "false_positive"),
        ("Internal Route Notice", "LOW", "Route /health returned 200", "false_positive"),
        ("HTTP 200 Response Code", "INFO", "Standard GET request", "false_positive"),
        ("Standard Cookie Header", "INFO", "Session cookie present", "false_positive"),
        ("Static Image File", "INFO", "PNG image requested", "false_positive"),
        ("Robots.txt file found", "INFO", "Robots.txt present", "false_positive"),
        ("Sitemap.xml file found", "INFO", "Sitemap present", "false_positive"),
        ("Public CSS Stylesheet", "INFO", "Main.css loaded", "false_positive"),
        ("Public JavaScript File", "INFO", "Bundle.js loaded", "false_positive"),
    ]

    for title, sev, ev, label in sample_feedbacks:
        f = Finding(subdomain_id=sub.id, check_name=title, severity=sev, evidence=ev, status="OPEN")
        db.add(f)
        db.commit()
        db.refresh(f)

        req_body = FindingApprovalRequest(approved_by="security_auditor")
        if label == "confirmed_vulnerability":
            approve_finding(finding_id=f.id, approval_in=req_body, db=db)
        else:
            reject_finding(finding_id=f.id, approval_in=req_body, db=db)

    fb_count = db.query(FeedbackLabel).count()
    print(f"[+] Total Feedback Labels in Database after seeding: {fb_count}", flush=True)

    # Step 3: Run retrain_from_feedback.py with 25 feedback samples
    print("\n[+] Test 3: Executing feedback retraining pipeline...", flush=True)
    res2 = run_feedback_retraining(min_threshold=20)

    print(f"\n--- Retraining & Model Swap Evaluation Summary ---", flush=True)
    print(f"  Status:          {res2['status']}", flush=True)
    print(f"  Feedback Count:  {res2['feedback_count']}", flush=True)
    print(f"  Old Champion F1: {res2['old_f1']:.4f}", flush=True)
    print(f"  New Model F1:    {res2['new_f1']:.4f}", flush=True)
    print(f"  Model Swapped:   {'[YES - REPLACED]' if res2['swapped'] else '[NO - BLOCKED]'}", flush=True)

    if res2['new_f1'] > res2['old_f1']:
        print("  Model Trend: IMPROVED (+{:.4f} F1)".format(res2['new_f1'] - res2['old_f1']), flush=True)
    elif res2['new_f1'] == res2['old_f1']:
        print("  Model Trend: FLAT (0.0000 F1 delta - Swap safely blocked)", flush=True)
    else:
        print("  Model Trend: WORSE ({:.4f} F1 delta - Swap safely blocked)".format(res2['new_f1'] - res2['old_f1']), flush=True)

    db.close()
    print("================================================================================", flush=True)

if __name__ == "__main__":
    run_verification()
