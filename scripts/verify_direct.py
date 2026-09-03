"""
Direct Verification Script for Mission 5 Part 4
-----------------------------------------------
Loads all findings from database, verifies recommendation population,
and executes finding approval via approve_finding API function.
"""

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.database import SessionLocal
from backend.models import Finding, FindingStatus, Subdomain, Scan
from backend.services.remediation_advisor import generate_recommendation
from backend.routers.findings import approve_finding
from backend.schemas import FindingApprovalRequest


def verify():
    print("================================================================================", flush=True)
    print("MISSION 5 PART 4 — DIRECT DATABASE & APPROVAL VERIFICATION", flush=True)
    print("================================================================================", flush=True)

    db = SessionLocal()

    # Query existing findings from DB
    findings = db.query(Finding).all()
    print(f"[+] Total Findings currently in Database: {len(findings)}", flush=True)

    if not findings:
        # Seed test scan, subdomain, and 4 findings matching different check patterns
        print("[+] Seeding 4 representative findings (Header, Git, SQLi, Fallback)...", flush=True)
        scan = Scan(target="http://localhost:3000", status="COMPLETED")
        db.add(scan)
        db.commit()
        db.refresh(scan)

        sub = Subdomain(scan_id=scan.id, hostname="localhost", ip_address="127.0.0.1")
        db.add(sub)
        db.commit()
        db.refresh(sub)

        sample_checks = [
            ("Missing Security Header: Content-Security-Policy", "MEDIUM", "CSP header missing in HTTP response"),
            ("Exposed Git Repository", "HIGH", ".git/HEAD accessible over HTTP GET"),
            ("SQL Injection in parameter id", "HIGH", "Boolean SQL injection vulnerability"),
            ("Unrecognized Custom Check XYZ", "LOW", "Custom check flag triggered"),
        ]

        for check_name, sev, ev in sample_checks:
            advice = generate_recommendation({"check_name": check_name, "severity": sev, "evidence": ev})
            f = Finding(
                subdomain_id=sub.id,
                check_name=check_name,
                severity=sev,
                evidence=ev,
                recommendation=advice.get("recommendation"),
                config_snippet=advice.get("config_snippet"),
                status=FindingStatus.OPEN.value,
            )
            db.add(f)
        db.commit()
        findings = db.query(Finding).filter(Finding.subdomain_id == sub.id).all()

    all_non_empty = True
    specific_matches = []
    fallback_matches = []

    for f in findings:
        rec = f.recommendation
        if not rec or not rec.strip():
            all_non_empty = False
            print(f"[FAIL]: Finding #{f.id} '{f.check_name}' has empty recommendation!", flush=True)
        else:
            if "Manual review recommended" in rec:
                fallback_matches.append(f)
            else:
                specific_matches.append(f)

    print(f"\n--- Recommendation Verification Audit ---", flush=True)
    print(f"  Every Finding Has Non-Empty Recommendation: {'[YES - ALL PASSED]' if all_non_empty else '[NO - FAILURES DETECTED]'}", flush=True)
    print(f"  Specific Pattern Mappings Matched:         {len(specific_matches)}", flush=True)
    print(f"  Generic Fallback Mappings Used:            {len(fallback_matches)}", flush=True)

    print("\nDetailed Findings Breakdown:", flush=True)
    for f in findings:
        is_fallback = "Manual review recommended" in (f.recommendation or "")
        tag = "[FALLBACK]" if is_fallback else "[SPECIFIC]"
        print(f"  - Finding #{f.id} {tag}: '{f.check_name}' ({f.severity})", flush=True)
        print(f"    Rec: {f.recommendation}", flush=True)
        if f.config_snippet:
            print(f"    Snippet: {f.config_snippet.splitlines()[0]}...", flush=True)

    # Approve finding #1 via API
    target_finding = findings[0]
    fid = target_finding.id
    print(f"\n[+] Approving Finding #{fid} ('{target_finding.check_name}') via API approval endpoint...", flush=True)

    req_body = FindingApprovalRequest(approved_by="auditor_sarah@nkat.ai")
    approve_finding(finding_id=fid, approval_in=req_body, db=db)

    # Re-query DB to confirm persistence
    db.expire_all()
    db_refreshed = db.query(Finding).filter(Finding.id == fid).first()

    print(f"  Database Verification:", flush=True)
    print(f"    ID:          #{db_refreshed.id}", flush=True)
    print(f"    Status:      {db_refreshed.status} (Expected: RESOLVED)", flush=True)
    print(f"    Approved By: {db_refreshed.approved_by}", flush=True)
    print(f"    Approved At: {db_refreshed.approved_at}", flush=True)

    assert db_refreshed.status == FindingStatus.RESOLVED.value, f"Status mismatch: {db_refreshed.status}"
    assert db_refreshed.approved_by == "auditor_sarah@nkat.ai", f"Approved_by mismatch: {db_refreshed.approved_by}"
    assert db_refreshed.approved_at is not None, "Approved_at timestamp is None!"

    print("\n[+] HUMAN APPROVAL WORKFLOW VERIFIED SUCCESSFULLY IN DATABASE!", flush=True)

    db.close()
    print("================================================================================", flush=True)

if __name__ == "__main__":
    verify()
