"""
Mission 5 Part 4 Verification Script — Full Scan & Human Approval Workflow
--------------------------------------------------------------------------
1. Runs full background scan pipeline.
2. Queries database findings and verifies every finding has a non-empty recommendation.
3. Identifies specific vs fallback recommendation mappings.
4. Approves finding via API and verifies status update to RESOLVED in database.
"""

import os
import sys
import asyncio
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.database import SessionLocal
from backend.models import Scan, Subdomain, Finding, FindingStatus, ScanStatus
from backend.services.scan_service import run_scan_pipeline_background
from backend.routers.findings import approve_finding
from backend.schemas import FindingApprovalRequest


async def run_verification():
    print("================================================================================", flush=True)
    print("MISSION 5 PART 4 — VERIFY FULL SCAN & HUMAN APPROVAL WORKFLOW", flush=True)
    print("================================================================================", flush=True)

    db = SessionLocal()

    # Step 1: Create a test scan entry
    target_url = "http://localhost:3000"
    scan = Scan(target=target_url, status=ScanStatus.PENDING.value)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    print(f"[+] Created Scan ID #{scan.id} for target: {target_url}", flush=True)

    # Step 2: Execute full scan pipeline
    print("\n[+] Executing full vulnerability scan & nuclei pipeline...", flush=True)
    await run_scan_pipeline_background(scan.id, target_url)

    # Step 3: Fetch all findings from database
    db.refresh(scan)
    subdomains = db.query(Subdomain).filter(Subdomain.scan_id == scan.id).all()
    sub_ids = [s.id for s in subdomains]

    findings = db.query(Finding).filter(Finding.subdomain_id.in_(sub_ids)).all()
    print(f"\n[+] Total Findings Persisted in DB: {len(findings)}", flush=True)

    all_non_empty = True
    specific_matches = []
    fallback_matches = []

    for f in findings:
        rec = f.recommendation
        if not rec or not rec.strip():
            all_non_empty = False
            print(f" FAIL: Finding #{f.id} '{f.check_name}' has empty recommendation!")
        else:
            if "Manual review recommended" in rec:
                fallback_matches.append(f)
            else:
                specific_matches.append(f)

    print(f"\n--- Recommendation Verification Audit ---")
    print(f" Every Finding Has Non-Empty Recommendation: {' YES' if all_non_empty else ' NO'}")
    print(f"  Specific Pattern Mappings Matched:         {len(specific_matches)}")
    print(f"  Generic Fallback Mappings Used:            {len(fallback_matches)}")

    print("\nDetailed Findings Breakdown:")
    for f in findings:
        is_fallback = "Manual review recommended" in (f.recommendation or "")
        tag = "[FALLBACK]" if is_fallback else "[SPECIFIC]"
        print(f"  - Finding #{f.id} {tag}: '{f.check_name}' ({f.severity})")
        print(f"    Rec: {f.recommendation}")
        if f.config_snippet:
            print(f"    Snippet: {f.config_snippet.splitlines()[0]}...")

    # Step 4: Approve one finding via API and verify DB update
    if findings:
        target_finding = findings[0]
        fid = target_finding.id
        print(f"\n[+] Approving Finding #{fid} ('{target_finding.check_name}') via API approval endpoint...", flush=True)

        req_body = FindingApprovalRequest(approved_by="auditor_sarah@nkat.ai")
        updated_res = approve_finding(finding_id=fid, approval_in=req_body, db=db)

        # Re-query DB to confirm persistence
        db.expire_all()
        db_refreshed = db.query(Finding).filter(Finding.id == fid).first()

        print(f"  Database Verification:")
        print(f"    ID:          #{db_refreshed.id}")
        print(f"    Status:      {db_refreshed.status} (Expected: RESOLVED)")
        print(f"    Approved By: {db_refreshed.approved_by}")
        print(f"    Approved At: {db_refreshed.approved_at}")

        assert db_refreshed.status == FindingStatus.RESOLVED.value, f"Status mismatch: {db_refreshed.status}"
        assert db_refreshed.approved_by == "auditor_sarah@nkat.ai", f"Approved_by mismatch: {db_refreshed.approved_by}"
        assert db_refreshed.approved_at is not None, "Approved_at timestamp is None!"

        print("\n HUMAN APPROVAL WORKFLOW VERIFIED SUCCESSFULLY IN DATABASE!")

    db.close()
    print("================================================================================", flush=True)

if __name__ == "__main__":
    asyncio.run(run_verification())
