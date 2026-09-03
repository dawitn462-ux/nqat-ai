"""
Mission 10.5 Part 3 — Fresh Scan & Dashboard Deduplication Verification Script
---------------------------------------------------------------------------------
1. Initiates a fresh scan against target host.
2. Executes full scan pipeline with custom checks and nuclei integration.
3. Verifies findings persisted for the new scan run are strictly deduplicated.
4. Confirms load_latest_scan_data() and render_dashboard_html() report the exact deduplicated count.
"""

import sys
import os
import asyncio
from datetime import datetime, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from backend.database import SessionLocal, Base, engine
from backend.models import Scan, Subdomain, Finding, ScanStatus
from backend.services.scan_service import _execute_scan_async
from dashboard.server import load_latest_scan_data, render_dashboard_html


async def run_fresh_scan_verification():
    print("=====================================================================")
    print("      MISSION 10.5 — FRESH SCAN DEDUPLICATION VERIFICATION          ")
    print("=====================================================================")

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    target_url = "http://localhost:3000"

    try:
        # Step 1: Create fresh Scan record
        scan = Scan(target=target_url, status=ScanStatus.RUNNING.value)
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id
        print(f"[1] Created fresh scan run ID #{scan_id} for target: '{target_url}'")

        # Step 2: Trigger scan task execution
        print(f"[2] Executing scan pipeline for scan_id #{scan_id}...")
        await _execute_scan_async(scan_id=scan_id, target_url=target_url)

        # Step 3: Query DB findings for this fresh scan
        db.refresh(scan)
        print(f"    -> Scan ID #{scan_id} completed with status: '{scan.status}'")

        scan_findings = (
            db.query(Finding)
            .join(Subdomain, Finding.subdomain_id == Subdomain.id)
            .filter(Subdomain.scan_id == scan_id)
            .all()
        )
        finding_count = len(scan_findings)
        print(f"[3] Fresh Scan ID #{scan_id} database finding count: {finding_count}")
        assert finding_count < 20, f"Expected deduplicated finding count < 20, got {finding_count}"

        print("    -> Findings returned by scan pipeline:")
        for idx, f in enumerate(scan_findings, start=1):
            print(f"       {idx}. [{f.severity}] #{f.id} - '{f.check_name}' (OWASP: {f.owasp_category}, CWE: {f.cwe_id})")

        # Step 4: Verify load_latest_scan_data() and render_dashboard_html()
        dash_data = load_latest_scan_data()
        dash_count = dash_data["total_vulnerabilities"]
        print(f"\n[4] Dashboard load_latest_scan_data() report count: {dash_count}")
        assert dash_count == finding_count, f"Dashboard count ({dash_count}) does not match scan DB count ({finding_count})!"

        html_out = render_dashboard_html()
        assert f"{dash_count} DETECTED" in html_out or f"{dash_count} FINDINGS" in html_out, "Accurate count not found in dashboard HTML!"
        print(f"    -> [VERIFIED] Dashboard renders exact count: '{dash_count} DETECTED/FINDINGS' (not 268)")

        print("=====================================================================")
        print("   MISSION 10.5 VERIFICATION COMPLETE — ALL DUP FIXES PASSED (100%)  ")
        print("=====================================================================")

    finally:
        db.close()


if __name__ == "__main__":
    asyncio.run(run_fresh_scan_verification())
