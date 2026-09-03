"""
Part 5 — Verification & Report Script for Mission 11
---------------------------------------------------
1. Sets short demo deadlines on a test finding.
2. Triggers auto-approval batch engine.
3. Confirms finding transitions to AUTO_APPROVED with distinct visual badge rendering.
4. Confirms audit log records auto-approve action with actor='system'.
5. Executes rollback to restore finding to OPEN.
6. Confirms audit log records rollback action with actor='human'.
"""

import sys
import os
import json
from datetime import datetime, timezone, timedelta

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Ensure project root is in python path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from backend.database import SessionLocal, Base, engine
from backend.models import Scan, Subdomain, Finding, FindingStatus, ScanStatus, AuditLog
from backend.services.auto_approval_scheduler import check_and_auto_approve_expired_findings
from backend.routers.findings import rollback_finding
from dashboard.server import render_dashboard_html


def run_verification():
    print("=====================================================================")
    print("      MISSION 11 PART 5 — VERIFICATION & AUDIT TRAIL REPORT         ")
    print("=====================================================================")

    # Ensure DB tables exist
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    try:
        # Step 1: Create test scan and finding with expired demo deadline
        now_utc = datetime.now(timezone.utc)
        demo_deadline = now_utc - timedelta(seconds=10) # expired 10s ago

        test_scan = Scan(target="http://localhost:3000", status=ScanStatus.COMPLETED.value)
        db.add(test_scan)
        db.commit()
        db.refresh(test_scan)

        test_sub = Subdomain(scan_id=test_scan.id, hostname="localhost")
        db.add(test_sub)
        db.commit()
        db.refresh(test_sub)

        test_finding = Finding(
            subdomain_id=test_sub.id,
            check_name="Exposed Git Repository",
            severity="HIGH",
            status=FindingStatus.OPEN.value,
            evidence="Public .git/HEAD exposed",
            review_deadline=demo_deadline,
        )
        db.add(test_finding)
        db.commit()
        db.refresh(test_finding)

        finding_id = test_finding.id
        print(f"[1] Created test OPEN finding #{finding_id} with demo review_deadline={demo_deadline.isoformat()}")

        # Step 2: Trigger auto-approval scheduler
        print("[2] Triggering auto-approval background scheduler...")
        transitioned_count = check_and_auto_approve_expired_findings()
        print(f"    -> Transitioned {transitioned_count} expired finding(s).")

        db.refresh(test_finding)
        assert test_finding.status == "AUTO_APPROVED", f"Expected AUTO_APPROVED, got {test_finding.status}"
        print(f"    -> Finding #{finding_id} status updated to: '{test_finding.status}'")
        print(f"    -> Previous state snapshot: {test_finding.previous_state}")

        # Step 3: Verify distinct visual badge in dashboard HTML
        html_out = render_dashboard_html()
        assert " AUTO-APPROVED (TIMEOUT)" in html_out, "Distinct visual badge not found in dashboard HTML!"
        print(" -> [VERIFIED] Dashboard renders distinct badge ' AUTO-APPROVED (TIMEOUT)'")

        # Step 4: Verify auto-approve audit log entry
        auto_audit = (
            db.query(AuditLog)
            .filter(AuditLog.finding_id == finding_id, AuditLog.action == "auto-approve")
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert auto_audit is not None, "Auto-approve audit log record not found!"
        assert auto_audit.actor == "system", f"Expected actor='system', got '{auto_audit.actor}'"
        print(f"    -> [VERIFIED] AuditLog record: id={auto_audit.id} | action='{auto_audit.action}' | actor='{auto_audit.actor}' ({auto_audit.actor_name})")

        # Step 5: Execute Rollback
        print(f"[3] Executing rollback for finding #{finding_id}...")
        rollback_finding(finding_id=finding_id, db=db)

        db.refresh(test_finding)
        assert test_finding.status == "OPEN", f"Expected status restored to OPEN, got {test_finding.status}"
        assert test_finding.approved_at is None, "approved_at was not cleared on rollback"
        assert test_finding.approved_by is None, "approved_by was not cleared on rollback"
        print(f"    -> [VERIFIED] Finding #{finding_id} status successfully restored to: '{test_finding.status}'")

        # Step 6: Verify rollback audit log entry
        rollback_audit = (
            db.query(AuditLog)
            .filter(AuditLog.finding_id == finding_id, AuditLog.action == "rollback")
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert rollback_audit is not None, "Rollback audit log record not found!"
        assert rollback_audit.actor == "human", f"Expected actor='human', got '{rollback_audit.actor}'"
        print(f"    -> [VERIFIED] AuditLog record: id={rollback_audit.id} | action='{rollback_audit.action}' | actor='{rollback_audit.actor}' ({rollback_audit.actor_name})")

        print("=====================================================================")
        print("    MISSION 11 VERIFICATION COMPLETE — ALL CHECKS PASSED (100%)      ")
        print("=====================================================================")

    finally:
        db.close()


if __name__ == "__main__":
    run_verification()
