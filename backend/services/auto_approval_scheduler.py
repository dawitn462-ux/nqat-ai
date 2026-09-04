
"""
Auto-Approval Background Scheduler Service using APScheduler.
Periodically audits OPEN findings with expired review deadlines and auto-transitions
their status to AUTO_APPROVED (time-expired-and-approved-for-action).
"""

import sys
import logging
from datetime import datetime, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy.orm import Session

from backend.database import SessionLocal
from backend.models import Finding, FindingStatus

import json

from backend.services.audit_logger import log_audit_event

logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler()


def check_and_auto_approve_expired_findings(db: Session = None) -> int:
    """
    Policy check for expired findings.
    Audits OPEN findings with expired review deadlines, records previous_state snapshot,
    and auto-transitions status to AUTO_APPROVED.
    """
    should_close = False
    if db is None:
        db = SessionLocal()
        should_close = True

    try:
        now_utc = datetime.now(timezone.utc)
        expired_findings = (
            db.query(Finding)
            .filter(
                Finding.status == FindingStatus.OPEN.value,
                Finding.review_deadline.isnot(None),
                Finding.review_deadline <= now_utc,
            )
            .all()
        )

        transitioned_count = 0
        for finding in expired_findings:
            prev_snapshot = {
                "status": finding.status,
                "approved_at": finding.approved_at.isoformat() if finding.approved_at else None,
                "approved_by": finding.approved_by,
            }
            finding.previous_state = json.dumps(prev_snapshot)
            finding.status = FindingStatus.AUTO_APPROVED.value
            finding.approved_at = now_utc
            finding.approved_by = "system_auto_approval_scheduler"

            # Auto-generate virtual patch / remediation snippet if missing
            try:
                from backend.services.remediation_advisor import generate_recommendation
                finding_dict = {
                    "id": finding.id,
                    "check_name": finding.check_name,
                    "severity": finding.severity,
                    "evidence": finding.evidence,
                }
                rec = generate_recommendation(finding_dict)
                if not finding.recommendation and rec.get("recommendation"):
                    finding.recommendation = rec.get("recommendation")
                if not finding.config_snippet and rec.get("config_snippet"):
                    finding.config_snippet = rec.get("config_snippet")
            except Exception as patch_exc:
                logger.warning(f"Failed generating recommendation patch for finding #{finding.id}: {patch_exc}")

            log_audit_event(
                db=db,
                finding_id=finding.id,
                action="auto-approve-and-patch",
                actor="system",
                actor_name="system_auto_approval_scheduler"
            )

            # Create InAppNotification alerting analysts of auto-patch execution
            try:
                from backend.models import InAppNotification
                notif = InAppNotification(
                    organization_id=1,
                    title=f"Auto-Patched Finding #{finding.id}: Deadline Passed",
                    message=(
                        f"Human review deadline expired for finding #{finding.id} ('{finding.check_name}'). "
                        f"Platform automatically applied virtual remediation patch and updated status to AUTO_APPROVED."
                    ),
                    severity="HIGH" if finding.severity in ("CRITICAL", "HIGH") else "MEDIUM",
                    is_read=False,
                    created_at=now_utc
                )
                db.add(notif)
            except Exception as notif_exc:
                logger.warning(f"Could not create auto-patch notification for finding #{finding.id}: {notif_exc}")

            transitioned_count += 1

        db.commit()
        return transitioned_count
    except Exception as exc:
        db.rollback()
        logger.error(f"Error executing check_and_auto_approve_expired_findings: {exc}")
        return 0
    finally:
        if should_close:
            db.close()


def start_auto_approval_scheduler(interval_seconds: int = 60):
    """
    Starts the APScheduler background job running every interval_seconds (default 60s).
    """
    if not scheduler.running:
        scheduler.add_job(
            check_and_auto_approve_expired_findings,
            "interval",
            seconds=interval_seconds,
            id="auto_approval_job",
            replace_existing=True,
        )
        scheduler.start()
        sys.stdout.write(
            f"[+] [APScheduler] Auto-approval scheduler started (running every {interval_seconds}s).\n"
        )


def shutdown_auto_approval_scheduler():
    """
    Gracefully shuts down the background scheduler.
    """
    if scheduler.running:
        scheduler.shutdown(wait=False)
        sys.stdout.write("[*] [APScheduler] Auto-approval scheduler shut down.\n")
