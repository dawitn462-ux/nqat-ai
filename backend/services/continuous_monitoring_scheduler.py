"""
Continuous Monitoring & Recurring Re-scan Scheduler Daemon.
Uses APScheduler to periodically re-scan all VERIFIED domain targets,
detect new findings compared against baseline posture, and dispatch in-app notifications.
"""

import sys
import logging
import asyncio
from typing import List, Set
from datetime import datetime, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy.orm import Session

from backend.database import SessionLocal
from backend.models import DomainTarget, DomainVerificationStatus, Scan, Subdomain, Finding, InAppNotification, ScanStatus

logger = logging.getLogger("nkat.monitoring_scheduler")

_monitoring_scheduler: BackgroundScheduler = None


def run_continuous_monitoring_cycle() -> int:
    """
    Executes a continuous monitoring cycle:
    1. Fetches all VERIFIED domain targets.
    2. Snapshots existing finding check names for each target.
    3. Runs scan pipeline against verified domain targets.
    4. Identifies new findings and generates InAppNotification records.
    Returns total count of new notifications generated.
    """
    from backend.services.scan_service import _execute_scan_async
    db: Session = SessionLocal()
    notifications_created = 0

    try:
        verified_domains = (
            db.query(DomainTarget)
            .filter(DomainTarget.status == DomainVerificationStatus.VERIFIED.value)
            .all()
        )

        if not verified_domains:
            logger.info("[Monitoring Scheduler] No VERIFIED domain targets found for re-scan cycle.")
            return 0

        for domain_rec in verified_domains:
            target_url = domain_rec.target_url or f"http://{domain_rec.domain}"
            org_id = domain_rec.organization_id

            # Part 4 — Expiry Check (30 days)
            from backend.services.domain_verification_service import is_domain_verified_and_active, reverify_domain_target, log_domain_audit
            if not is_domain_verified_and_active(domain_rec):
                domain_rec.status = DomainVerificationStatus.EXPIRED.value
                domain_rec.last_error = "Domain verification expired (>30 days). Re-verification required."
                log_domain_audit(
                    db=db,
                    user_id=None,
                    domain=domain_rec.domain,
                    method=domain_rec.verification_method,
                    result="EXPIRED",
                    details="Domain verification expired (older than 30 days). Re-verification required."
                )
                db.commit()
                logger.warning(f"[Monitoring Scheduler] Paused re-scan for '{domain_rec.domain}': Verification expired (>30 days).")
                continue

            # Part 3 — Scheduled Re-verification Check
            reverify_ok, reverify_msg = reverify_domain_target(db, domain_rec)
            if not reverify_ok:
                logger.warning(f"[Monitoring Scheduler] Paused re-scan for '{domain_rec.domain}': Re-verification failed ({reverify_msg}).")
                continue

            # 1. Snapshot existing check names for this domain
            existing_findings_query = (
                db.query(Finding.check_name)
                .join(Subdomain, Finding.subdomain_id == Subdomain.id)
                .join(Scan, Subdomain.scan_id == Scan.id)
                .filter(Scan.organization_id == org_id)
                .filter(Scan.target.contains(domain_rec.domain))
                .all()
            )
            pre_existing_checks: Set[str] = {f[0].strip().lower() for f in existing_findings_query if f[0]}


            # 2. Create new Scan record
            new_scan = Scan(
                target=target_url,
                status=ScanStatus.PENDING.value,
                organization_id=org_id
            )
            db.add(new_scan)
            db.commit()
            db.refresh(new_scan)

            # 3. Execute scan pipeline
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(_execute_scan_async(new_scan.id, target_url))
                loop.close()
            except Exception as exc:
                logger.error(f"[Monitoring Scheduler] Error re-scanning {target_url}: {exc}")
                continue

            # 4. Query findings produced in this scan
            new_scan_findings = (
                db.query(Finding)
                .join(Subdomain, Finding.subdomain_id == Subdomain.id)
                .filter(Subdomain.scan_id == new_scan.id)
                .all()
            )

            # 5. Detect newly introduced findings
            for finding in new_scan_findings:
                check_key = (finding.check_name or "").strip().lower()
                if check_key not in pre_existing_checks:
                    # Create InAppNotification
                    notif = InAppNotification(
                        organization_id=org_id,
                        domain_id=domain_rec.id,
                        scan_id=new_scan.id,
                        finding_id=finding.id,
                        title=f"NEW {finding.severity} FINDING: {finding.check_name}",
                        message=f"Continuous re-scan of '{domain_rec.domain}' detected new {finding.severity} finding: {finding.check_name}.",
                        severity=finding.severity,
                        is_read=False
                    )
                    db.add(notif)
                    notifications_created += 1

        db.commit()
        if notifications_created > 0:
            logger.info(f"[+] [Monitoring Scheduler] Continuous re-scan completed. {notifications_created} new finding notification(s) generated.")
    except Exception as exc:
        db.rollback()
        logger.error(f"[!] Error running continuous monitoring cycle: {exc}")
    finally:
        db.close()

    return notifications_created


def start_continuous_monitoring_scheduler(interval_minutes: int = 15) -> BackgroundScheduler:
    """
    Starts the APScheduler background continuous monitoring daemon.
    """
    global _monitoring_scheduler

    if _monitoring_scheduler and _monitoring_scheduler.running:
        logger.info("[Monitoring Scheduler] Daemon is already running.")
        return _monitoring_scheduler

    _monitoring_scheduler = BackgroundScheduler(daemon=True)
    _monitoring_scheduler.add_job(
        func=run_continuous_monitoring_cycle,
        trigger="interval",
        minutes=interval_minutes,
        id="continuous_domain_monitoring_job",
        name="Recurring re-scan and new-finding detection daemon",
        replace_existing=True
    )
    _monitoring_scheduler.start()
    logger.info(f"[+] [Monitoring Scheduler] Recurring Re-Scan Daemon started (running every {interval_minutes} minutes).")
    return _monitoring_scheduler


def shutdown_continuous_monitoring_scheduler():
    """
    Gracefully shuts down the background continuous monitoring scheduler.
    """
    global _monitoring_scheduler

    if _monitoring_scheduler and _monitoring_scheduler.running:
        _monitoring_scheduler.shutdown(wait=False)
        logger.info("[*] [Monitoring Scheduler] Recurring Re-Scan Daemon shut down cleanly.")
        _monitoring_scheduler = None
