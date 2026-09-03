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


def check_and_auto_approve_expired_findings() -> int:
    """
    Policy check for expired findings.
    Note: Auto-patching/auto-approval after review deadline is disabled by policy.
    Findings remain in OPEN status for explicit human review.
    """
    logger.info("Auto-patching/approval after deadline expiration is disabled by policy. Open findings require manual review.")
    return 0


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
