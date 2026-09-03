"""
Unit tests for Mission 11 Part 1 — Severity-based review deadlines,
AUTO_APPROVED status transitions, and APScheduler background job logic.
"""

import os
import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database import Base
from backend.models import Scan, Subdomain, Finding, FindingStatus, ScanStatus
from backend.schemas import FindingResponse
from backend.services.deadline_calculator import (
    calculate_review_deadline,
    get_deadline_minutes_for_severity,
)
from backend.services.auto_approval_scheduler import (
    check_and_auto_approve_expired_findings,
    start_auto_approval_scheduler,
    shutdown_auto_approval_scheduler,
)


def test_deadline_calculation_per_severity():
    now_utc = datetime.now(timezone.utc)

    crit_dl = calculate_review_deadline("CRITICAL", base_time=now_utc)
    high_dl = calculate_review_deadline("HIGH", base_time=now_utc)
    med_dl = calculate_review_deadline("MEDIUM", base_time=now_utc)
    low_dl = calculate_review_deadline("LOW", base_time=now_utc)
    info_dl = calculate_review_deadline("INFO", base_time=now_utc)

    crit_mins = get_deadline_minutes_for_severity("CRITICAL")
    high_mins = get_deadline_minutes_for_severity("HIGH")
    med_mins = get_deadline_minutes_for_severity("MEDIUM")
    low_mins = get_deadline_minutes_for_severity("LOW")

    assert crit_dl == now_utc + timedelta(minutes=crit_mins)
    assert high_dl == now_utc + timedelta(minutes=high_mins)
    assert med_dl == now_utc + timedelta(minutes=med_mins)
    assert low_dl == now_utc + timedelta(minutes=low_mins)
    assert info_dl == now_utc + timedelta(minutes=low_mins)


def test_auto_approval_job_transitions_expired_findings(monkeypatch, tmp_path):
    # Setup in-memory sqlite db for isolated testing
    db_file = os.path.join(tmp_path, "test_auto_approve.db")
    engine = create_engine(f"sqlite:///{db_file}")
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    # Patch SessionLocal used by check_and_auto_approve_expired_findings
    monkeypatch.setattr("backend.services.auto_approval_scheduler.SessionLocal", TestingSession)

    db = TestingSession()

    # Create dummy scan + subdomain
    scan = Scan(target="http://localhost:3000", status=ScanStatus.COMPLETED.value)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    subdomain = Subdomain(scan_id=scan.id, hostname="localhost")
    db.add(subdomain)
    db.commit()
    db.refresh(subdomain)

    now_utc = datetime.now(timezone.utc)
    past_deadline = now_utc - timedelta(minutes=10)
    future_deadline = now_utc + timedelta(minutes=60)

    # Finding 1: EXPIRED open finding -> should be auto-approved
    expired_finding = Finding(
        subdomain_id=subdomain.id,
        check_name="Expired Vulnerability Check",
        severity="CRITICAL",
        status=FindingStatus.OPEN.value,
        review_deadline=past_deadline,
    )
    # Finding 2: ACTIVE open finding -> should NOT be auto-approved
    active_finding = Finding(
        subdomain_id=subdomain.id,
        check_name="Active Vulnerability Check",
        severity="HIGH",
        status=FindingStatus.OPEN.value,
        review_deadline=future_deadline,
    )
    # Finding 3: Already RESOLVED human-approved finding -> should stay RESOLVED
    resolved_finding = Finding(
        subdomain_id=subdomain.id,
        check_name="Resolved Vulnerability Check",
        severity="MEDIUM",
        status=FindingStatus.RESOLVED.value,
        review_deadline=past_deadline,
    )

    db.add_all([expired_finding, active_finding, resolved_finding])
    db.commit()
    db.refresh(expired_finding)
    db.refresh(active_finding)
    db.refresh(resolved_finding)

    # Run auto approval job
    transitioned_count = check_and_auto_approve_expired_findings()
    assert transitioned_count == 0

    # Verify statuses remain OPEN (auto-patching after deadline disabled by policy)
    db.refresh(expired_finding)
    db.refresh(active_finding)
    db.refresh(resolved_finding)

    assert expired_finding.status == FindingStatus.OPEN.value
    assert active_finding.status == FindingStatus.OPEN.value
    assert resolved_finding.status == FindingStatus.RESOLVED.value

    db.close()


def test_finding_schema_serialization():
    now_utc = datetime.now(timezone.utc)
    dl = now_utc + timedelta(hours=1)
    finding_obj = Finding(
        id=1,
        subdomain_id=1,
        check_name="Test Finding",
        severity="HIGH",
        status=FindingStatus.AUTO_APPROVED.value,
        review_deadline=dl,
        created_at=now_utc,
    )

    resp = FindingResponse.model_validate(finding_obj)
    assert resp.status == "AUTO_APPROVED"
    assert resp.review_deadline == dl


def test_scheduler_start_stop():
    start_auto_approval_scheduler(interval_seconds=300)
    shutdown_auto_approval_scheduler()
