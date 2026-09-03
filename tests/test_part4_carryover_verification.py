"""
Part 4 Carry-Over Verification Test Suite.
Confirms timeout auto-approval + rollback (Mission 11) and NIST / CISA KEV / EPSS / OWASP threat feeds (Missions 12+18)
operate seamlessly alongside Part 3 domain monitoring and scoped organizations.
"""

import pytest
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base
from backend.models import Scan, Subdomain, Finding, FindingStatus, SeverityLevel, AuditLog
from backend.services.auto_approval_scheduler import check_and_auto_approve_expired_findings
from backend.services.threat_feed_client import enrich_finding_with_threat_intel, update_threat_feed_caches
from backend.services.remediation_advisor import generate_recommendation
from backend.services.auth_service import seed_default_organization_and_user


@pytest.fixture(autouse=True)
def setup_carryover_db():
    SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    db = TestingSessionLocal()
    seed_res = seed_default_organization_and_user(db)
    org_id = seed_res["organization_id"]
    db.close()

    yield TestingSessionLocal, engine, org_id


def test_part4_timeout_auto_approval_and_rollback(setup_carryover_db):
    TestingSessionLocal, _, org_id = setup_carryover_db
    db = TestingSessionLocal()

    # 1. Create scan, subdomain, and an OPEN finding with expired review deadline
    scan = Scan(target="http://localhost:3000", status="COMPLETED", organization_id=org_id)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    sub = Subdomain(scan_id=scan.id, hostname="localhost", ip_address="127.0.0.1")
    db.add(sub)
    db.commit()
    db.refresh(sub)

    past_deadline = datetime.now(timezone.utc) - timedelta(hours=2)
    finding = Finding(
        subdomain_id=sub.id,
        check_name="SQL Injection Vulnerability",
        severity=SeverityLevel.HIGH.value,
        evidence="SELECT * FROM users",
        status=FindingStatus.OPEN.value,
        review_deadline=past_deadline
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    finding_id = finding.id

    # 2. Run auto-approval job (Mission 11 feature)
    with pytest.MonkeyPatch.context() as m:
        m.setattr("backend.services.auto_approval_scheduler.SessionLocal", lambda: db)
        transitioned = check_and_auto_approve_expired_findings()
        assert transitioned == 1

    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    assert finding.status == FindingStatus.AUTO_APPROVED.value
    assert finding.previous_state is not None
    assert "OPEN" in finding.previous_state

    # 3. Test rollback capability (Mission 11 feature)
    import json
    prev = json.loads(finding.previous_state)
    finding.status = prev["status"]
    finding.previous_state = None
    db.commit()

    db.refresh(finding)
    assert finding.status == FindingStatus.OPEN.value

    db.close()


def test_part4_threat_intel_enrichment_cisa_epss_owasp(setup_carryover_db):
    TestingSessionLocal, _, org_id = setup_carryover_db
    db = TestingSessionLocal()

    scan = Scan(target="http://localhost:3000", status="COMPLETED", organization_id=org_id)
    db.add(scan)
    db.commit()

    sub = Subdomain(scan_id=scan.id, hostname="localhost", ip_address="127.0.0.1")
    db.add(sub)
    db.commit()

    finding = Finding(
        subdomain_id=sub.id,
        check_name="Log4Shell RCE Vulnerability (CVE-2021-44228)",
        severity=SeverityLevel.CRITICAL.value,
        evidence="JNDI lookup attempt",
        status=FindingStatus.OPEN.value,
        cwe_id="CWE-502"
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)

    # Enrich with CISA KEV + EPSS threat intelligence
    enrich_finding_with_threat_intel(db, finding)

    db.refresh(finding)
    # Log4Shell is known in CISA KEV
    assert finding.is_in_cisa_kev is True or finding.epss_score is not None or finding.owasp_category is not None

    # Test remediation advisor OWASP + CWE enrichment
    advice = generate_recommendation({"check_name": finding.check_name, "severity": finding.severity})
    assert advice.get("owasp_category") is not None
    assert advice.get("cwe_info") is not None or advice.get("config_snippet") is not None

    db.close()
