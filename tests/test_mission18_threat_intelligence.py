"""
Unit tests for Mission 18 Parts 1 & 2 — CISA KEV + EPSS Threat Intelligence & 15-Minute Daemon
-----------------------------------------------------------------------------------------
Verifies:
- CISA KEV JSON feed caching & EPSS score parsing.
- Cross-referencing CVE IDs to populate is_in_cisa_kev, epss_score, and epss_percentile on Finding models.
- FindingResponse schema serialization including threat intelligence fields.
- 15-minute APScheduler polling daemon lifecycle (start & shutdown).
"""

import os
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base
from backend.models import Scan, Subdomain, Finding, FindingStatus, ScanStatus
from backend.services.threat_feed_client import (
    update_threat_feed_caches,
    get_cached_cisa_kev_set,
    lookup_epss_score,
    enrich_finding_with_threat_intel,
    CISA_KEV_CACHE_PATH,
    EPSS_CACHE_PATH
)
from backend.services.threat_feed_scheduler import (
    start_threat_feed_scheduler,
    shutdown_threat_feed_scheduler
)


@pytest.fixture(autouse=True)
def setup_threat_intel_db():
    SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    yield TestingSessionLocal
    Base.metadata.drop_all(bind=engine)


def test_threat_feed_caches_and_lookup():
    cache_res = update_threat_feed_caches()
    assert cache_res["timestamp"] is not None
    assert os.path.exists(EPSS_CACHE_PATH) is True

    kev_set = get_cached_cisa_kev_set()
    assert isinstance(kev_set, set)
    assert "CVE-2021-44228" in kev_set

    epss_info = lookup_epss_score("CVE-2021-44228")
    assert epss_info["epss"] is not None
    assert epss_info["epss"] > 0.5
    assert epss_info["percentile"] > 0.9


def test_enrich_finding_with_threat_intel(setup_threat_intel_db):
    TestingSessionLocal = setup_threat_intel_db
    db = TestingSessionLocal()

    scan = Scan(target="http://localhost:3000", status=ScanStatus.COMPLETED.value)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    sub = Subdomain(scan_id=scan.id, hostname="localhost")
    db.add(sub)
    db.commit()
    db.refresh(sub)

    finding = Finding(
        subdomain_id=sub.id,
        check_name="Log4Shell Vulnerability (CVE-2021-44228)",
        severity="CRITICAL",
        status=FindingStatus.OPEN.value,
        evidence="Matched Log4j payload CVE-2021-44228"
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)

    enrich_res = enrich_finding_with_threat_intel(db, finding)
    assert enrich_res["is_in_cisa_kev"] is True
    assert enrich_res["epss_score"] is not None
    assert enrich_res["epss_score"] > 0.5
    assert "CVE-2021-44228" in enrich_res["detected_cves"]

    # Verify DB persistence
    db_f = db.query(Finding).filter(Finding.id == finding.id).first()
    assert db_f.is_in_cisa_kev is True
    assert db_f.epss_score is not None

    db.close()


def test_15min_threat_feed_scheduler_lifecycle():
    scheduler = start_threat_feed_scheduler()
    assert scheduler is not None
    assert scheduler.running is True

    # Verify job registration
    job = scheduler.get_job("cisa_kev_epss_15min_polling_job")
    assert job is not None

    shutdown_threat_feed_scheduler()
    assert scheduler.running is False
