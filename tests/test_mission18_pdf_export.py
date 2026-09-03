"""
Unit tests for Mission 18 Parts 3 & 4 — PDF Executive Report Export & Verification
----------------------------------------------------------------------------------
Verifies:
- PDF document generation via ReportLab (generate_scan_pdf_report).
- PDF header magic bytes ('%PDF-1.').
- GET /api/v1/scans/{scan_id}/report/pdf REST API endpoint integration.
- Attachment content-disposition header and application/pdf media type.
"""

import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.database import Base, get_db
from backend.models import Scan, Subdomain, Finding, FindingStatus, ScanStatus
from backend.services.pdf_generator import generate_scan_pdf_report


@pytest.fixture(autouse=True)
def setup_pdf_test_db():
    SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    yield TestingSessionLocal, engine
    app.dependency_overrides.clear()


def test_generate_scan_pdf_report(setup_pdf_test_db):
    TestingSessionLocal, _ = setup_pdf_test_db
    db = TestingSessionLocal()

    scan = Scan(target="http://localhost:3000", status=ScanStatus.COMPLETED.value)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    sub = Subdomain(scan_id=scan.id, hostname="localhost")
    db.add(sub)
    db.commit()
    db.refresh(sub)

    f1 = Finding(
        subdomain_id=sub.id,
        check_name="SQL Injection Vulnerability (CVE-2021-44228)",
        severity="CRITICAL",
        status=FindingStatus.OPEN.value,
        is_in_cisa_kev=True,
        epss_score=0.975,
        epss_percentile=0.998,
        evidence="Matched SQLi payload"
    )
    db.add(f1)
    db.commit()

    pdf_bytes = generate_scan_pdf_report(db, scan.id)
    assert pdf_bytes is not None
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF-1.")

    # Save sample PDF for verification
    sample_pdf_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "scan_report_executive_sample.pdf")
    os.makedirs(os.path.dirname(sample_pdf_path), exist_ok=True)
    with open(sample_pdf_path, "wb") as f:
        f.write(pdf_bytes)

    assert os.path.exists(sample_pdf_path) is True
    db.close()


def test_pdf_export_api_endpoint(setup_pdf_test_db):
    TestingSessionLocal, _ = setup_pdf_test_db
    db = TestingSessionLocal()

    scan = Scan(target="http://localhost:3000", status=ScanStatus.COMPLETED.value)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    scan_id = scan.id
    db.close()

    client = TestClient(app)
    res = client.get(f"/api/v1/scans/{scan_id}/report/pdf")

    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert "attachment; filename=" in res.headers["content-disposition"]
    assert res.content.startswith(b"%PDF-1.")
