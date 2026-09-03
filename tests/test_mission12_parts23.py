"""
Unit tests for Mission 12 Parts 2 & 3 — Database schema standards mapping and authoritative citations.
"""

import os
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database import Base
from backend.models import Scan, Subdomain, Finding, FindingStatus, ScanStatus
from backend.services.reference_mapper import get_standards_mapping, CHECK_TYPE_STANDARDS_MAP
from backend.services.remediation_advisor import generate_recommendation
from dashboard.server import render_dashboard_html


def test_standards_lookup_dictionary():
    assert "sql_injection" in CHECK_TYPE_STANDARDS_MAP
    assert CHECK_TYPE_STANDARDS_MAP["sql_injection"]["owasp_category"] == "A03:2021 - Injection"
    assert CHECK_TYPE_STANDARDS_MAP["sql_injection"]["cwe_id"] == "CWE-89"

    mapping_sqli = get_standards_mapping("SQL Injection Vulnerability")
    assert mapping_sqli["cwe_id"] == "CWE-89"

    mapping_git = get_standards_mapping("Exposed Git Repository")
    assert mapping_git["cwe_id"] == "CWE-200"


def test_remediation_advisor_authoritative_citation():
    rec = generate_recommendation({"check_name": "SQL Injection", "severity": "HIGH"})
    assert "full_fix_guide" in rec
    guide = rec["full_fix_guide"]
    assert "authoritative_citation" in guide
    assert "Per OWASP" in guide["authoritative_citation"]
    assert "CWE-89" in guide["authoritative_citation"]


def test_database_finding_owasp_and_cwe_columns(tmp_path):
    db_file = os.path.join(tmp_path, "test_parts23.db")
    engine = create_engine(f"sqlite:///{db_file}")
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    db = TestingSession()
    scan = Scan(target="http://localhost:3000", status=ScanStatus.COMPLETED.value)
    db.add(scan)
    db.commit()

    subdomain = Subdomain(scan_id=scan.id, hostname="localhost")
    db.add(subdomain)
    db.commit()

    rec = generate_recommendation({"check_name": "Exposed Git Repository", "severity": "HIGH"})
    f = Finding(
        subdomain_id=subdomain.id,
        check_name="Exposed Git Repository",
        severity="HIGH",
        status=FindingStatus.OPEN.value,
        owasp_category=rec.get("owasp_category"),
        cwe_id=rec.get("cwe_id") or "CWE-200"
    )
    db.add(f)
    db.commit()
    db.refresh(f)

    assert f.owasp_category == "A01:2021 - Broken Access Control"
    assert f.cwe_id == "CWE-200"
    db.close()


def test_dashboard_rendering_authoritative_citation():
    html_out = render_dashboard_html()
    assert " Standard Citation:" in html_out
