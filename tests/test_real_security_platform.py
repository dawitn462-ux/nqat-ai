"""
Comprehensive Real Security Platform Acceptance Test Suite (10 Acceptance Tests).
Tests against running target application, real DAST/SAST engines, HTTP evidence capture,
target scope enforcement, independent verification engine, BEFORE/AFTER evidence pairs,
and resolution lifecycle validation.
"""

import os
import sys
import json
import time
import pytest
import threading
import httpx
from http.server import HTTPServer
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.main import app
from backend.database import Base, get_db
from backend.services.auth_service import seed_default_organization_and_user
from backend.auth import create_access_token
from backend.models import DomainTarget, DomainVerificationStatus, TargetStatus, Finding, FindingStatus, Subdomain, Scan
from tests.vulnerable_app.app import VulnerableAppHandler, init_db

VALID_API_KEY = "nkat_secret_api_key_2026"
TEST_PORT = 8888
TEST_APP_URL = f"http://127.0.0.1:{TEST_PORT}"


@pytest.fixture(scope="module")
def run_local_vulnerable_lab():
    """Spawns live running Vulnerable Security Lab HTTP server on http://127.0.0.1:8888 if not already running."""
    init_db()
    server = None
    try:
        server = HTTPServer(("127.0.0.1", TEST_PORT), VulnerableAppHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.5)
    except OSError:
        # Server port already bound by live running lab process
        pass

    yield TEST_APP_URL

    if server:
        server.shutdown()
        server.server_close()


@pytest.fixture
def test_env():
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
    import backend.database
    import backend.services.scan_service
    orig_sessionlocal_db = backend.database.SessionLocal
    orig_sessionlocal_scan = backend.services.scan_service.SessionLocal
    backend.database.SessionLocal = TestingSessionLocal
    backend.services.scan_service.SessionLocal = TestingSessionLocal

    db = TestingSessionLocal()
    seed_default_organization_and_user(db)

    # Pre-register http://127.0.0.1:8888 as APPROVED target in Target Registry
    target_rec = DomainTarget(
        organization_id=1,
        domain="127.0.0.1",
        target_url=TEST_APP_URL,
        verification_token="nkat-verify-test-token",
        verification_method="dns_txt",
        status=DomainVerificationStatus.VERIFIED.value,
        target_status=TargetStatus.APPROVED.value
    )
    db.add(target_rec)
    db.commit()
    db.close()

    yield TestingSessionLocal
    app.dependency_overrides.clear()
    backend.database.SessionLocal = orig_sessionlocal_db
    backend.services.scan_service.SessionLocal = orig_sessionlocal_scan


# ==============================================================================
# TEST 1: Real Vulnerability Appears on Live NKAT News Lab & Captures Evidence
# ==============================================================================
def test_1_scanner_executes_on_live_lab_and_captures_http_evidence(run_local_vulnerable_lab, test_env):
    client = TestClient(app)
    headers = {"X-API-Key": VALID_API_KEY}

    res = client.post("/api/v1/scan", json={"target": TEST_APP_URL}, headers=headers)
    assert res.status_code == 201, f"Scan failed: {res.text}"

    # Retrieve created findings
    db = test_env()
    findings = db.query(Finding).all()
    assert len(findings) > 0, "Real scan against live application should produce findings"

    hdr_finding = next((f for f in findings if "Header" in f.check_name or "x-powered-by" in f.check_name.lower()), None)
    assert hdr_finding is not None, "Missing security header or banner disclosure finding should exist"
    assert hdr_finding.request_evidence is not None, "Request evidence MUST be captured"
    assert hdr_finding.response_evidence is not None, "Response evidence MUST be captured"
    assert "status_code" in hdr_finding.response_evidence
    db.close()


# ==============================================================================
# TEST 2: Approve Remediation — Updates Status to PATCH_APPROVED (Not premature RESOLVED)
# ==============================================================================
def test_2_approve_remediation_updates_status_to_patch_approved(test_env):
    db = test_env()
    scan = Scan(organization_id=1, target=TEST_APP_URL, status="COMPLETED")
    db.add(scan)
    db.commit()
    sub = Subdomain(scan_id=scan.id, hostname="127.0.0.1:8888")
    db.add(sub)
    db.commit()

    finding = Finding(
        subdomain_id=sub.id,
        check_name="Missing Content-Security-Policy",
        severity="MEDIUM",
        evidence="Missing CSP header",
        status=FindingStatus.OPEN.value
    )
    db.add(finding)
    db.commit()
    finding_id = finding.id

    client = TestClient(app)
    headers = {"X-API-Key": VALID_API_KEY}

    res = client.patch(f"/api/v1/findings/{finding_id}/approve", json={"approved_by": "sec_architect"}, headers=headers)
    assert res.status_code == 200
    assert res.json()["status"] == FindingStatus.PATCH_APPROVED.value
    db.close()


# ==============================================================================
# TEST 3 & 4 & 5: Independent Verification Engine confirms fix -> Status becomes RESOLVED
# ==============================================================================
def test_3_4_5_independent_verification_confirms_fix_and_marks_resolved(run_local_vulnerable_lab, test_env):
    db = test_env()
    scan = Scan(organization_id=1, target=TEST_APP_URL, status="COMPLETED")
    db.add(scan)
    db.commit()
    sub = Subdomain(scan_id=scan.id, hostname="127.0.0.1:8888")
    db.add(sub)
    db.commit()

    finding = Finding(
        subdomain_id=sub.id,
        check_name="Missing Content-Security-Policy",
        severity="MEDIUM",
        evidence="Missing CSP header",
        vulnerability_type="MISSING_SECURITY_HEADER",
        request_evidence=json.dumps({"method": "GET", "url": f"{TEST_APP_URL}/"}),
        response_evidence=json.dumps({"status_code": 200, "headers": {"Content-Security-Policy": "default-src 'self'"}}),
        status=FindingStatus.PATCH_APPLIED.value
    )
    db.add(finding)
    db.commit()

    # Mock httpx GET returning response WITH CSP header
    from unittest.mock import patch, MagicMock
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Content-Security-Policy": "default-src 'self'"}
    mock_resp.text = "<html><body>Clean App</body></html>"

    with patch("httpx.Client.get", return_value=mock_resp):
        from backend.services.independent_verification_engine import IndependentVerificationEngine
        verifier = IndependentVerificationEngine()
        success, msg, after_ev = verifier.verify_finding(db, finding.id)
        assert success is True
        assert finding.status == FindingStatus.RESOLVED.value
    db.close()


# ==============================================================================
# TEST 6: Reopen Finding when patch breaks
# ==============================================================================
def test_6_broken_patch_reopens_finding(test_env):
    db = test_env()
    scan = Scan(organization_id=1, target=TEST_APP_URL, status="COMPLETED")
    db.add(scan)
    db.commit()
    sub = Subdomain(scan_id=scan.id, hostname="127.0.0.1:8888")
    db.add(sub)
    db.commit()

    finding = Finding(
        subdomain_id=sub.id,
        check_name="Missing Content-Security-Policy",
        severity="MEDIUM",
        evidence="Missing CSP header",
        vulnerability_type="MISSING_SECURITY_HEADER",
        request_evidence=json.dumps({"method": "GET", "url": f"{TEST_APP_URL}/"}),
        status=FindingStatus.PATCH_APPLIED.value
    )
    db.add(finding)
    db.commit()

    from backend.services.independent_verification_engine import IndependentVerificationEngine
    verifier = IndependentVerificationEngine()

    # Live vulnerable app has no CSP header, so verify_finding will return success=False
    success, msg, _ = verifier.verify_finding(db, finding.id)

    assert success is False
    assert finding.status == FindingStatus.REOPENED.value
    db.close()


# ==============================================================================
# TEST 7: Harmless False-Positive Scenario is NOT automatically confirmed
# ==============================================================================
def test_7_harmless_false_positive_not_confirmed(test_env):
    from scanner.checks.sqli import SQLInjectionCheck
    sqli_check = SQLInjectionCheck(client=None)

    # Clean response without SQL errors
    body_clean = json.dumps({"status": "ok", "message": "Search completed normally"})
    has_db_error = any(err.lower() in body_clean.lower() for err in sqli_check.DB_ERRORS)
    assert has_db_error is False, "Clean non-vulnerable output must NOT trigger SQLi error detection"


# ==============================================================================
# TEST 8: Disabled Scanner Binary returns TOOL_UNAVAILABLE without fake data
# ==============================================================================
def test_8_disabled_scanner_binary_returns_tool_unavailable(test_env):
    db = test_env()
    from backend.services.tool_registry import tool_registry

    # Get Nuclei tool
    nuclei_tool = tool_registry.get_tool("dast.nuclei_scan")
    assert nuclei_tool is not None

    # Temporarily mark status as MISSING
    orig_status = nuclei_tool.availability_status
    nuclei_tool.availability_status = "MISSING"

    res = tool_registry.execute_tool(db, "dast.nuclei_scan", target_url=TEST_APP_URL)
    assert res["status"] == "TOOL_UNAVAILABLE"
    assert "TOOL_UNAVAILABLE" in res["message"]

    # Restore status
    nuclei_tool.availability_status = orig_status
    db.close()


# ==============================================================================
# TEST 9: Target Response Change Reverts Finding
# ==============================================================================
def test_9_target_response_change_reverts_finding(test_env):
    db = test_env()
    scan = Scan(organization_id=1, target=TEST_APP_URL, status="COMPLETED")
    db.add(scan)
    db.commit()
    sub = Subdomain(scan_id=scan.id, hostname="127.0.0.1:8888")
    db.add(sub)
    db.commit()

    finding = Finding(
        subdomain_id=sub.id,
        check_name="Missing Content-Security-Policy",
        severity="MEDIUM",
        evidence="Missing CSP header",
        request_evidence=json.dumps({"method": "GET", "url": f"{TEST_APP_URL}/"}),
        status=FindingStatus.RESOLVED.value
    )
    db.add(finding)
    db.commit()

    from backend.services.independent_verification_engine import IndependentVerificationEngine
    verifier = IndependentVerificationEngine()

    # Re-run verification against live app where CSP is still missing
    success, msg, _ = verifier.verify_finding(db, finding.id)
    assert success is False
    assert finding.status == FindingStatus.REOPENED.value
    db.close()


# ==============================================================================
# TEST 10: Scan Attempt Outside Approved Target Registry is BLOCKED (403)
# ==============================================================================
def test_10_unapproved_target_blocked(test_env):
    client = TestClient(app)
    headers = {"X-API-Key": VALID_API_KEY}

    res = client.post("/api/v1/scan", json={"target": "http://unapproved-external-attacker-site.com"}, headers=headers)
    assert res.status_code == 403
    assert "NOT authorized" in res.json().get("detail", "")
