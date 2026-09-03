"""
Integration and Unit Tests for NKAT AI FastAPI Backend & Database Models.
"""

import time
import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_health_check_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"


def test_root_redirect_to_docs():
    response = client.get("/", follow_redirects=False)
    assert response.status_code in (302, 307)
    assert response.headers["location"] == "/docs"


def test_unauthorized_target_rejection_403():
    """
    Part 5 Required Test 1:
    Submitting an unauthorized target to POST /api/scan MUST be rejected with HTTP 403 Forbidden.
    """
    response = client.post("/api/scan", json={"target": "http://evil-unauthorized-target.com"})
    assert response.status_code == 403
    detail = response.json().get("detail", "")
    assert "NOT authorized" in detail or "authorization check failed" in detail


def test_full_scan_pipeline_execution():
    """
    Part 5 Required Test 2:
    Triggering a full scan against an authorized target (http://localhost:3000) MUST:
    1. Return scan_id immediately in PENDING status.
    2. Execute subdomain discovery & active vulnerability audit in background.
    3. Transition status to 'complete' and produce at least one finding.
    """
    # 1. Trigger scan via POST /api/scan
    response = client.post("/api/scan", json={"target": "http://localhost:3000"})
    assert response.status_code == 201
    data = response.json()
    scan_id = data["id"]
    assert data["target"] == "http://localhost:3000"
    assert data["status"] in ("PENDING", "RUNNING", "complete")

    # 2. Poll GET /api/scan/{scan_id} until status is 'COMPLETED' or timeout
    start_time = time.time()
    final_scan = None
    while time.time() - start_time < 90:
        get_res = client.get(f"/api/scan/{scan_id}")
        assert get_res.status_code == 200
        final_scan = get_res.json()
        if final_scan["status"] in ("complete", "COMPLETED"):
            break
        time.sleep(0.5)

    assert final_scan is not None
    assert final_scan["status"] in ("complete", "COMPLETED")
    assert len(final_scan["subdomains"]) >= 1

    # Confirm at least one finding was discovered and persisted
    all_findings = []
    for sub in final_scan["subdomains"]:
        all_findings.extend(sub.get("findings", []))

    assert len(all_findings) >= 1, f"Expected at least 1 finding in full scan report, got {len(all_findings)}"
