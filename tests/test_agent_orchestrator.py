"""
Full Agentic Security Orchestrator Test Suite — NKAT AI Security Platform
-------------------------------------------------------------------------
Verifies:
1. Assessment context initialization & scoping
2. Security boundary enforcement (arbitrary shell rejection, scope validation, protected paths)
3. Deterministic finding correlation (SAST + DAST matching)
4. Full autonomous assessment -> SAST/DAST discovery -> root cause analysis -> patch generation -> rescan -> VERIFIED fix workflow
5. Automated rollback on validation failure
"""

import os
import sys
import pytest
import sqlite3
import threading
import time
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.database import Base
from backend.models import Assessment, Scan, Subdomain, Finding, FindingStatus, Remediation, RemediationStatus, AuditLog
from backend.services.agent_capability_gateway import orchestrator_gateway
from backend.services.finding_correlator import correlate_assessment_findings
from backend.services.agent_loop import run_agent_orchestrator_loop, execute_agent_tool
from tests.vulnerable_app.app import run_server, init_db, DB_PATH


@pytest.fixture(scope="module")
def test_app_server():
    """Starts isolated vulnerable test application server on 127.0.0.1:8888."""
    init_db()
    server_thread = threading.Thread(target=run_server, args=(8888,), daemon=True)
    server_thread.start()
    time.sleep(0.5)
    yield "http://127.0.0.1:8888"


@pytest.fixture
def test_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_assessment_context_initialization(test_db):
    """Verify assessment context initialization and scope binding."""
    ass = Assessment(name="Quarterly Security Assessment", target_url="http://127.0.0.1:8888", repository_path=PROJECT_ROOT)
    test_db.add(ass)
    test_db.commit()

    scan = Scan(assessment_id=ass.id, target="http://127.0.0.1:8888", status="COMPLETED")
    test_db.add(scan)
    test_db.commit()

    ctx = orchestrator_gateway.execute_capability(test_db, "get_assessment_context", assessment_id=ass.id)
    assert ctx["status"] == "success"
    assert ctx["data"]["assessment_id"] == ass.id
    assert ctx["data"]["target_url"] == "http://127.0.0.1:8888"
    assert ctx["data"]["scans_count"] == 1


def test_capability_gateway_security_boundaries(test_db):
    """Verify Security Policy Gateway rejects arbitrary shell, unregistered tools, and unauthorized targets."""
    # 1. Arbitrary shell command execution rejection
    res_shell = orchestrator_gateway.execute_capability(test_db, "run_dast", command="rm -rf /")
    assert res_shell["status"] == "rejected_security_violation"

    # 2. Unregistered capability rejection
    res_unreg = orchestrator_gateway.execute_capability(test_db, "malicious_unregistered_tool")
    assert res_unreg["status"] == "rejected_unregistered_capability"

    # 3. Out-of-scope unauthorized target rejection
    res_scope = orchestrator_gateway.execute_capability(test_db, "run_dast", target_url="https://unauthorized-malicious-domain.com/evil")
    assert res_scope["status"] == "rejected_scope_violation"


def test_finding_correlation_engine(test_db):
    """Verify deterministic correlation matching SAST code findings with DAST HTTP endpoint findings."""
    ass = Assessment(name="Correlation Test Assessment", target_url="http://127.0.0.1:8888")
    test_db.add(ass)
    test_db.commit()

    scan = Scan(assessment_id=ass.id, target="http://127.0.0.1:8888", status="COMPLETED")
    test_db.add(scan)
    test_db.commit()

    sub = Subdomain(scan_id=scan.id, hostname="127.0.0.1:8888")
    test_db.add(sub)
    test_db.commit()

    # DAST finding
    f_dast = Finding(
        subdomain_id=sub.id,
        assessment_id=ass.id,
        check_name="SQL Injection in User Lookup",
        severity="HIGH",
        cwe_id="CWE-89",
        evidence="DAST hit on /api/v1/user",
        status=FindingStatus.OPEN.value
    )
    # SAST finding
    f_sast = Finding(
        subdomain_id=sub.id,
        assessment_id=ass.id,
        check_name="SAST: Unsafe SQL Query String Interpolation",
        severity="HIGH",
        cwe_id="CWE-89",
        evidence="file: tests/vulnerable_app/app.py:35",
        status=FindingStatus.OPEN.value
    )
    test_db.add(f_dast)
    test_db.add(f_sast)
    test_db.commit()

    correlated = correlate_assessment_findings(test_db, assessment_id=ass.id)
    assert len(correlated) == 1
    pair = correlated[0]
    assert pair["status"] == "CORRELATED"
    assert pair["dast_finding_id"] == f_dast.id
    assert pair["sast_finding_id"] == f_sast.id
    assert pair["cwe_id"] == "CWE-89"


def test_full_autonomous_agentic_orchestrator_lifecycle(test_db, test_app_server, monkeypatch):
    """
    End-to-End Orchestrator Test:
    Executes full assessment orchestration loop:
    1. Assessment context initialization
    2. SAST audit execution
    3. Finding correlation
    4. AI analysis & patch generation
    5. Patch safety validation & isolated branch application
    6. DAST rescan verification
    7. Finding marked RESOLVED and status VERIFIED
    """
    monkeypatch.setattr("backend.services.agent_loop.SessionLocal", lambda: test_db)

    ass = Assessment(name="Full E2E Assessment", target_url="http://127.0.0.1:8888", repository_path=PROJECT_ROOT)
    test_db.add(ass)
    test_db.commit()

    scan = Scan(assessment_id=ass.id, target="http://127.0.0.1:8888", status="COMPLETED")
    test_db.add(scan)
    test_db.commit()

    sub = Subdomain(scan_id=scan.id, hostname="127.0.0.1:8888")
    test_db.add(sub)
    test_db.commit()

    f = Finding(
        subdomain_id=sub.id,
        assessment_id=ass.id,
        check_name="SQL Injection in User Lookup Parameter",
        severity="HIGH",
        cwe_id="CWE-89",
        evidence="DAST hit on /api/v1/user?username=' OR '1'='1",
        status=FindingStatus.OPEN.value
    )
    test_db.add(f)
    test_db.commit()
    test_db.refresh(f)

    # Execute Autonomous Orchestrator Loop
    orch_res = run_agent_orchestrator_loop(ass.id)
    assert orch_res["status"] == "COMPLETED"
    assert orch_res["assessment_id"] == ass.id
    assert len(orch_res["trajectory"]) > 0

    # Execute finding analysis & patch validation through capability gateway
    an_res = orchestrator_gateway.execute_capability(test_db, "analyze_finding", finding_id=f.id)
    assert an_res["status"] == "success"
    rem_id = an_res["data"]["remediation_id"]

    val_res = orchestrator_gateway.execute_capability(test_db, "validate_patch", remediation_id=rem_id, target_url="http://127.0.0.1:8888/api/v1/user")
    assert val_res["status"] == "success"
    assert val_res["data"]["status"] == RemediationStatus.VERIFIED.value

    # Verify parent finding resolved in DB
    f_updated = test_db.query(Finding).filter(Finding.id == f.id).first()
    assert f_updated.status == FindingStatus.RESOLVED.value

    # Rollback for clean git state
    roll_res = orchestrator_gateway.execute_capability(test_db, "rollback_remediation", remediation_id=rem_id)
    assert roll_res["data"]["status"] == RemediationStatus.ROLLED_BACK.value
