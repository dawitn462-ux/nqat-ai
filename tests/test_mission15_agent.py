"""
Unit tests for Mission 15 — Minimal Real Agentic Loop (4 Tools, Max Iterations Guardrail, Audit Trail, Scope Protection).
"""

import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.database import Base, get_db
from backend.models import Scan, Subdomain, Finding, FindingStatus, AuditLog, ScanStatus
from backend.services.agent_loop import (
    get_findings,
    flag_for_priority_review,
    request_deeper_scan,
    summarize_risk,
    run_agent_triage_loop,
    MAX_AGENT_ITERATIONS
)

VALID_API_KEY = "nkat_secret_api_key_2026"


@pytest.fixture(autouse=True)
def setup_test_db():
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


def test_agent_4_tools_execution(setup_test_db, monkeypatch):
    TestingSessionLocal, _ = setup_test_db
    db = TestingSessionLocal()

    monkeypatch.setattr("backend.services.agent_loop.SessionLocal", TestingSessionLocal)

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
        check_name="SQL Injection Vulnerability",
        severity="CRITICAL",
        status=FindingStatus.OPEN.value,
        evidence="OR 1=1"
    )
    db.add(f1)
    db.commit()
    db.refresh(f1)

    # Tool 1: get_findings
    f_list = get_findings(db, scan.id)
    assert len(f_list) == 1
    assert f_list[0]["check_name"] == "SQL Injection Vulnerability"

    # Tool 2: flag_for_priority_review
    flag_res = flag_for_priority_review(db, f1.id, "Urgent SQLi vulnerability")
    assert flag_res["status"] == "success"

    # Audit log check for actor='agent'
    audit = db.query(AuditLog).filter(AuditLog.finding_id == f1.id, AuditLog.action == "priority_flag").first()
    assert audit is not None
    assert audit.actor == "agent"

    # Tool 3: request_deeper_scan
    deep_res = request_deeper_scan(db, sub.id)
    assert deep_res["status"] == "success"
    assert deep_res["target"] in ("localhost", "http://localhost:3000")

    # Tool 4: summarize_risk
    sum_res = summarize_risk(db, scan.id)
    assert sum_res["status"] == "success"
    assert "Risk Evaluation" in sum_res["summary"]
    assert sum_res["critical_count"] == 1

    db.close()


def test_run_agent_triage_loop_trajectory_and_guardrail(setup_test_db, monkeypatch):
    TestingSessionLocal, _ = setup_test_db
    monkeypatch.setattr("backend.services.agent_loop.SessionLocal", TestingSessionLocal)

    db = TestingSessionLocal()
    scan = Scan(target="http://localhost:3000", status=ScanStatus.COMPLETED.value)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    sub = Subdomain(scan_id=scan.id, hostname="localhost")
    db.add(sub)
    db.commit()
    db.refresh(sub)

    # Seed 6 findings to test iteration cap guardrail
    for i in range(6):
        f = Finding(
            subdomain_id=sub.id,
            check_name=f"Threat Finding #{i+1}",
            severity="HIGH" if i < 3 else "CRITICAL",
            status=FindingStatus.OPEN.value,
        )
        db.add(f)
    db.commit()

    scan_id = scan.id
    db.close()

    result = run_agent_triage_loop(scan_id)
    assert result["status"] == "COMPLETED"
    assert result["iterations_used"] <= MAX_AGENT_ITERATIONS
    assert len(result["trajectory"]) > 0


def test_agent_triage_api_endpoint(setup_test_db, monkeypatch):
    TestingSessionLocal, _ = setup_test_db
    monkeypatch.setattr("backend.services.agent_loop.SessionLocal", TestingSessionLocal)

    db = TestingSessionLocal()
    scan = Scan(target="http://localhost:3000", status=ScanStatus.COMPLETED.value)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    scan_id = scan.id
    db.close()

    client = TestClient(app)
    res = client.post(
        f"/api/v1/scans/{scan_id}/agent-triage",
        headers={"X-API-Key": VALID_API_KEY}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["scan_id"] == scan_id
    assert "trajectory" in data


def test_unauthorized_tool_and_scope_guardrails(setup_test_db, monkeypatch):
    TestingSessionLocal, _ = setup_test_db
    db = TestingSessionLocal()
    monkeypatch.setattr("backend.services.agent_loop.SessionLocal", TestingSessionLocal)

    from backend.services.agent_loop import execute_agent_tool

    scan = Scan(target="http://localhost:3000", status=ScanStatus.COMPLETED.value)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    sub = Subdomain(scan_id=scan.id, hostname="http://unauthorized-external-site.com")
    db.add(sub)
    db.commit()
    db.refresh(sub)

    f1 = Finding(subdomain_id=sub.id, check_name="Test Check", severity="HIGH")
    db.add(f1)
    db.commit()
    db.refresh(f1)

    # 1. Attempt unauthorized tool call (Prompt Injection bypass attempt)
    unauth_res = execute_agent_tool(db, "auto_approve_finding", finding_id=f1.id)
    assert unauth_res["status"] == "rejected_unauthorized_tool"
    assert "Guardrail Violation" in unauth_res["message"]

    # 2. Attempt deeper scan on unauthorized target
    scope_res = execute_agent_tool(db, "request_deeper_scan", subdomain_id=sub.id)
    assert scope_res["status"] == "rejected_scope_violation"

    db.close()
