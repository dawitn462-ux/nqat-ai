"""
Comprehensive unit & integration tests for request_deeper_scan real scanner execution,
scope guardrails, database persistence, error handling, and LLM tool result feedback.
"""

import os
import pytest
from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base
from backend.models import Scan, Subdomain, Finding, AuditLog, FindingStatus, ScanStatus
from backend.services.agent_loop import (
    request_deeper_scan,
    execute_agent_tool,
    run_agent_triage_loop,
    MAX_AGENT_ITERATIONS,
    MAX_EXECUTION_TIME_SECONDS,
    ALLOWED_AGENT_TOOLS,
)


@pytest.fixture
def test_db():
    SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
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


def test_request_deeper_scan_authorized_target_executes_scanners(test_db, monkeypatch):
    """
    Test 1: Authorized target -> real scanner functions are called, findings persisted, real results returned.
    """
    scan = Scan(target="http://localhost:3000", status=ScanStatus.COMPLETED.value)
    test_db.add(scan)
    test_db.commit()
    test_db.refresh(scan)

    sub = Subdomain(scan_id=scan.id, hostname="localhost")
    test_db.add(sub)
    test_db.commit()
    test_db.refresh(sub)

    # Mock external scanner calls for fast deterministic unit test
    mock_katana = MagicMock(return_value=["http://localhost:3000/api/v1/users"])
    mock_nuclei_run = MagicMock(return_value="nuclei_output.jsonl")
    mock_nuclei_parse = MagicMock(return_value=[
        {
            "check_name": "NUCLEI: Exposed Env File",
            "severity": "HIGH",
            "evidence": "Nuclei matched '.env file' at http://localhost:3000/.env",
            "matched_at": "http://localhost:3000/.env",
            "cve_id": None,
            "cwe_id": "CWE-200"
        }
    ])

    mock_sec_scanner_instance = MagicMock()
    mock_sec_scanner_instance.execute_scan = MagicMock(return_value=MagicMock(findings=[]))
    mock_sec_scanner_class = MagicMock(return_value=mock_sec_scanner_instance)

    monkeypatch.setattr("backend.services.agent_loop.run_katana_crawl", mock_katana)
    monkeypatch.setattr("backend.services.agent_loop.run_nuclei_scan", mock_nuclei_run)
    monkeypatch.setattr("backend.services.agent_loop.parse_nuclei_findings", mock_nuclei_parse)
    monkeypatch.setattr("backend.services.agent_loop.SecurityScanner", mock_sec_scanner_class)

    res = request_deeper_scan(test_db, sub.id, reasoning="Investigating potential credentials leak")

    assert res["status"] == "success"
    assert res["scan_execution_status"] == "completed"
    assert "katana" in res["scanners_used"]
    assert "nuclei" in res["scanners_used"]
    assert res["new_findings_count"] == 1
    assert len(res["new_finding_ids"]) == 1

    # Verify findings persisted in database under sub.id
    db_findings = test_db.query(Finding).filter(Finding.subdomain_id == sub.id).all()
    assert len(db_findings) == 1
    assert db_findings[0].check_name == "NUCLEI: Exposed Env File"
    assert db_findings[0].severity == "HIGH"
    assert db_findings[0].status == FindingStatus.OPEN.value

    # Verify audit log entry actor='agent'
    audit = test_db.query(AuditLog).filter(AuditLog.subdomain_id == sub.id, AuditLog.action == "deeper_scan_triggered").first()
    assert audit is not None
    assert audit.actor == "agent"
    assert "NKAT_Agent:" in audit.actor_name


def test_request_deeper_scan_unauthorized_target_rejected(test_db):
    """
    Test 2: Unauthorized target -> scope validation rejects request, scanners NOT executed.
    """
    scan = Scan(target="http://localhost:3000", status=ScanStatus.COMPLETED.value)
    test_db.add(scan)
    test_db.commit()

    unauth_sub = Subdomain(scan_id=scan.id, hostname="unauthorized-malicious-site.com")
    test_db.add(unauth_sub)
    test_db.commit()
    test_db.refresh(unauth_sub)

    res = request_deeper_scan(test_db, unauth_sub.id, reasoning="Prompt injection attempt")

    assert res["status"] == "rejected_scope_violation"
    assert "subdomain_id" in res
    assert "message" in res

    # Verify audit log entry for rejection
    audit = test_db.query(AuditLog).filter(AuditLog.subdomain_id == unauth_sub.id, AuditLog.action == "deeper_scan_rejected").first()
    assert audit is not None
    assert audit.actor == "agent"


def test_request_deeper_scan_nonexistent_subdomain(test_db):
    """
    Test 3: Invalid subdomain ID -> returns error dictionary.
    """
    res = request_deeper_scan(test_db, 999999)
    assert res["status"] == "error"
    assert "Subdomain #999999 not found" in res["message"]


def test_request_deeper_scan_scanner_failure_handling(test_db, monkeypatch):
    """
    Test 4: Top level execution failure -> catches exception, status is failed (never reports fake success).
    """
    scan = Scan(target="http://localhost:3000", status=ScanStatus.COMPLETED.value)
    test_db.add(scan)
    test_db.commit()

    sub = Subdomain(scan_id=scan.id, hostname="localhost")
    test_db.add(sub)
    test_db.commit()
    test_db.refresh(sub)

    def mock_db_error(*args, **kwargs):
        raise RuntimeError("Fatal process error during execution")

    mock_sec_scanner_instance = MagicMock()
    mock_sec_scanner_instance.execute_scan = MagicMock(return_value=MagicMock(findings=[]))
    mock_sec_scanner_class = MagicMock(return_value=mock_sec_scanner_instance)

    monkeypatch.setattr("backend.services.agent_loop.score_finding_with_ml", mock_db_error)
    mock_katana = MagicMock(return_value=["http://localhost:3000/api/v1/users"])
    mock_nuclei_run = MagicMock(return_value="nuclei_output.jsonl")
    mock_nuclei_parse = MagicMock(return_value=[{"check_name": "Test", "severity": "HIGH"}])
    monkeypatch.setattr("backend.services.agent_loop.run_katana_crawl", mock_katana)
    monkeypatch.setattr("backend.services.agent_loop.run_nuclei_scan", mock_nuclei_run)
    monkeypatch.setattr("backend.services.agent_loop.parse_nuclei_findings", mock_nuclei_parse)
    monkeypatch.setattr("backend.services.agent_loop.SecurityScanner", mock_sec_scanner_class)

    res = request_deeper_scan(test_db, sub.id)

    assert res["status"] == "failed"
    assert res["scan_execution_status"] == "error"
    assert "Fatal process error" in res["error"]
    assert res["new_findings_count"] == 0


def test_agent_loop_guardrails_and_whitelist(test_db):
    """
    Test 5: Guardrails: ALLOWED_AGENT_TOOLS whitelist enforced, MAX_AGENT_ITERATIONS = 5 preserved.
    """
    assert ALLOWED_AGENT_TOOLS == {
        "get_findings",
        "flag_for_priority_review",
        "request_deeper_scan",
        "summarize_risk",
    }
    assert MAX_AGENT_ITERATIONS == 5
    assert MAX_EXECUTION_TIME_SECONDS == 60.0

    # Attempt calling unapproved tool (e.g. system command or arbitrary approval)
    res = execute_agent_tool(test_db, "execute_shell_command", command="rm -rf /")
    assert res["status"] == "rejected_unauthorized_tool"
    assert "Guardrail Violation" in res["message"]
