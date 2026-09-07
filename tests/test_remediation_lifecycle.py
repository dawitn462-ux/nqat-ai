"""
Comprehensive End-to-End Remediation Lifecycle Test Suite — NKAT AI Security Platform
--------------------------------------------------------------------------------------
Verifies complete 18-step remediation workflow using isolated vulnerable test application:
1. Vulnerability discovery (SQL Injection DAST scan)
2. Finding-to-source mapping
3. AI root cause analysis
4. Git diff patch generation
5. Patch safety validation & protected path checks
6. Isolated Git branch patch application
7. Multi-stage syntax, unit test, SAST, and DAST rescan validation
8. Original vulnerability verification (BEFORE vs AFTER)
9. Security regression checking
10. Rollback to base commit state
11. Enforcement of fundamental invariant: AI CLAIM != SECURITY VERIFICATION
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
from backend.models import Scan, Subdomain, Finding, FindingStatus, Remediation, RemediationStatus, AuditLog
from backend.services.remediation_engine import (
    map_finding_to_source,
    generate_remediation_analysis_and_patch,
    validate_patch_safety,
    apply_patch_in_isolated_branch,
    validate_remediation_and_rescan,
    rollback_remediation
)
from tests.vulnerable_app.app import run_server, get_user_from_db, init_db


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


def test_end_to_end_verified_remediation_lifecycle(test_db, test_app_server):
    """
    Primary End-to-End Lifecycle Demonstration Test:
    1. Vulnerability detected via DAST on test app (/api/v1/user?username=' OR '1'='1)
    2. Finding stored in DB
    3. Finding mapped to source code (tests/vulnerable_app/app.py:28)
    4. AI analyzes root cause & generates parameterized query patch
    5. Patch safety validation passes
    6. Patch applied to isolated branch
    7. Syntax + SAST + DAST rescan executes
    8. Original vulnerability verified GONE
    9. Status becomes VERIFIED and finding becomes RESOLVED
    10. Rollback restores base state
    """
    scan = Scan(target="http://127.0.0.1:8888", status="COMPLETED")
    test_db.add(scan)
    test_db.commit()

    sub = Subdomain(scan_id=scan.id, hostname="127.0.0.1:8888")
    test_db.add(sub)
    test_db.commit()

    finding = Finding(
        subdomain_id=sub.id,
        check_name="SQL Injection in User Lookup Parameter",
        severity="HIGH",
        evidence="DAST matched payload '\' OR \'1\'=\'1' returning all 2 user records",
        status=FindingStatus.OPEN.value
    )
    test_db.add(finding)
    test_db.commit()
    test_db.refresh(finding)

    # Step 1: Finding-to-Source Mapping
    mapping = map_finding_to_source(test_db, finding)
    assert mapping["affected_file"] == os.path.join("tests", "vulnerable_app", "app.py")
    assert mapping["affected_function"] == "get_user_from_db"
    assert mapping["confidence"] >= 0.90

    # Step 2: AI Root Cause Analysis & Patch Generation
    analysis = generate_remediation_analysis_and_patch(test_db, finding, mapping)
    assert analysis["status"] == RemediationStatus.PATCH_GENERATED.value
    assert "Unsafe string interpolation" in analysis["root_cause"]
    assert "SELECT id, username, role FROM users WHERE username = ?" in analysis["patch"]

    # Save Remediation Model
    remediation = Remediation(
        finding_id=finding.id,
        repository=mapping["repository"],
        affected_file=mapping["affected_file"],
        affected_function=mapping["affected_function"],
        vulnerable_line=mapping["vulnerable_line"],
        root_cause=analysis["root_cause"],
        patch_strategy=analysis["patch_strategy"],
        patch=analysis["patch"],
        confidence=analysis["confidence"],
        status=analysis["status"]
    )
    test_db.add(remediation)
    test_db.commit()
    test_db.refresh(remediation)

    # Step 3: Patch Safety Engine
    safe, msg = validate_patch_safety(remediation.patch, remediation.affected_file)
    assert safe is True

    # Step 4: Apply Patch to Isolated Branch
    app_res = apply_patch_in_isolated_branch(remediation.id, remediation.affected_file, remediation.patch)
    assert app_res["status"] == RemediationStatus.PATCH_VALIDATING.value

    # Step 5: Multi-Stage Validation & DAST Rescan
    val_res = validate_remediation_and_rescan(test_db, remediation, target_url="http://127.0.0.1:8888/api/v1/user")
    assert val_res["status"] == RemediationStatus.VERIFIED.value
    assert val_res["validation_results"]["syntax"] == "PASSED"
    assert val_res["validation_results"]["sast"] == "PASSED"
    assert "PASSED" in val_res["validation_results"]["dast"]

    # Step 6: Verify Finding Status Transition in DB
    test_db.refresh(finding)
    assert finding.status == FindingStatus.RESOLVED.value

    # Step 7: Test Rollback & Restoration
    roll_res = rollback_remediation(test_db, remediation.id)
    assert roll_res["status"] == RemediationStatus.ROLLED_BACK.value

    # Verify app file restored to vulnerable state
    with open(os.path.join(PROJECT_ROOT, remediation.affected_file), "r", encoding="utf-8") as f:
        restored_content = f.read()
    assert "query = f\"SELECT id, username, role FROM users WHERE username = '{username}'\"" in restored_content


def test_patch_safety_protected_file_rejection():
    """Verify patch safety engine rejects patches targeting protected files (.env, credentials)."""
    safe, msg = validate_patch_safety("--- a/.env\n+++ b/.env\n+DB_PASS=123", ".env")
    assert safe is False
    assert "protected" in msg.lower()


def test_patch_safety_path_traversal_rejection():
    """Verify patch safety engine rejects path traversal attempts."""
    safe, msg = validate_patch_safety("--- a/../../etc/passwd\n+++ b/../../etc/passwd", "../../etc/passwd")
    assert safe is False
    assert "traversal" in msg.lower() or "outside" in msg.lower()


def test_ai_claim_does_not_equal_verification(test_db):
    """
    Enforces invariant: AI CLAIM != SECURITY VERIFICATION.
    If DAST rescan fails (vulnerability still present), status MUST NOT become VERIFIED.
    """
    scan = Scan(target="http://127.0.0.1:8888", status="COMPLETED")
    test_db.add(scan)
    test_db.commit()

    sub = Subdomain(scan_id=scan.id, hostname="127.0.0.1:8888")
    test_db.add(sub)
    test_db.commit()

    finding = Finding(
        subdomain_id=sub.id,
        check_name="SQL Injection",
        severity="HIGH",
        evidence="Vulnerable parameter",
        status=FindingStatus.OPEN.value
    )
    test_db.add(finding)
    test_db.commit()

    # Create remediation with ineffective patch that leaves vulnerable query string intact
    remediation = Remediation(
        finding_id=finding.id,
        affected_file=os.path.join("tests", "vulnerable_app", "app.py"),
        patch="--- dummy patch",
        status=RemediationStatus.PATCH_VALIDATING.value
    )
    test_db.add(remediation)
    test_db.commit()

    # Validate against active vulnerable app without replacing code -> SAST fails
    val_res = validate_remediation_and_rescan(test_db, remediation, target_url="http://127.0.0.1:8888/api/v1/user")
    assert val_res["status"] == RemediationStatus.VALIDATION_FAILED.value
    assert remediation.status == RemediationStatus.VALIDATION_FAILED.value
    test_db.refresh(finding)
    assert finding.status == FindingStatus.OPEN.value  # Must remain OPEN
