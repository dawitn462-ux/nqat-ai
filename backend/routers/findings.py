"""
Findings Router — API endpoints for vulnerability finding management, recommendation retrieval, human approval, and ML feedback logging.
Includes /api/v1/ route versioning and API Key authentication dependencies on state-changing endpoints.
"""

import re
import json
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import Subdomain, Finding, FindingStatus, FeedbackLabel, AuditLog, Scan
from backend.schemas import FindingCreate, FindingResponse, FindingApprovalRequest, AuditLogResponse, FindingStatusUpdateRequest, ReverifyFindingResponse
from backend.services.remediation_advisor import generate_recommendation
from backend.services.deadline_calculator import calculate_review_deadline
from backend.services.audit_logger import log_audit_event
from backend.auth import verify_api_key

router = APIRouter(tags=["Findings"])


def extract_finding_features(check_name: str, evidence: str = "") -> list:
    """
    Extracts 10 security domain features matching CSIC dataset format from finding check_name and evidence text.
    Feature vector: ['req_len', 'is_post', 'num_params', 'special_chars', 'sql_count', 'xss_count', 'trav_count', 'alpha_count', 'digit_count', 'non_ascii']
    """
    text = f"{check_name} {evidence or ''}"
    req_len = float(len(text))
    is_post = 1.0 if "POST" in text.upper() else 0.0
    num_params = float(text.count("=") + text.count("&"))
    special_chars = float(sum(text.count(c) for c in ['\'', '"', '<', '>', '%', ';', '--', '(', ')', '=', '/', '\\', '?', '&']))

    sql_regex = re.compile(r'(?:select|union|insert|update|delete|drop|exec|or\s+1=1|--|/\*|sqli|injection)', re.IGNORECASE)
    xss_regex = re.compile(r'(?:<script|onerror|onload|javascript:|alert\(|document\.cookie|xss)', re.IGNORECASE)
    trav_regex = re.compile(r'(?:\.\./|\.\.\\|etc/passwd|win\.ini|boot\.ini|directory|path)', re.IGNORECASE)

    sql_count = float(len(sql_regex.findall(text)))
    xss_count = float(len(xss_regex.findall(text)))
    trav_count = float(len(trav_regex.findall(text)))

    alpha_count = float(sum(1 for c in text if c.isalpha()))
    digit_count = float(sum(1 for c in text if c.isdigit()))
    non_ascii = float(sum(1 for c in text if ord(c) > 127))

    return [
        req_len, is_post, num_params, special_chars,
        sql_count, xss_count, trav_count,
        alpha_count, digit_count, non_ascii
    ]


@router.post("/api/v1/subdomains/{subdomain_id}/findings", response_model=FindingResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_api_key)])
@router.post("/api/subdomains/{subdomain_id}/findings", response_model=FindingResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_api_key)])
@router.post("/api/subdomains/{subdomain_id}/findings/", response_model=FindingResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_api_key)])
def add_finding_to_subdomain(subdomain_id: int, finding_in: FindingCreate, db: Session = Depends(get_db)):
    """
    Adds a vulnerability finding to a specific subdomain. Requires X-API-Key header.
    """
    db_subdomain = db.query(Subdomain).filter(Subdomain.id == subdomain_id).first()
    if not db_subdomain:
        raise HTTPException(status_code=404, detail=f"Subdomain with ID {subdomain_id} not found")

    f_dict = {"check_name": finding_in.check_name, "severity": finding_in.severity, "evidence": finding_in.evidence}
    rec_info = generate_recommendation(f_dict)

    deadline = finding_in.review_deadline or calculate_review_deadline(finding_in.severity)

    db_finding = Finding(
        subdomain_id=subdomain_id,
        check_name=finding_in.check_name,
        severity=finding_in.severity,
        evidence=finding_in.evidence,
        recommendation=finding_in.recommendation or rec_info.get("recommendation"),
        config_snippet=finding_in.config_snippet or rec_info.get("config_snippet"),
        status=finding_in.status or FindingStatus.OPEN.value,
        review_deadline=deadline,
        owasp_category=finding_in.owasp_category or rec_info.get("owasp_category"),
        cwe_id=finding_in.cwe_id or (rec_info.get("cwe_info", {}).get("cwe_id") if isinstance(rec_info.get("cwe_info"), dict) else rec_info.get("cwe_id")),
    )
    db.add(db_finding)
    db.commit()
    db.refresh(db_finding)
    return db_finding


@router.get("/api/v1/subdomains/{subdomain_id}/findings", response_model=List[FindingResponse])
@router.get("/api/subdomains/{subdomain_id}/findings", response_model=List[FindingResponse])
@router.get("/api/subdomains/{subdomain_id}/findings/", response_model=List[FindingResponse])
def list_findings_for_subdomain(subdomain_id: int, db: Session = Depends(get_db)):
    """
    Lists all findings for a specific subdomain, enriched with Prioritization Index and SLA clock.
    """
    from backend.services.prioritization import enrich_finding_prioritization
    db_subdomain = db.query(Subdomain).filter(Subdomain.id == subdomain_id).first()
    if not db_subdomain:
        raise HTTPException(status_code=404, detail=f"Subdomain with ID {subdomain_id} not found")

    findings = db.query(Finding).filter(Finding.subdomain_id == subdomain_id).all()
    for f in findings:
        enrich_finding_prioritization(db, f)
    db.commit()
    return findings


@router.get("/api/v1/findings", response_model=List[FindingResponse])
@router.get("/api/findings", response_model=List[FindingResponse])
def list_all_findings(
    request: Request,
    priority_tier: Optional[str] = None,
    status: Optional[str] = None,
    is_sla_breached: Optional[bool] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """
    Lists all findings across target inventory with optional filtering by Priority Tier (P1-P4), Status, or SLA breach status.
    Scoped by organization_id for non-admin users.
    """
    from backend.services.prioritization import enrich_finding_prioritization

    auth_header = request.headers.get("Authorization") if request else None
    org_id = None
    role = None
    if auth_header and auth_header.startswith("Bearer "):
        try:
            from backend.auth import decode_access_token
            token_str = auth_header.split(" ")[1]
            payload = decode_access_token(token_str)
            org_id = payload.get("organization_id")
            role = payload.get("role")
        except Exception:
            pass

    query = db.query(Finding)
    if role != "admin" and org_id is not None:
        query = query.join(Subdomain, Finding.subdomain_id == Subdomain.id)\
                     .join(Scan, Subdomain.scan_id == Scan.id)\
                     .filter(Scan.organization_id == org_id)

    if priority_tier:
        query = query.filter(Finding.priority_tier == priority_tier.upper())
    if status:
        query = query.filter(Finding.status == status.upper())
    if is_sla_breached is not None:
        query = query.filter(Finding.is_sla_breached == is_sla_breached)

    findings = query.order_by(Finding.created_at.desc()).offset(skip).limit(limit).all()
    for f in findings:
        enrich_finding_prioritization(db, f)
    db.commit()
    return findings


@router.put("/api/v1/findings/{finding_id}/status", response_model=FindingResponse)
@router.put("/api/findings/{finding_id}/status", response_model=FindingResponse)
def update_finding_governance_status(
    finding_id: int,
    status_in: FindingStatusUpdateRequest,
    db: Session = Depends(get_db)
):
    """
    Lifecycle Governance State Transition.
    Validates state transitions (OPEN -> UNDER_TRIAGE -> IN_REMEDIATION -> RESOLVED/CLOSED/RISK_ACCEPTED).
    """
    from backend.services.governance import transition_finding_status
    db_finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not db_finding:
        raise HTTPException(status_code=404, detail=f"Finding with ID {finding_id} not found")

    ok, msg = transition_finding_status(
        db=db,
        finding=db_finding,
        new_status=status_in.status,
        actor=status_in.actor or "analyst",
        reason=status_in.reason
    )

    if not ok:
        raise HTTPException(status_code=400, detail=msg)

    return db_finding


@router.post("/api/v1/findings/{finding_id}/reverify", response_model=ReverifyFindingResponse)
@router.post("/api/findings/{finding_id}/reverify", response_model=ReverifyFindingResponse)
def reverify_finding_fix(
    finding_id: int,
    db: Session = Depends(get_db)
):
    """
    Automated Re-Verification Engine.
    Programmatically executes an active targeted check against the target asset to confirm resolution before closing finding.
    """
    from backend.services.governance import reverify_finding_target
    result = reverify_finding_target(db, finding_id)
    if result.get("status") == "NOT_FOUND":
        raise HTTPException(status_code=404, detail="Finding not found")

    return {
        "finding_id": result["finding_id"],
        "status": result["status"],
        "is_reverified": result["is_reverified"],
        "details": result["details"],
        "reverified_at": datetime.now(timezone.utc)
    }


@router.patch("/api/v1/findings/{finding_id}/approve", response_model=FindingResponse, dependencies=[Depends(verify_api_key)])
@router.patch("/api/findings/{finding_id}/approve", response_model=FindingResponse, dependencies=[Depends(verify_api_key)])
@router.patch("/api/subdomains/{subdomain_id}/findings/{finding_id}/approve", response_model=FindingResponse, dependencies=[Depends(verify_api_key)])
def approve_finding(
    finding_id: int,
    approval_in: Optional[FindingApprovalRequest] = None,
    subdomain_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """
    Approves a finding, updating status to RESOLVED and recording features snapshot. Requires X-API-Key header.
    """
    db_finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not db_finding:
        raise HTTPException(status_code=404, detail=f"Finding with ID {finding_id} not found")

    reviewer = approval_in.approved_by if approval_in and approval_in.approved_by else "admin"

    # Capture state snapshot before approval
    snapshot = {
        "status": db_finding.status,
        "evidence": db_finding.evidence,
        "approved_at": str(db_finding.approved_at) if db_finding.approved_at else None,
        "approved_by": db_finding.approved_by,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    db_finding.previous_state = json.dumps(snapshot)

    db_finding.status = FindingStatus.RESOLVED.value
    db_finding.approved_at = datetime.now(timezone.utc)
    db_finding.approved_by = reviewer

    # Record ML feedback label snapshot
    feat_snapshot = extract_finding_features(db_finding.check_name, db_finding.evidence or "")
    fb_label = FeedbackLabel(
        finding_id=finding_id,
        features_snapshot=json.dumps(feat_snapshot),
        human_label="confirmed_vulnerability"
    )
    db.add(fb_label)

    # Record audit log event
    log_audit_event(db, finding_id, action="approve", actor="human", actor_name=reviewer)

    db.commit()
    db.refresh(db_finding)
    return db_finding


@router.patch("/api/v1/findings/{finding_id}/reject", response_model=FindingResponse, dependencies=[Depends(verify_api_key)])
@router.patch("/api/findings/{finding_id}/reject", response_model=FindingResponse, dependencies=[Depends(verify_api_key)])
@router.patch("/api/subdomains/{subdomain_id}/findings/{finding_id}/reject", response_model=FindingResponse, dependencies=[Depends(verify_api_key)])
def reject_finding(
    finding_id: int,
    approval_in: Optional[FindingApprovalRequest] = None,
    subdomain_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """
    Rejects a finding recommendation, keeping status OPEN. Requires X-API-Key header.
    """
    db_finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not db_finding:
        raise HTTPException(status_code=404, detail=f"Finding with ID {finding_id} not found")

    reviewer = approval_in.approved_by if approval_in and approval_in.approved_by else "admin"

    # Capture state snapshot before rejection
    snapshot = {
        "status": db_finding.status,
        "evidence": db_finding.evidence,
        "approved_at": str(db_finding.approved_at) if db_finding.approved_at else None,
        "approved_by": db_finding.approved_by,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    db_finding.previous_state = json.dumps(snapshot)

    db_finding.status = FindingStatus.OPEN.value
    db_finding.approved_at = datetime.now(timezone.utc)
    db_finding.approved_by = f"rejected_by_{reviewer}"

    # Record ML feedback label snapshot
    feat_snapshot = extract_finding_features(db_finding.check_name, db_finding.evidence or "")
    fb_label = FeedbackLabel(
        finding_id=finding_id,
        features_snapshot=json.dumps(feat_snapshot),
        human_label="false_positive"
    )
    db.add(fb_label)

    # Record audit log event
    log_audit_event(db, finding_id, action="reject", actor="human", actor_name=reviewer)

    db.commit()
    db.refresh(db_finding)
    return db_finding


@router.patch("/api/v1/findings/{finding_id}/rollback", response_model=FindingResponse, dependencies=[Depends(verify_api_key)])
@router.patch("/api/findings/{finding_id}/rollback", response_model=FindingResponse, dependencies=[Depends(verify_api_key)])
@router.patch("/api/subdomains/{subdomain_id}/findings/{finding_id}/rollback", response_model=FindingResponse, dependencies=[Depends(verify_api_key)])
def rollback_finding(
    finding_id: int,
    subdomain_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """
    Rolls back a finding's status to its previous_state snapshot. Requires X-API-Key header.
    """
    db_finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not db_finding:
        raise HTTPException(status_code=404, detail=f"Finding with ID {finding_id} not found")

    target_status = FindingStatus.OPEN.value
    if db_finding.previous_state:
        try:
            snap = json.loads(db_finding.previous_state)
            target_status = snap.get("status", FindingStatus.OPEN.value)
        except Exception:
            pass

    db_finding.status = target_status
    db_finding.approved_at = None
    db_finding.approved_by = None

    # Record rollback event snapshot in feedback_labels table
    feat_snapshot = extract_finding_features(db_finding.check_name, db_finding.evidence or "")
    fb_label = FeedbackLabel(
        finding_id=finding_id,
        features_snapshot=json.dumps(feat_snapshot),
        human_label="rollback"
    )
    db.add(fb_label)

    # Record audit log event
    log_audit_event(db, finding_id, action="rollback", actor="human", actor_name="admin")

    db.commit()
    db.refresh(db_finding)
    return db_finding


@router.get("/api/v1/audit-logs", response_model=List[AuditLogResponse])
@router.get("/api/audit-logs", response_model=List[AuditLogResponse])
def list_audit_logs(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """
    Lists audit log entries tracking status transitions.
    """
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit).all()
    return logs
