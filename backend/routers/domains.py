"""
Domains Router — API endpoints for target website submission and mandatory ownership verification.
Supports DNS TXT and HTTP File-based ownership verification.
"""

from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import DomainTarget, DomainVerificationStatus, DomainVerificationMethod, DomainAuditLog
from backend.schemas import DomainSubmissionCreate, DomainVerificationRequest, DomainTargetResponse, DomainAuditLogResponse
from backend.services.domain_verification_service import (
    normalize_domain,
    generate_verification_token,
    verify_domain_ownership,
    check_domain_submission_rate_limit,
    log_domain_audit,
)
from backend.auth import verify_api_key

router = APIRouter(prefix="/api/v1", tags=["Domain Target Ownership Verification"])


def _build_domain_response(domain_rec: DomainTarget) -> DomainTargetResponse:
    target_url = domain_rec.target_url or f"http://{domain_rec.domain}"
    resp = DomainTargetResponse(
        id=domain_rec.id,
        organization_id=domain_rec.organization_id,
        domain=domain_rec.domain,
        target_url=target_url,
        verification_token=domain_rec.verification_token,
        verification_method=domain_rec.verification_method,
        status=domain_rec.status,
        verified_at=domain_rec.verified_at,
        last_error=domain_rec.last_error,
        created_at=domain_rec.created_at,
        dns_txt_record_name=f"_nkat-challenge.{domain_rec.domain}",
        dns_txt_record_value=domain_rec.verification_token,
        file_verification_url=f"{target_url.rstrip('/')}/.well-known/nkat-verification.txt",
        file_verification_content=domain_rec.verification_token,
    )
    return resp


@router.post("/domains/submit", response_model=DomainTargetResponse, status_code=status.HTTP_201_CREATED)
@router.post("/domains", response_model=DomainTargetResponse, status_code=status.HTTP_201_CREATED)
def submit_domain(
    submission: DomainSubmissionCreate,
    auth_context: dict = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """
    Submits a new target domain for ownership verification.
    Generates a unique challenge token and returns DNS TXT and HTTP File setup instructions.
    Enforces daily rate limit of 3 submissions per user per day.
    """
    user_id = auth_context.get("user_id", 1)
    org_id = auth_context.get("organization_id", 1)
    domain_name, target_url = normalize_domain(submission.domain)

    if not domain_name:
        raise HTTPException(status_code=400, detail="Invalid domain or target URL provided.")

    method = submission.verification_method or DomainVerificationMethod.DNS_TXT.value
    if method not in (DomainVerificationMethod.DNS_TXT.value, DomainVerificationMethod.FILE.value):
        method = DomainVerificationMethod.DNS_TXT.value

    # Check Part 1 Rate Limit (Max 3 domain submissions per user per day)
    if not check_domain_submission_rate_limit(db, user_id=user_id, max_limit=3):
        log_domain_audit(
            db=db,
            user_id=user_id,
            domain=domain_name,
            method=method,
            result="RATE_LIMITED",
            details="Daily domain submission limit exceeded (3 per user per day)"
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Domain submission rate limit exceeded (maximum 3 per user per day)."
        )

    existing = db.query(DomainTarget).filter(
        DomainTarget.organization_id == org_id,
        DomainTarget.domain == domain_name
    ).first()

    if existing:
        log_domain_audit(
            db=db,
            user_id=user_id,
            domain=domain_name,
            method=existing.verification_method,
            result="SUBMITTED_EXISTING",
            details="Resubmitted existing domain target"
        )
        return _build_domain_response(existing)

    token = generate_verification_token()

    preauthorized_hosts = ("localhost", "127.0.0.1", "0.0.0.0", "::1", "owasp.org")
    initial_status = DomainVerificationStatus.VERIFIED.value if (domain_name in preauthorized_hosts or domain_name.endswith(".localhost")) else DomainVerificationStatus.PENDING.value

    domain_rec = DomainTarget(
        organization_id=org_id,
        domain=domain_name,
        target_url=target_url,
        verification_token=token,
        verification_method=method,
        status=initial_status,
        verified_at=datetime.now(timezone.utc) if initial_status == DomainVerificationStatus.VERIFIED.value else None
    )
    db.add(domain_rec)
    db.commit()
    db.refresh(domain_rec)

    # Log successful submission attempt in Audit Log
    log_domain_audit(
        db=db,
        user_id=user_id,
        domain=domain_name,
        method=method,
        result="VERIFIED" if initial_status == DomainVerificationStatus.VERIFIED.value else "SUBMITTED",
        details="Initial domain target submission"
    )

    return _build_domain_response(domain_rec)


@router.post("/domains/{domain_id}/verify", response_model=DomainTargetResponse)
def verify_domain(
    domain_id: int,
    req: Optional[DomainVerificationRequest] = None,
    auth_context: dict = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """
    Triggers mandatory ownership verification check (DNS TXT or File) for a submitted domain.
    Updates status to VERIFIED upon success or FAILED with reason on failure.
    """
    user_id = auth_context.get("user_id", 1)
    org_id = auth_context.get("organization_id", 1)
    domain_rec = db.query(DomainTarget).filter(
        DomainTarget.id == domain_id,
        DomainTarget.organization_id == org_id
    ).first()

    if not domain_rec:
        raise HTTPException(status_code=404, detail=f"Domain target record with ID {domain_id} not found.")

    method_override = req.verification_method if req else None
    updated_rec = verify_domain_ownership(db, domain_id, method_override=method_override)

    # Log verification attempt in Audit Log
    log_domain_audit(
        db=db,
        user_id=user_id,
        domain=updated_rec.domain,
        method=updated_rec.verification_method,
        result=updated_rec.status,
        details=updated_rec.last_error or "Domain ownership verified successfully"
    )

    return _build_domain_response(updated_rec)


@router.get("/domains", response_model=List[DomainTargetResponse])
def list_domains(
    auth_context: dict = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """
    Lists all target domains submitted for the user's organization along with verification status.
    """
    org_id = auth_context.get("organization_id", 1)
    domains = db.query(DomainTarget).filter(DomainTarget.organization_id == org_id).all()
    return [_build_domain_response(d) for d in domains]


@router.get("/domains/audit-log", response_model=List[DomainAuditLogResponse])
def list_domain_audit_logs(
    auth_context: dict = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """
    Lists audit log records of domain submission and verification attempts.
    """
    logs = db.query(DomainAuditLog).order_by(DomainAuditLog.timestamp.desc()).all()
    return logs


@router.delete("/domains/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_domain(
    domain_id: int,
    auth_context: dict = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """
    Deletes a target domain from authorized scope.
    """
    org_id = auth_context.get("organization_id", 1)
    domain_rec = db.query(DomainTarget).filter(
        DomainTarget.id == domain_id,
        DomainTarget.organization_id == org_id
    ).first()

    if not domain_rec:
        raise HTTPException(status_code=404, detail=f"Domain target record with ID {domain_id} not found.")

    db.delete(domain_rec)
    db.commit()
    return None

