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
from backend.schemas import DomainSubmissionCreate, DomainVerificationRequest, DomainTargetResponse, DomainAuditLogResponse, DomainQuotaResponse
from backend.services.domain_verification_service import (
    normalize_domain,
    generate_verification_token,
    verify_domain_ownership,
    check_domain_submission_rate_limit,
    get_user_domain_submission_count_24h,
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
        owner=domain_rec.owner or ("Vuln Bookstore" if domain_rec.domain == "localhost" else "Security Team"),
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

    preauthorized_hosts = ("localhost", "127.0.0.1", "0.0.0.0", "::1")
    is_preauthorized = (domain_name in preauthorized_hosts or domain_name.endswith(".localhost"))

    # 1. If target already exists in org, update target_url and ensure verified if preauthorized
    existing = db.query(DomainTarget).filter(
        DomainTarget.organization_id == org_id,
        DomainTarget.domain == domain_name
    ).first()

    if existing:
        if target_url and target_url != existing.target_url:
            existing.target_url = target_url
        if is_preauthorized and existing.status != DomainVerificationStatus.VERIFIED.value:
            existing.status = DomainVerificationStatus.VERIFIED.value
            existing.verified_at = datetime.now(timezone.utc)
            existing.last_error = None
        db.commit()
        db.refresh(existing)
        log_domain_audit(
            db=db,
            user_id=user_id,
            domain=domain_name,
            method=existing.verification_method,
            result="SUBMITTED_EXISTING",
            details="Resubmitted existing domain target"
        )
        return _build_domain_response(existing)

    # 2. Rate limit check (Max 3 external domain submissions per user per 24h; local loopback targets exempt)
    if not is_preauthorized and not check_domain_submission_rate_limit(db, user_id=user_id, max_limit=3):
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
            detail="Domain submission rate limit exceeded (maximum 3 per user per day). Click 'Reset Quota' to refresh your daily allowance."
        )

    token = generate_verification_token()

    initial_status = DomainVerificationStatus.VERIFIED.value if is_preauthorized else DomainVerificationStatus.PENDING.value

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
    Localhost / loopback domains are automatically verified immediately without remote DNS calls.
    """
    user_id = auth_context.get("user_id", 1)
    org_id = auth_context.get("organization_id", 1)
    domain_rec = db.query(DomainTarget).filter(
        DomainTarget.id == domain_id,
        DomainTarget.organization_id == org_id
    ).first()

    if not domain_rec:
        raise HTTPException(status_code=404, detail=f"Domain target record with ID {domain_id} not found.")

    preauthorized_hosts = ("localhost", "127.0.0.1", "0.0.0.0", "::1")
    if domain_rec.domain in preauthorized_hosts or domain_rec.domain.endswith(".localhost"):
        domain_rec.status = DomainVerificationStatus.VERIFIED.value
        domain_rec.verified_at = datetime.now(timezone.utc)
        domain_rec.last_error = None
        db.commit()
        db.refresh(domain_rec)
        log_domain_audit(
            db=db,
            user_id=user_id,
            domain=domain_rec.domain,
            method=domain_rec.verification_method,
            result="VERIFIED",
            details="Local loopback development target auto-verified"
        )
        return _build_domain_response(domain_rec)

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


@router.get("/domains/quota", response_model=DomainQuotaResponse)
def get_domain_quota(
    auth_context: dict = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """
    Returns the current authenticated user's domain submission / challenge token quota (3 per user per 24 hours).
    Quota usage is strictly isolated per user_id.
    """
    user_id = auth_context.get("user_id", 1)
    used = get_user_domain_submission_count_24h(db, user_id=user_id)
    return DomainQuotaResponse(
        user_id=user_id,
        daily_limit=3,
        used_24h=used,
        remaining_24h=max(0, 3 - used)
    )


@router.post("/domains/quota/reset", response_model=DomainQuotaResponse)
def reset_domain_quota(
    auth_context: dict = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """
    Resets the current user's domain submission daily quota by purging past 24h audit submission entries.
    """
    user_id = auth_context.get("user_id", 1)
    db.query(DomainAuditLog).filter(
        (DomainAuditLog.user_id == user_id) | (DomainAuditLog.user_id.is_(None)),
        DomainAuditLog.result.in_(["SUBMITTED", "VERIFIED", "SUBMITTED_EXISTING", "RATE_LIMITED"])
    ).delete(synchronize_session=False)
    db.commit()

    return DomainQuotaResponse(
        user_id=user_id,
        daily_limit=3,
        used_24h=0,
        remaining_24h=3
    )


