"""
Scans Router — API endpoints for scan lifecycle management and asynchronous background scanning.
Includes /api/v1/ route versioning, API Key authentication, and slowapi rate limiting.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request, status
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address

from backend.database import get_db
from backend.models import Scan, ScanStatus
from backend.schemas import ScanCreate, ScanResponse, ScanStatusUpdate
from backend.services.scan_service import validate_target_authorization, run_scan_pipeline_background
from backend.auth import verify_api_key

limiter = Limiter(key_func=get_remote_address)
router = APIRouter(prefix="/api/v1", tags=["Scans"])


@router.post("/scan", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
@router.post("/scans", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
def trigger_scan(
    request: Request,
    scan_in: ScanCreate,
    background_tasks: BackgroundTasks,
    auth_context: dict = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """
    Validates target against docs/AUTHORIZED_TARGETS.md policy (403 if unauthorized).
    Requires X-API-Key header or Bearer JWT token. Rate limited to 10 requests/minute.
    Launches scan execution in background.
    """
    org_id = auth_context.get("organization_id", 1)
    try:
        validated_target = validate_target_authorization(scan_in.target, db=db, org_id=org_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc)
        )

    db_scan = Scan(target=validated_target, status=ScanStatus.PENDING.value, organization_id=org_id)
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)

    try:
        from backend.services.activity_logger import log_platform_activity
        log_platform_activity(
            db,
            action_type="SCAN_TRIGGER",
            user_id=auth_context.get("user_id"),
            username=auth_context.get("username", "admin"),
            target_resource=f"Target: {validated_target}",
            details=f"Scan #{db_scan.id} initialized for organization #{org_id}"
        )
    except Exception:
        pass

    # Launch background scan pipeline
    background_tasks.add_task(run_scan_pipeline_background, db_scan.id, validated_target)

    return db_scan


@router.get("/scan/{scan_id}", response_model=ScanResponse)
@router.get("/scans/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, request: Request, db: Session = Depends(get_db)):
    """
    Retrieves current status + subdomains + findings for a specific scan_id.
    Enforces multi-tenant organization authorization.
    """
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

    db_scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not db_scan:
        raise HTTPException(status_code=404, detail=f"Scan with ID {scan_id} not found")

    if role != "admin" and org_id is not None and db_scan.organization_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied: You do not have permission to view this scan.")

    return db_scan


@router.get("/scans", response_model=List[ScanResponse])
def list_scans(
    request: Request,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """
    Lists scan records. Scoped strictly by organization_id for non-admin users.
    Admins can view all scans across the platform.
    """
    auth_header = request.headers.get("Authorization") if request else None
    api_key = request.headers.get("X-API-Key") if request else None
    
    org_id = None
    role = None
    
    if auth_header and auth_header.startswith("Bearer "):
        try:
            from backend.auth import decode_access_token
            token_str = auth_header.split(" ")[1]
            payload = decode_access_token(token_str)
            org_id = payload.get("organization_id")
            role = payload.get("role")
        except Exception as exc:
            print(f"[!] Decode token error in list_scans: {exc}")

    if role == "admin":
        scans = db.query(Scan).order_by(Scan.created_at.desc()).offset(skip).limit(limit).all()
    elif org_id is not None:
        scans = db.query(Scan).filter(Scan.organization_id == org_id).order_by(Scan.created_at.desc()).offset(skip).limit(limit).all()
    else:
        # Default fallback for unauthenticated calls: return empty or default scans
        scans = db.query(Scan).filter(Scan.organization_id == 1).order_by(Scan.created_at.desc()).offset(skip).limit(limit).all()

    return scans


@router.patch("/scans/{scan_id}/status", response_model=ScanResponse, dependencies=[Depends(verify_api_key)])
def update_scan_status(scan_id: int, update: ScanStatusUpdate, db: Session = Depends(get_db)):
    """
    Updates status for a scan. Requires X-API-Key header.
    """
    db_scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not db_scan:
        raise HTTPException(status_code=404, detail=f"Scan with ID {scan_id} not found")

    db_scan.status = update.status
    db.commit()
    db.refresh(db_scan)
    return db_scan


@router.get("/scans/{scan_id}/report/pdf")
def export_scan_pdf_report(scan_id: int, db: Session = Depends(get_db)):
    """
    Generates and returns an executive PDF security report for scan_id.
    """
    from fastapi.responses import Response
    from backend.services.pdf_generator import generate_scan_pdf_report

    try:
        pdf_bytes = generate_scan_pdf_report(db, scan_id)
        filename = f"nkat_scan_{scan_id}_executive_report.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF report: {exc}")


@router.get("/waf/user-traffic")
def get_user_waf_traffic_endpoint(domain: str | None = None):
    """
    Returns WAF protection stats and live blocked attack alerts for user website targets on User Dashboard.
    """
    from backend.services.waf_service import get_user_waf_traffic_summary
    return get_user_waf_traffic_summary(target_domain=domain)
