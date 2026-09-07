"""
Remediation API Router — Exposes REST endpoints for End-to-End Remediation Lifecycle.
---------------------------------------------------------------------------------------
Endpoints:
- POST /api/v1/remediations/analyze/{finding_id}
- POST /api/v1/remediations/{remediation_id}/generate-patch
- POST /api/v1/remediations/{remediation_id}/apply-and-validate
- POST /api/v1/remediations/{remediation_id}/rollback
- GET /api/v1/remediations/{remediation_id}
"""

import json
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Dict, Any

from backend.database import get_db
from backend.models import Finding, Remediation, RemediationStatus
from backend.auth import verify_api_key
from backend.services.remediation_engine import (
    map_finding_to_source,
    generate_remediation_analysis_and_patch,
    validate_patch_safety,
    apply_patch_in_isolated_branch,
    validate_remediation_and_rescan,
    rollback_remediation
)

router = APIRouter(prefix="/api/v1/remediations", tags=["Verified Remediation Lifecycle"])


@router.post("/analyze/{finding_id}", dependencies=[Depends(verify_api_key)])
def analyze_finding_remediation(finding_id: int, db: Session = Depends(get_db)):
    """
    Step 1: Performs finding-to-source mapping and AI root cause analysis.
    """
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding #{finding_id} not found.")

    mapping = map_finding_to_source(db, finding)
    analysis = generate_remediation_analysis_and_patch(db, finding, mapping)

    remediation = Remediation(
        finding_id=finding.id,
        repository=mapping.get("repository"),
        affected_file=mapping.get("affected_file"),
        affected_function=mapping.get("affected_function"),
        vulnerable_line=mapping.get("vulnerable_line"),
        root_cause=analysis.get("root_cause"),
        patch_strategy=analysis.get("patch_strategy"),
        patch=analysis.get("patch"),
        confidence=analysis.get("confidence", 0.0),
        status=analysis.get("status", RemediationStatus.PROPOSED.value)
    )
    db.add(remediation)
    db.commit()
    db.refresh(remediation)

    return remediation


@router.post("/{remediation_id}/apply-and-validate", dependencies=[Depends(verify_api_key)])
def apply_and_validate_remediation(remediation_id: int, db: Session = Depends(get_db)):
    """
    Steps 2 & 3: Validates patch safety, applies patch to isolated branch, runs unit/SAST/DAST tests,
    performs security rescan, and marks status as VERIFIED if all checks pass.
    """
    remediation = db.query(Remediation).filter(Remediation.id == remediation_id).first()
    if not remediation:
        raise HTTPException(status_code=404, detail=f"Remediation #{remediation_id} not found.")

    if not remediation.patch or not remediation.affected_file:
        raise HTTPException(status_code=400, detail="Remediation lacks valid patch content or target file.")

    # 1. Patch Safety Check
    safe, msg = validate_patch_safety(remediation.patch, remediation.affected_file)
    if not safe:
        remediation.status = RemediationStatus.VALIDATION_FAILED.value
        db.commit()
        raise HTTPException(status_code=400, detail=f"Patch Safety Guardrail Rejection: {msg}")

    # 2. Apply patch in isolated branch
    app_res = apply_patch_in_isolated_branch(remediation.id, remediation.affected_file, remediation.patch)
    if app_res.get("status") == RemediationStatus.FAILED.value:
        remediation.status = RemediationStatus.FAILED.value
        db.commit()
        raise HTTPException(status_code=500, detail=app_res.get("error"))

    remediation.branch = app_res.get("branch")
    remediation.base_commit = app_res.get("base_commit")
    remediation.status = RemediationStatus.PATCH_VALIDATING.value
    db.commit()

    # 3. Multi-stage validation & DAST rescan
    val_res = validate_remediation_and_rescan(db, remediation)
    return val_res


@router.post("/{remediation_id}/rollback", dependencies=[Depends(verify_api_key)])
def rollback_remediation_endpoint(remediation_id: int, db: Session = Depends(get_db)):
    """
    Executes Git rollback to restore repository to base_commit state.
    """
    res = rollback_remediation(db, remediation_id)
    return res


@router.get("/{remediation_id}", dependencies=[Depends(verify_api_key)])
def get_remediation_status(remediation_id: int, db: Session = Depends(get_db)):
    """
    Returns full lifecycle status, diff patch, and validation details for a remediation.
    """
    remediation = db.query(Remediation).filter(Remediation.id == remediation_id).first()
    if not remediation:
        raise HTTPException(status_code=404, detail=f"Remediation #{remediation_id} not found.")
    return remediation
