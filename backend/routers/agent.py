"""
Agentic Decision Loop Router — Exposes POST /api/v1/scans/{scan_id}/agent-triage.
Requires X-API-Key authentication header.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import Scan
from backend.services.agent_loop import run_agent_triage_loop
from backend.auth import verify_api_key

router = APIRouter(prefix="/api/v1/scans/{scan_id}", tags=["Agent Triage"])


@router.post("/agent-triage", dependencies=[Depends(verify_api_key)])
def trigger_agent_triage(scan_id: int, db: Session = Depends(get_db)):
    """
    Executes the autonomous agentic decision loop on completed scan_id:
    Invokes tools dynamically (get_findings, flag_for_priority_review, request_deeper_scan, summarize_risk)
    with strict 5-iteration guardrail.
    """
    db_scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not db_scan:
        raise HTTPException(status_code=404, detail=f"Scan with ID {scan_id} not found")

    result = run_agent_triage_loop(scan_id)
    return result
