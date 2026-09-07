"""
Agentic Security Orchestrator Router
------------------------------------
Exposes assessment-level orchestration endpoints:
- POST /api/v1/assessments/{assessment_id}/orchestrate
- GET /api/v1/assessments/{assessment_id}/context
- GET /api/v1/agent/capabilities
- POST /api/v1/scans/{scan_id}/agent-triage (Backward compatible)
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Dict, Any

from backend.database import get_db
from backend.models import Scan, Assessment
from backend.services.agent_loop import run_agent_orchestrator_loop, run_agent_triage_loop
from backend.services.agent_capability_gateway import orchestrator_gateway
from backend.auth import verify_api_key

router = APIRouter(prefix="/api/v1", tags=["Agentic Security Orchestrator"])


@router.post("/assessments/{assessment_id}/orchestrate", dependencies=[Depends(verify_api_key)])
def orchestrate_assessment(assessment_id: int, db: Session = Depends(get_db)):
    """
    Executes full assessment security orchestration loop across SAST, DAST, correlation, and remediation.
    """
    ass = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not ass:
        raise HTTPException(status_code=404, detail=f"Assessment #{assessment_id} not found.")

    res = run_agent_orchestrator_loop(assessment_id)
    return res


@router.get("/assessments/{assessment_id}/context", dependencies=[Depends(verify_api_key)])
def get_assessment_context(assessment_id: int, db: Session = Depends(get_db)):
    """
    Returns bounded assessment context for UI visualizer.
    """
    res = orchestrator_gateway.execute_capability(db, "get_assessment_context", assessment_id=assessment_id)
    return res


@router.get("/agent/capabilities", dependencies=[Depends(verify_api_key)])
def list_agent_capabilities():
    """
    Lists all registered security capabilities in the Agent Capability Gateway.
    """
    caps = orchestrator_gateway.list_capabilities()
    return [
        {
            "id": c.id,
            "name": c.name,
            "category": c.category,
            "description": c.description,
            "requires_authorization": c.requires_authorization,
            "risk_level": c.risk_level,
            "timeout_seconds": c.timeout_seconds,
            "enabled": c.enabled
        }
        for c in caps
    ]


@router.post("/scans/{scan_id}/agent-triage", dependencies=[Depends(verify_api_key)])
def trigger_agent_triage(scan_id: int, db: Session = Depends(get_db)):
    """
    Backward-compatible single-scan agent triage endpoint.
    """
    db_scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not db_scan:
        raise HTTPException(status_code=404, detail=f"Scan with ID {scan_id} not found")

    result = run_agent_triage_loop(scan_id)
    return result


@router.get("/agent/tools", dependencies=[Depends(verify_api_key)])
def list_authorized_tools():
    """
    Backward-compatible authorized tool listing endpoint.
    """
    return list_agent_capabilities()
