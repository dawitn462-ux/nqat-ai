"""
Threat Correlation & Attack Path Graph Router
----------------------------------------------
Exposes GET /api/v1/scans/{scan_id}/threat-graph endpoint returning
directed attack graph nodes, edges, compound attack chains, and composite threat vector scores.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.services.threat_correlation import compute_attack_path_graph

router = APIRouter(prefix="/api/v1", tags=["Threat Correlation Graph"])


@router.get("/scans/{scan_id}/threat-graph")
def get_scan_threat_graph(scan_id: int, db: Session = Depends(get_db)):
    """
    Computes and returns directed attack path graph nodes, edges,
    compound attack chains, and composite threat score (0-100) for a scan_id.
    """
    graph_data = compute_attack_path_graph(db, scan_id)
    if not graph_data or graph_data["total_nodes"] == 0:
        raise HTTPException(status_code=404, detail=f"No threat graph found for Scan ID {scan_id}")
    return graph_data
