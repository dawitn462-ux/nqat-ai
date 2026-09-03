"""
Subdomains Router — API endpoints for subdomain discovery management.
Includes /api/v1/ route versioning and API Key authentication.
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import Scan, Subdomain
from backend.schemas import SubdomainCreate, SubdomainResponse
from backend.auth import verify_api_key

router = APIRouter(prefix="/api/v1/scans/{scan_id}/subdomains", tags=["Subdomains"])


@router.post("/", response_model=SubdomainResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_api_key)])
@router.post("", response_model=SubdomainResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_api_key)])
def add_subdomain_to_scan(scan_id: int, subdomain_in: SubdomainCreate, db: Session = Depends(get_db)):
    """
    Adds a discovered subdomain to a specific scan. Requires X-API-Key header.
    """
    db_scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not db_scan:
        raise HTTPException(status_code=404, detail=f"Scan with ID {scan_id} not found")

    db_subdomain = Subdomain(
        scan_id=scan_id,
        hostname=subdomain_in.hostname,
        ip_address=subdomain_in.ip_address,
    )
    db.add(db_subdomain)
    db.commit()
    db.refresh(db_subdomain)
    return db_subdomain


@router.get("/", response_model=List[SubdomainResponse])
@router.get("", response_model=List[SubdomainResponse])
def list_subdomains_for_scan(scan_id: int, db: Session = Depends(get_db)):
    """
    Lists all subdomains discovered for a specific scan.
    """
    db_scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not db_scan:
        raise HTTPException(status_code=404, detail=f"Scan with ID {scan_id} not found")

    subdomains = db.query(Subdomain).filter(Subdomain.scan_id == scan_id).all()
    return subdomains
