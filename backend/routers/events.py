"""
Continuous & Event-Driven Security Events Router (Pillar 1).
Provides CI/CD Webhook ingestion endpoints and Real-time CVE/EPSS Intelligence sync triggers.
"""

import logging
import asyncio
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from backend.database import get_db
from backend.models import Scan, ScanStatus, Finding
from backend.schemas import EventWebhookRequest
from backend.services.scan_service import _execute_scan_async
from backend.services.prioritization import enrich_finding_prioritization

logger = logging.getLogger("nkat.events_router")

router = APIRouter(prefix="/api/v1/events", tags=["Continuous Security Events & Webhooks"])


@router.post("/webhook")
def handle_cicd_webhook(
    payload: EventWebhookRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    CI/CD Deployment & Commit Push Webhook.
    Triggers immediate targeted security re-scans upon code changes or app deployments.
    """
    target_url = payload.target_url.strip()
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = f"http://{target_url}"

    logger.info(f"[Events Router] Received '{payload.event_type}' webhook for '{target_url}' (Commit: {payload.commit_sha})")

    # Create new Scan record
    new_scan = Scan(
        target=target_url,
        status=ScanStatus.PENDING.value
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    # Launch background scan execution
    def _run_async_scan(scan_id: int, url: str):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_execute_scan_async(scan_id, url))
        finally:
            loop.close()

    background_tasks.add_task(_run_async_scan, new_scan.id, target_url)

    return {
        "status": "SCAN_TRIGGERED",
        "scan_id": new_scan.id,
        "event_type": payload.event_type,
        "target_url": target_url,
        "triggered_by": payload.triggered_by,
        "message": "Real-time CI/CD webhook triggered continuous delta scan successfully."
    }


@router.post("/sync-cve-intel")
def sync_cve_threat_intelligence(
    db: Session = Depends(get_db)
):
    """
    Continuous Threat Intel Sync Endpoint.
    Re-evaluates existing inventory against newly published EPSS scores and CISA KEV additions,
    updating Priority Tiers and Contextual Risk Scores in real-time.
    """
    from backend.services.threat_feed_client import fetch_cisa_kev_cves, fetch_epss_scores

    kev_cves = fetch_cisa_kev_cves()
    findings = db.query(Finding).all()

    updated_count = 0
    p1_boosted = 0

    for finding in findings:
        cwe_or_check = (finding.check_name or "").upper()
        # Match KEV
        if any(kev_id in cwe_or_check for kev_id in kev_cves):
            finding.is_in_cisa_kev = True

        # Re-score via Prioritization Engine
        prev_tier = finding.priority_tier
        enrich_finding_prioritization(db, finding)
        if finding.priority_tier == "P1" and prev_tier != "P1":
            p1_boosted += 1
        updated_count += 1

    db.commit()
    return {
        "status": "COMPLETED",
        "total_findings_evaluated": updated_count,
        "p1_priority_boosts": p1_boosted,
        "message": f"Real-time CVE threat intelligence sync updated {updated_count} findings."
    }
