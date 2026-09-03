"""
Unified Activity Logger Service — Mission 30 Part 1
---------------------------------------------------
Centralized activity logging engine capturing platform activities across:
1. User Logins (auth)
2. Scan Triggers (scanner)
3. Finding Approvals / Rejections (remediations)
4. Domain Target Submissions & Verifications (domains)
5. Admin Role & Governance Changes (user management)

Maintains platform_activity_logs table and provides unified querying.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.models import PlatformActivityLog, AuditLog, DomainAuditLog, User

logger = logging.getLogger("nkat.activity_logger")


def log_platform_activity(
    db: Session,
    action_type: str,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    target_resource: Optional[str] = None,
    ip_address: Optional[str] = "127.0.0.1",
    details: Optional[str] = None
) -> PlatformActivityLog:
    """
    Logs a unified activity event to platform_activity_logs table.
    """
    try:
        if user_id and not username:
            u_rec = db.query(User).filter(User.id == user_id).first()
            if u_rec:
                username = u_rec.username

        if not username:
            username = "system"

        log_entry = PlatformActivityLog(
            user_id=user_id,
            username=username,
            action_type=action_type.upper(),
            target_resource=target_resource,
            ip_address=ip_address or "127.0.0.1",
            details=details,
            timestamp=datetime.now(timezone.utc)
        )
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)
        logger.info(f"[ActivityLog] {username} -> {action_type} on {target_resource}")
        return log_entry
    except Exception as exc:
        logger.warning(f"[!] Error recording platform activity log: {exc}")
        db.rollback()
        return None


def get_unified_activity_logs(db: Session, limit: int = 50, action_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Returns unified activity log stream joining PlatformActivityLog, AuditLog, and DomainAuditLog records.
    """
    unified_entries = []

    # 1. Fetch from PlatformActivityLog
    query = db.query(PlatformActivityLog)
    if action_filter:
        query = query.filter(PlatformActivityLog.action_type == action_filter.upper())

    activity_logs = query.order_by(desc(PlatformActivityLog.timestamp)).limit(limit).all()

    for act in activity_logs:
        unified_entries.append({
            "id": f"act_{act.id}",
            "user_id": act.user_id,
            "username": act.username or "system",
            "action_type": act.action_type,
            "target_resource": act.target_resource or "N/A",
            "ip_address": act.ip_address or "127.0.0.1",
            "details": act.details or "",
            "timestamp": act.timestamp.isoformat() if act.timestamp else datetime.now(timezone.utc).isoformat()
        })

    # 2. Join historical AuditLog entries if available
    try:
        audit_logs = db.query(AuditLog).order_by(desc(AuditLog.timestamp)).limit(limit).all()
        for a in audit_logs:
            action_map = {
                "approve": "FINDING_APPROVE",
                "auto-approve": "AUTO_APPROVE",
                "reject": "FINDING_REJECT",
                "manual_status_change": "FINDING_STATUS_CHANGE"
            }
            action_type = action_map.get(a.action, a.action.upper())

            # Check for duplicate by timestamp / resource
            dupe = any(e["target_resource"] == f"Finding #{a.finding_id}" and e["action_type"] == action_type for e in unified_entries)
            if not dupe:
                unified_entries.append({
                    "id": f"aud_{a.id}",
                    "user_id": a.user_id,
                    "username": a.actor or "system",
                    "action_type": action_type,
                    "target_resource": f"Finding #{a.finding_id}",
                    "ip_address": "127.0.0.1",
                    "details": a.details or f"Finding state changed from {a.previous_state} to {a.new_state}",
                    "timestamp": a.timestamp.isoformat() if a.timestamp else datetime.now(timezone.utc).isoformat()
                })
    except Exception:
        pass

    # 3. Join historical DomainAuditLog entries if available
    try:
        domain_logs = db.query(DomainAuditLog).order_by(desc(DomainAuditLog.timestamp)).limit(limit).all()
        for d in domain_logs:
            action_type = "DOMAIN_VERIFICATION"
            u_name = d.user.username if d.user else "system"
            dupe = any(e["target_resource"] == f"Domain: {d.domain}" for e in unified_entries)
            if not dupe:
                unified_entries.append({
                    "id": f"dom_{d.id}",
                    "user_id": d.user_id,
                    "username": u_name,
                    "action_type": action_type,
                    "target_resource": f"Domain: {d.domain}",
                    "ip_address": "127.0.0.1",
                    "details": d.details or f"Verification method: {d.method}, result: {d.result}",
                    "timestamp": d.timestamp.isoformat() if d.timestamp else datetime.now(timezone.utc).isoformat()
                })
    except Exception:
        pass

    # Sort all merged logs by timestamp descending
    unified_entries.sort(key=lambda x: x["timestamp"], reverse=True)
    return unified_entries[:limit]
