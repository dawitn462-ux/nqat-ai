"""
Audit Logger Service — records all finding status transitions to the audit_logs table.
Tracks: finding_id, action ('approve', 'reject', 'auto-approve', 'rollback'), actor ('human' or 'system'), actor_name, timestamp.
"""

import sys
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from backend.models import AuditLog


def log_audit_event(
    db: Session,
    finding_id: Optional[int] = None,
    action: str = "action",
    actor: str = "agent",
    actor_name: str = None,
    subdomain_id: Optional[int] = None,
    scan_id: Optional[int] = None
) -> AuditLog:
    """
    Creates and persists an AuditLog entry for a finding or agent status transition.
    """
    log_entry = AuditLog(
        finding_id=finding_id,
        subdomain_id=subdomain_id,
        scan_id=scan_id,
        action=action,
        actor=actor,
        actor_name=actor_name,
        timestamp=datetime.now(timezone.utc),
    )
    db.add(log_entry)
    try:
        db.flush()
        sys.stdout.write(
            f"[+] [AuditLog] finding_id={finding_id} | action={action} | actor={actor} ({actor_name})\n"
        )
    except Exception as exc:
        sys.stderr.write(f"[!] Warning logging audit event: {exc}\n")
    return log_entry
