import sys
import os
from sqlalchemy.orm import Session

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.database import SessionLocal, engine
from backend.models import DomainAuditLog

def reset_quota():
    db = SessionLocal()
    try:
        deleted = db.query(DomainAuditLog).filter(
            DomainAuditLog.result.in_(["SUBMITTED", "VERIFIED", "SUBMITTED_EXISTING", "RATE_LIMITED"])
        ).delete(synchronize_session=False)
        db.commit()
        print(f"Successfully deleted {deleted} past domain audit log entries for rate limit reset.")
    except Exception as e:
        db.rollback()
        print(f"Error resetting domain quota: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    reset_quota()
