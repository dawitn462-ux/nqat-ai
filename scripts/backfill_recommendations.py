"""
Backfill Recommendations Script
-------------------------------
Populates missing recommendation and config_snippet fields for all existing findings in the DB.
"""

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.database import SessionLocal
from backend.models import Finding
from backend.services.remediation_advisor import generate_recommendation


def backfill():
    db = SessionLocal()
    findings = db.query(Finding).all()
    print(f"[+] Total Findings in Database: {len(findings)}")

    updated = 0
    specific_count = 0
    fallback_count = 0

    for f in findings:
        advice = generate_recommendation({"check_name": f.check_name, "severity": f.severity, "evidence": f.evidence})
        f.recommendation = advice.get("recommendation")
        f.config_snippet = advice.get("config_snippet")
        updated += 1

        if "Manual review recommended" in (f.recommendation or ""):
            fallback_count += 1
        else:
            specific_count += 1

    db.commit()
    print(f"[+] Successfully backfilled recommendations for all {updated} database findings!")
    print(f"   - Specific Pattern Mappings Matched: {specific_count}")
    print(f"   - Generic Fallback Mappings Used:   {fallback_count}")
    db.close()

if __name__ == "__main__":
    backfill()
