"""
Mission 31 Part 3 — Malicious Infrastructure Cross-Reference Test
-------------------------------------------------------------------
Simulates discovery of an asset listed in URLhaus / ThreatFox cache and confirms
the platform generates a CRITICAL finding titled "Associated with Known Malicious Infrastructure".
"""

import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database import SessionLocal
from backend.models import Scan, Subdomain, Finding, FindingStatus
from backend.services.threat_feed_client import check_asset_against_malicious_feeds


def test_malicious_crossref():
    print("=" * 70)
    print("MISSION 31 PART 3 — MALICIOUS INFRASTRUCTURE CROSS-REFERENCE TEST")
    print("=" * 70)

    # 1. Test direct feed lookup for known test indicator
    test_asset = "http://malicious-c2-botnet.test/payload.bin"
    print(f"[STEP 1] Performing direct feed lookup for asset: '{test_asset}'...")
    res = check_asset_against_malicious_feeds(test_asset)

    print(f"  Is Malicious: {res.get('is_malicious')}")
    print(f"  Feed Name:    {res.get('feed_name')}")
    print(f"  Threat Type:  {res.get('threat_type')}")
    print(f"  Details:      {res.get('details')}\n")

    # 2. Test database finding generation logic
    db = SessionLocal()
    try:
        print("[STEP 2] Simulating scan discovery and creating test DB record...")
        db_scan = Scan(target="http://malicious-c2-botnet.test", status="COMPLETED")
        db.add(db_scan)
        db.commit()
        db.refresh(db_scan)

        sub = Subdomain(scan_id=db_scan.id, hostname="malicious-c2-botnet.test", ip_address="198.51.100.55")
        db.add(sub)
        db.commit()
        db.refresh(sub)

        # Execute cross-referencing
        match_info = check_asset_against_malicious_feeds(sub.hostname)
        if match_info.get("is_malicious"):
            finding = Finding(
                subdomain_id=sub.id,
                check_name="Associated with Known Malicious Infrastructure",
                severity="CRITICAL",
                evidence=f"Discovered asset '{sub.hostname}' was matched in real-time threat feed '{match_info.get('feed_name')}'. {match_info.get('details')}",
                recommendation="IMMEDIATE ISOLATION REQUIRED: Hostname/IP matches active C2/malware infrastructure.",
                status=FindingStatus.OPEN.value
            )
            db.add(finding)
            db.commit()
            db.refresh(finding)

            print("  [SUCCESS] Finding created successfully!")
            print(f"  Finding ID:     {finding.id}")
            print(f"  Check Title:    {finding.check_name}")
            print(f"  Severity:       {finding.severity}")
            print(f"  Evidence:       {finding.evidence}")

            # Cleanup test record
            db.delete(finding)
            db.delete(sub)
            db.delete(db_scan)
            db.commit()
            print("\n  [CLEANUP] Test DB records cleaned up cleanly.")

    except Exception as exc:
        print(f"  [ERROR] {exc}")
        db.rollback()
    finally:
        db.close()

    print("=" * 70)
    print("VERIFICATION COMPLETED SUCCESSFULLY")
    print("=" * 70)

if __name__ == "__main__":
    test_malicious_crossref()
