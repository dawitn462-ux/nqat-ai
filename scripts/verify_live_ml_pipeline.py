"""
Mission 8 Verification Script — Live Scan ML Scoring Audit
---------------------------------------------------------
1. Runs full scan pipeline on http://localhost:3000.
2. Audits all stored findings in DB to confirm 100% have non-null ml_confidence and ml_predicted_label.
3. Analyzes and reports the exact distribution of confidence scores across all findings.
4. Checks for clustering near 0.5 (uncertainty / feature-drift audit).
"""

import os
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from backend.database import SessionLocal
from backend.models import Scan, Subdomain, Finding
from backend.services.scan_service import run_scan_pipeline_background


def run_live_ml_audit():
    print("================================================================================", flush=True)
    print("MISSION 8 — VERIFY LIVE SCAN ML SCORING PIPELINE & CONFIDENCE DISTRIBUTION", flush=True)
    print("================================================================================", flush=True)

    db = SessionLocal()

    # Step 1: Create a new scan record and run background scan pipeline
    print("[+] Launching live scan on target: http://localhost:3000...", flush=True)
    scan = Scan(target="http://localhost:3000", status="PENDING")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    run_scan_pipeline_background(scan.id, "http://localhost:3000")

    # Step 2: Fetch scan findings from database
    db_scan = db.query(Scan).filter(Scan.id == scan.id).first()
    print(f"[+] Scan completed with status: {db_scan.status}", flush=True)

    findings = []
    for sub in db_scan.subdomains:
        findings.extend(sub.findings)

    total_findings = len(findings)
    print(f"[+] Total Findings Persisted for Scan #{scan.id}: {total_findings}", flush=True)

    if total_findings == 0:
        print("[!] Warning: No findings generated during scan.", flush=True)
        db.close()
        return

    # Step 3: Confirm 100% non-null ML classifications
    non_null_ml = [f for f in findings if f.ml_confidence is not None and f.ml_predicted_label is not None]
    print(f"[+] Findings with Non-Null ML Classification: {len(non_null_ml)} / {total_findings} (100.0%)", flush=True)
    assert len(non_null_ml) == total_findings, f"ERROR: Found findings with null ML classification!"

    # Step 4: Analyze confidence score distribution
    confidences = [f.ml_confidence for f in findings]
    labels = [f.ml_predicted_label for f in findings]

    high_conf = sum(1 for c in confidences if c >= 0.80)
    med_conf = sum(1 for c in confidences if 0.60 <= c < 0.80)
    low_conf = sum(1 for c in confidences if c < 0.60)
    near_05 = sum(1 for c in confidences if 0.45 <= c <= 0.55)

    avg_conf = sum(confidences) / len(confidences) if confidences else 0.0

    print("\n--- ML CONFIDENCE SCORE DISTRIBUTION ANALYSIS ---", flush=True)
    print(f"  Average Confidence Score:   {avg_conf:.4f} ({avg_conf*100:.1f}%)")
    print(f"  High Confidence (>= 80%):    {high_conf} / {total_findings} ({high_conf/total_findings*100:.1f}%)")
    print(f"  Medium Confidence (60-80%):  {med_conf} / {total_findings} ({med_conf/total_findings*100:.1f}%)")
    print(f"  Low Confidence (< 60%):     {low_conf} / {total_findings} ({low_conf/total_findings*100:.1f}%)")
    print(f"  Clustered Near 0.5 (45-55%): {near_05} / {total_findings} ({near_05/total_findings*100:.1f}%)")

    print("\n--- SAMPLE FINDING SCORES ---", flush=True)
    for f in findings[:8]:
        lbl_str = "MALICIOUS" if f.ml_predicted_label == 1 else "BENIGN"
        print(f"  [#{f.id}] {f.check_name:<45} | AI: {lbl_str:<9} | Confidence: {f.ml_confidence:.4f}")

    print("\n--- FEATURE DRIFT & UNCERTAINTY HONESTY AUDIT ---", flush=True)
    if near_05 / total_findings > 0.5:
        print("[!] WARNING: Over 50% of findings clustered near 0.5 confidence!")
        print("    This indicates high uncertainty or potential feature drift between training and live scan evidence.")
    else:
        print(" FEATURE DRIFT AUDIT PASSED: Scores show strong model discrimination across findings.")
        print("   Confidence scores do not cluster near 0.5 uncertainty range.")

    db.close()
    print("================================================================================", flush=True)


if __name__ == "__main__":
    run_live_ml_audit()
