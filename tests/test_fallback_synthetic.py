"""
Synthetic Finding Fallback Verification Script (Mission 5 Part 4 Follow-up)
-------------------------------------------------------------------------
Tests 3 synthetic findings with check_names that don't match existing patterns:
1. 'Exposed Redis Instance'
2. 'Weak JWT Secret'
3. 'Insecure CORS Policy'

Verifies they fall through to generic fallback ('MANUAL_REVIEW') without false pattern matches.
"""

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.services.remediation_advisor import generate_recommendation


def test_synthetic_fallbacks():
    print("================================================================================", flush=True)
    print("TESTING SYNTHETIC FINDINGS GENERIC FALLBACK BEHAVIOR", flush=True)
    print("================================================================================", flush=True)

    synthetic_findings = [
        {"check_name": "Exposed Redis Instance", "severity": "HIGH", "evidence": "Unauthenticated Redis port 6379 exposed"},
        {"check_name": "Weak JWT Secret", "severity": "MEDIUM", "evidence": "HS256 secret brute-forced: 'secret123'"},
        {"check_name": "Insecure CORS Policy", "severity": "MEDIUM", "evidence": "Access-Control-Allow-Origin: *"},
    ]

    all_passed = True

    for item in synthetic_findings:
        check = item["check_name"]
        res = generate_recommendation(item)

        print(f"\n--- Testing Synthetic Finding: '{check}' ---", flush=True)
        print(f"  Check Name:           {res['check_name']}", flush=True)
        print(f"  Recommendation Title: {res['recommendation_title']}", flush=True)
        print(f"  Remediation Type:     {res['remediation_type']}", flush=True)
        print(f"  Recommendation:       {res['recommendation']}", flush=True)

        # Verification checks
        is_fallback = res.get("remediation_type") == "MANUAL_REVIEW"
        is_title_fallback = res.get("recommendation_title") == "Manual Security Review Recommended"
        contains_fallback_text = "Manual review recommended" in res.get("recommendation", "")

        if is_fallback and is_title_fallback and contains_fallback_text:
            print(f"  Result: [OK] Correctly fell through to generic fallback!", flush=True)
        else:
            all_passed = False
            print(f"  Result: [FAIL] Accidental pattern match occurred! Type: {res.get('remediation_type')}", flush=True)

    print("\n================================================================================", flush=True)
    if all_passed:
        print("[+] ALL 3 SYNTHETIC FINDINGS CORRECTLY FELL THROUGH TO GENERIC FALLBACK!", flush=True)
    else:
        print("[!] SOME SYNTHETIC FINDINGS FAILED FALLBACK VERIFICATION!", flush=True)
    print("================================================================================", flush=True)

    assert all_passed, "Synthetic fallback verification failed!"

if __name__ == "__main__":
    test_synthetic_fallbacks()
