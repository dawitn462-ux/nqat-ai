import sys
import json
from backend.services.nvd_classifier_service import classify_cve_description

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

def run_e2e_cve_traces():
    sample_cves = [
        {
            "cve_id": "CVE-2018-3810",
            "description": "Authentication Bypass vulnerability in the Oturia Smart Google Code Inserter plugin before 3.5 for WordPress allows unauthenticated attackers to insert arbitrary JavaScript or HTML code (via the sgcgoogleanalytic parameter) that runs on all pages served by WordPress. The saveGoogleCode() function in smartgooglecode.php does not check if the current request is made by an authorized user, thus allowing any unauthenticated user to successfully update the inserted code.",
            "attack_vector": "NETWORK",
            "exploitability_score": 3.9,
            "nvd_actual_severity": "CRITICAL",
            "nvd_base_score": 9.8
        },
        {
            "cve_id": "CVE-2017-18006",
            "description": "netpub/server.np in Extensis Portfolio NetPublish has XSS in the quickfind parameter, aka Open Bug Bounty ID OBB-290447.",
            "attack_vector": "NETWORK",
            "exploitability_score": 2.8,
            "nvd_actual_severity": "MEDIUM",
            "nvd_base_score": 6.1
        },
        {
            "cve_id": "CVE-2020-0001",
            "description": "In getProcessRecordLocked of ActivityManagerService.java, there is a possible privilege escalation due to a confused deputy. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Product: Android. Versions: Android-8.0, Android-8.1, Android-9, Android-10. Android ID: A-140055304.",
            "attack_vector": "LOCAL",
            "exploitability_score": 1.8,
            "nvd_actual_severity": "HIGH",
            "nvd_base_score": 7.8
        }
    ]

    print("=======================================================================")
    print("      MISSION 24 END-TO-END CVE EVIDENCE CHAIN TRACE REPORT             ")
    print("=======================================================================\n")

    for item in sample_cves:
        cve_id = item["cve_id"]
        desc = item["description"]
        av = item["attack_vector"]
        exp = item["exploitability_score"]
        actual_sev = item["nvd_actual_severity"]
        
        # Run through ML classifier pipeline
        res = classify_cve_description(desc, attack_vector=av, exploitability_score=exp)
        pred_sev = res["predicted_severity"]
        conf = res["confidence"]
        feats = res["features_extracted"]
        keywords = res["top_keywords"]

        match_status = " MATCH" if pred_sev == actual_sev else f" DIFF (Predicted: {pred_sev}, NVD: {actual_sev})"

        print(f" CVE ID: {cve_id}")
        print(f"  - Description: \"{desc}\"")
        print(f"  - Extracted Features:")
        print(f"      • Length: {feats['desc_len']} chars | Words: {feats['word_count']}")
        print(f"      • Keyword Flags: AuthBypass={feats['is_auth_bypass']}, Unauthenticated={feats['is_unauthenticated']}, Injection={feats['is_injection']}, XSS={feats['is_xss']}, RCE={feats['is_rce']}")
        print(f"      • NVD Vector Component: Attack Vector={av}, Exploitability Score={exp}")
        print(f"      • Top TF-IDF Keywords: {keywords}")
        print(f"  - ML Model Prediction: {pred_sev} (Confidence: {conf:.2%})")
        print(f"  - NVD Listed Severity: {actual_sev} (Base Score: {item['nvd_base_score']})")
        print(f"  - Comparison Outcome:  {match_status}")
        print("-" * 75 + "\n")

if __name__ == "__main__":
    run_e2e_cve_traces()
