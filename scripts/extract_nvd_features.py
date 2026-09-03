import os
import sys
import json
import re
import pandas as pd
import numpy as np

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

def extract_cve_text_and_vector_features(record: dict) -> dict:
    desc = record.get("description", "")
    desc_lower = desc.lower()
    
    # 1. Real Text Structural Features
    desc_len = len(desc)
    word_count = len(desc.split())
    
    # 2. Keyword Presence Features (0 or 1)
    is_injection = int(bool(re.search(r'\b(injection|sqli|sql injection|command injection)\b', desc_lower)))
    is_overflow = int(bool(re.search(r'\b(overflow|buffer overflow|stack overflow|heap overflow|memory corruption)\b', desc_lower)))
    is_auth_bypass = int(bool(re.search(r'\b(authentication bypass|auth bypass|bypass authentication|privilege escalation)\b', desc_lower)))
    is_xss = int(bool(re.search(r'\b(xss|cross-site scripting|cross site scripting)\b', desc_lower)))
    is_rce = int(bool(re.search(r'\b(remote code execution|execute arbitrary code|arbitrary code execution|code execution)\b', desc_lower)))
    is_dos = int(bool(re.search(r'\b(denial of service|dos|crash|resource exhaustion)\b', desc_lower)))
    is_unauthenticated = int(bool(re.search(r'\b(unauthenticated|unauthorized|without authentication)\b', desc_lower)))
    is_root_admin = int(bool(re.search(r'\b(root|administrator|admin privileges|system privileges|root privileges)\b', desc_lower)))
    
    # Authoritative Ground Truth Label directly from NVD
    label_severity = record.get("base_severity", "MEDIUM").upper()

    return {
        "cve_id": record.get("cve_id"),
        "desc_len": desc_len,
        "word_count": word_count,
        "is_injection": is_injection,
        "is_overflow": is_overflow,
        "is_auth_bypass": is_auth_bypass,
        "is_xss": is_xss,
        "is_rce": is_rce,
        "is_dos": is_dos,
        "is_unauthenticated": is_unauthenticated,
        "is_root_admin": is_root_admin,
        "ground_truth_severity": label_severity
    }

def main():
    json_path = os.path.join("data", "nvd_cve_dataset.json")
    if not os.path.exists(json_path):
        print(f"[!] Error: {json_path} not found.")
        sys.exit(1)
        
    with open(json_path, "r", encoding="utf-8") as f:
        records = json.load(f)
        
    print(f"[*] Processing {len(records):,} real NVD CVE entries for feature extraction...")
    
    feature_rows = []
    for r in records:
        f_dict = extract_cve_text_and_vector_features(r)
        if f_dict["ground_truth_severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            feature_rows.append(f_dict)
            
    df = pd.DataFrame(feature_rows)
    csv_path = os.path.join("data", "nvd_features_dataset.csv")
    df.to_csv(csv_path, index=False)
    
    print(f"\n Feature extraction complete! Saved {len(df):,} rows to {csv_path}")
    print("\n--- Feature Dataset Summary ---")
    print(df.describe().T[["mean", "std", "min", "max"]])
    print("\n--- Ground Truth Class Distribution ---")
    print(df["ground_truth_severity"].value_counts())

if __name__ == "__main__":
    main()
