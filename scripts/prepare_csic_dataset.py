"""
CSIC 2010 Vulnerability & WAF Classification Dataset Preparation (Full-Scale Raw Data)
--------------------------------------------------------------------------------------
Parses CSIC 2010 HTTP raw traffic, extracts domain security features,
deduplicates feature vectors to ensure 0 train/test data leakage,
verifies ZERO train/test overlap, and saves the 4 CSV files:
- csic_X_train.csv
- csic_X_test.csv
- csic_y_train.csv
- csic_y_test.csv
"""

import os
import re
import csv
import random
import sys

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
os.makedirs(DATA_DIR, exist_ok=True)

def parse_http_requests(filepath):
    if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
        return []
    requests = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    raw_blocks = re.split(r'\n(?=(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+)', content)
    for block in raw_blocks:
        b = block.strip()
        if b:
            requests.append(b)
    return requests

def extract_features_single(req):
    req_len = float(len(req))
    is_post = 1.0 if req.startswith('POST') else 0.0
    num_params = float(req.count('='))
    special_chars = float(sum(req.count(c) for c in ['\'', '"', '<', '>', '%', ';', '--', '(', ')', '=', '/', '\\', '?', '&']))
    
    sql_regex = re.compile(r'(?:select|union|insert|update|delete|drop|exec|or\s+1=1|--|/\*)', re.IGNORECASE)
    xss_regex = re.compile(r'(?:<script|onerror|onload|javascript:|alert\(|document\.cookie)', re.IGNORECASE)
    trav_regex = re.compile(r'(?:\.\./|\.\.\\|etc/passwd|win\.ini|boot\.ini)', re.IGNORECASE)

    sql_count = float(len(sql_regex.findall(req)))
    xss_count = float(len(xss_regex.findall(req)))
    trav_count = float(len(trav_regex.findall(req)))

    alpha_count = float(sum(1 for c in req if c.isalpha()))
    digit_count = float(sum(1 for c in req if c.isdigit()))
    non_ascii = float(sum(1 for c in req if ord(c) > 127))

    return [
        req_len, is_post, num_params, special_chars,
        sql_count, xss_count, trav_count,
        alpha_count, digit_count, non_ascii
    ]

FEATURE_NAMES = [
    'req_len', 'is_post', 'num_params', 'special_chars',
    'sql_count', 'xss_count', 'trav_count',
    'alpha_count', 'digit_count', 'non_ascii'
]

def prepare_and_save():
    print("================================================================================", flush=True)
    print("PREPARING CSIC 2010 DATASET (X_train, X_test, y_train, y_test)", flush=True)
    print("================================================================================", flush=True)

    f_norm_train = os.path.join(DATA_DIR, "normalTrafficTraining.txt")
    f_norm_test = os.path.join(DATA_DIR, "normalTrafficTest.txt")
    f_anom_test = os.path.join(DATA_DIR, "anomalousTrafficTest.txt")

    norm_reqs = parse_http_requests(f_norm_train) + parse_http_requests(f_norm_test)
    anom_reqs = parse_http_requests(f_anom_test)

    print(f"Parsed Normal Requests: {len(norm_reqs):,}", flush=True)
    print(f"Parsed Attack Requests: {len(anom_reqs):,}", flush=True)

    all_reqs = norm_reqs + anom_reqs
    all_labels = [0]*len(norm_reqs) + [1]*len(anom_reqs)

    # Extract features for all requests
    print("Extracting domain security features...", flush=True)
    all_features = [extract_features_single(r) for r in all_reqs]

    # Feature-level deduplication to guarantee 0 data leakage
    feat_dict = {}
    for feat, lbl in zip(all_features, all_labels):
        t_feat = tuple(feat)
        if t_feat not in feat_dict:
            feat_dict[t_feat] = lbl

    dedup_feats = list(feat_dict.keys())
    dedup_labels = [feat_dict[f] for f in dedup_feats]

    print(f"Total CSIC 2010 Corpus Samples (Feature Deduplicated): {len(dedup_feats):,}", flush=True)
    print(f"Class Balance: Normal (0) = {dedup_labels.count(0):,}, Attack (1) = {dedup_labels.count(1):,}", flush=True)

    indices = list(range(len(dedup_feats)))
    random.seed(42)
    random.shuffle(indices)

    split_idx = int(len(indices) * 0.7)
    train_idx = set(indices[:split_idx])
    test_idx = set(indices[split_idx:])

    # VERIFY ZERO OVERLAP
    print("\n--- Verifying Zero Overlap between Train and Test splits ---", flush=True)
    idx_intersection = train_idx.intersection(test_idx)
    assert len(idx_intersection) == 0, f"ERROR: Found index overlap! {idx_intersection}"

    X_train_rows = [list(dedup_feats[i]) for i in indices[:split_idx]]
    X_test_rows = [list(dedup_feats[i]) for i in indices[split_idx:]]
    train_labels = [dedup_labels[i] for i in indices[:split_idx]]
    test_labels = [dedup_labels[i] for i in indices[split_idx:]]

    set_X_tr = set(tuple(r) for r in X_train_rows)
    set_X_te = set(tuple(r) for r in X_test_rows)
    feat_overlap = len(set_X_tr.intersection(set_X_te))

    print(f"Index Overlap: {len(idx_intersection)} samples", flush=True)
    print(f"Feature Matrix Duplicate Row Overlap: {feat_overlap} rows", flush=True)
    assert feat_overlap == 0, f"Feature overlap error: {feat_overlap}"
    print(" ZERO OVERLAP VERIFIED! Train and Test sets are 100% strictly separated.", flush=True)

    path_X_train = os.path.join(DATA_DIR, "csic_X_train.csv")
    path_X_test = os.path.join(DATA_DIR, "csic_X_test.csv")
    path_y_train = os.path.join(DATA_DIR, "csic_y_train.csv")
    path_y_test = os.path.join(DATA_DIR, "csic_y_test.csv")

    with open(path_X_train, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(FEATURE_NAMES)
        writer.writerows(X_train_rows)

    with open(path_X_test, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(FEATURE_NAMES)
        writer.writerows(X_test_rows)

    with open(path_y_train, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['label'])
        writer.writerows([[lbl] for lbl in train_labels])

    with open(path_y_test, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['label'])
        writer.writerows([[lbl] for lbl in test_labels])

    print("\n--- Saved Clean CSV Files ---", flush=True)
    print(f"csic_X_train.csv: ({len(X_train_rows)}, {len(FEATURE_NAMES)}) -> {path_X_train}", flush=True)
    print(f"csic_X_test.csv:  ({len(X_test_rows)}, {len(FEATURE_NAMES)}) -> {path_X_test}", flush=True)
    print(f"csic_y_train.csv: ({len(train_labels)}, 1) -> {path_y_train}", flush=True)
    print(f"csic_y_test.csv:  ({len(test_labels)}, 1) -> {path_y_test}", flush=True)
    print("================================================================================", flush=True)

if __name__ == "__main__":
    prepare_and_save()
