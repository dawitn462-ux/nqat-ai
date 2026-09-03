"""
OWASP BenchmarkJava Dataset Preparation Script (Real Files Only)
--------------------------------------------------------------
Part 2: Reads 2,740 actual Java source files from data/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode/,
extracts static code features, joins each file's feature vector to its official ground-truth label
from expectedresults-1.2.csv by test name, performs feature deduplication & zero train/test overlap audit,
and saves the 4 dataset CSVs:
- owasp_X_train.csv
- owasp_X_test.csv
- owasp_y_train.csv
- owasp_y_test.csv
"""

import os
import sys
import re
import csv
import random

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
BENCHMARK_DIR = os.path.join(DATA_DIR, "BenchmarkJava")
TEST_CODE_DIR = os.path.join(BENCHMARK_DIR, "src", "main", "java", "org", "owasp", "benchmark", "testcode")
EXPECTED_RESULTS_CSV = os.path.join(BENCHMARK_DIR, "expectedresults-1.2.csv")


def parse_ground_truth_labels(csv_path: str) -> dict:
    """
    Parses official OWASP expectedresults-1.2.csv ground truth mapping.
    Maps test_name (e.g. 'BenchmarkTest00001') -> label (1 for true vulnerability, 0 for false/safe).
    """
    labels = {}
    with open(csv_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) >= 3:
                name, cat, real_vuln = parts[0], parts[1], parts[2].lower()
                labels[name] = 1 if real_vuln == 'true' else 0
    return labels


def extract_java_features(java_content: str) -> list:
    """
    Extracts 11 static code domain features from raw Java file text.
    """
    code_len = float(len(java_content))
    num_lines = float(len(java_content.splitlines()))
    num_semicolons = float(java_content.count(';'))
    num_parens = float(java_content.count('(') + java_content.count(')'))
    num_quotes = float(java_content.count('\'') + java_content.count('"'))

    is_sql = 1.0 if any(k in java_content for k in ["executeQuery", "prepareStatement", "SELECT", "WHERE", "createStatement"]) else 0.0
    is_cmdi = 1.0 if any(k in java_content for k in ["exec(", "ProcessBuilder", "Runtime.getRuntime", "Process"]) else 0.0
    is_pathtraver = 1.0 if any(k in java_content for k in ["File(", "FileInputStream", "getCanonicalPath", "FileOutputStream", "File"]) else 0.0
    is_xss = 1.0 if any(k in java_content for k in ["getWriter", "response.write", "HTML", "encodeForHTML", "print("]) else 0.0
    is_crypto = 1.0 if any(k in java_content for k in ["Cipher", "MessageDigest", "KeyGenerator", "SecretKey", "getInstance"]) else 0.0

    special_chars = float(sum(java_content.count(c) for c in ['+', '-', '*', '/', '%', '<', '>', '=', '&', '|', '!']))

    return [
        code_len, num_lines, num_semicolons, num_parens, num_quotes,
        is_sql, is_cmdi, is_pathtraver, is_xss, is_crypto, special_chars
    ]


FEATURE_NAMES = [
    'code_len', 'num_lines', 'num_semicolons', 'num_parens', 'num_quotes',
    'is_sql', 'is_cmdi', 'is_pathtraver', 'is_xss', 'is_crypto', 'special_chars'
]


def prepare_owasp_dataset():
    print("================================================================================", flush=True)
    print("PART 2 — FEATURE EXTRACTION FROM REAL OWASP BENCHMARK JAVA FILES ONLY", flush=True)
    print("================================================================================", flush=True)

    if not os.path.exists(EXPECTED_RESULTS_CSV):
        raise FileNotFoundError(f"Missing official ground truth file: {EXPECTED_RESULTS_CSV}")

    # Parse ground truth
    labels_map = parse_ground_truth_labels(EXPECTED_RESULTS_CSV)
    print(f"[+] Loaded {len(labels_map):,} ground-truth labels from expectedresults-1.2.csv", flush=True)

    processed_samples = []
    processed_labels = []
    file_names = []

    # Read actual .java files from disk
    java_files = [f for f in os.listdir(TEST_CODE_DIR) if f.endswith('.java') and f.startswith('BenchmarkTest')]
    print(f"[+] Found {len(java_files):,} Java test code files on disk in {TEST_CODE_DIR}", flush=True)

    for fname in sorted(java_files):
        test_id = os.path.splitext(fname)[0]
        if test_id in labels_map:
            fpath = os.path.join(TEST_CODE_DIR, fname)
            try:
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                feats = extract_java_features(content)
                processed_samples.append(feats)
                processed_labels.append(labels_map[test_id])
                file_names.append(fname)
            except Exception as exc:
                sys.stderr.write(f"[!] Error reading {fname}: {exc}\n")

    total_processed = len(processed_samples)
    print(f"\n SUCCESSFULLY PROCESSED AND LABELED {total_processed:,} REAL JAVA FILES!", flush=True)
    print(f"   - Vulnerable Real Test Cases (1):     {processed_labels.count(1):,} ({processed_labels.count(1)/total_processed*100:.1f}%)", flush=True)
    print(f"   - Safe / Non-Vulnerable Cases (0):    {processed_labels.count(0):,} ({processed_labels.count(0)/total_processed*100:.1f}%)", flush=True)

    # Feature-level deduplication to guarantee 0 data leakage
    feat_dict = {}
    for feat, lbl in zip(processed_samples, processed_labels):
        t_feat = tuple(feat)
        if t_feat not in feat_dict:
            feat_dict[t_feat] = lbl

    dedup_feats = list(feat_dict.keys())
    dedup_labels = [feat_dict[f] for f in dedup_feats]

    print(f"\n[+] Unique Deduplicated Feature Matrix Rows: {len(dedup_feats):,} samples", flush=True)

    indices = list(range(len(dedup_feats)))
    random.seed(42)
    random.shuffle(indices)

    split_idx = int(len(indices) * 0.7)
    train_idx = set(indices[:split_idx])
    test_idx = set(indices[split_idx:])

    # Zero train/test overlap audit
    idx_intersection = train_idx.intersection(test_idx)
    assert len(idx_intersection) == 0, f"ERROR: Index overlap detected! {idx_intersection}"

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
    assert feat_overlap == 0, f"Feature overlap leakage error: {feat_overlap}"
    print(" ZERO OVERLAP VERIFIED! Train and Test sets are 100% strictly separated.", flush=True)

    path_X_train = os.path.join(DATA_DIR, "owasp_X_train.csv")
    path_X_test = os.path.join(DATA_DIR, "owasp_X_test.csv")
    path_y_train = os.path.join(DATA_DIR, "owasp_y_train.csv")
    path_y_test = os.path.join(DATA_DIR, "owasp_y_test.csv")

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
        writer.writerows([[lbl] for lbl in y_train_labels])

    with open(path_y_test, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['label'])
        writer.writerows([[lbl] for lbl in y_test_labels])

    print("\n--- Saved OWASP Benchmark Dataset CSV Files ---", flush=True)
    print(f"owasp_X_train.csv: ({len(X_train_rows)}, {len(FEATURE_NAMES)}) -> {path_X_train}", flush=True)
    print(f"owasp_X_test.csv:  ({len(X_test_rows)}, {len(FEATURE_NAMES)}) -> {path_X_test}", flush=True)
    print(f"owasp_y_train.csv: ({len(y_train_labels)}, 1) -> {path_y_train}", flush=True)
    print(f"owasp_y_test.csv:  ({len(y_test_labels)}, 1) -> {path_y_test}", flush=True)
    print("================================================================================", flush=True)


if __name__ == "__main__":
    prepare_owasp_dataset()
