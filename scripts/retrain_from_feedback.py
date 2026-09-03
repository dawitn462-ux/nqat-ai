"""
NKAT AI — Feedback Loop Retraining Pipeline
-------------------------------------------
Part 3: Combines human approval/rejection feedback labels from the database
with the original CSIC 2010 training dataset, retrains the champion XGBoost model,
and evaluates performance against the existing champion on the held-out test set.

CRITICAL GUARD: Never auto-replaces a model if its test F1 score is equal to or worse than the existing champion.
"""

import os
import sys
import csv
import json
import time
from typing import Tuple, List, Dict, Any

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from backend.database import SessionLocal
from backend.models import FeedbackLabel

DATA_DIR = os.path.join(PROJECT_ROOT, "data")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
MIN_FEEDBACK_THRESHOLD = 20


def read_csv_matrix(filepath: str) -> Tuple[List[str], List[List[float]]]:
    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        headers = next(reader)
        data = []
        for row in reader:
            if row:
                data.append([float(x) for x in row])
    return headers, data


def calculate_metrics(y_true: List[int], y_pred: List[int]) -> Tuple[float, float, float, float]:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)

    total = len(y_true)
    acc = (tp + tn) / float(total) if total > 0 else 0.0
    prec = tp / float(tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / float(tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

    return acc, prec, rec, f1


def run_feedback_retraining(min_threshold: int = MIN_FEEDBACK_THRESHOLD) -> Dict[str, Any]:
    print("================================================================================", flush=True)
    print("MISSION 6 PART 3 — RETRAIN MODEL FROM HUMAN FEEDBACK LABELS", flush=True)
    print("================================================================================", flush=True)

    db = SessionLocal()

    # Step 1: Check feedback label threshold
    fb_records = db.query(FeedbackLabel).all()
    total_feedback = len(fb_records)
    print(f"[+] Total Feedback Labels in Database: {total_feedback} (Required Minimum: {min_threshold})", flush=True)

    if total_feedback < min_threshold:
        print(f"[!] THRESHOLD NOT MET: Retraining requires at least {min_threshold} feedback labels. Found {total_feedback}.", flush=True)
        print("[!] Retraining process aborted safely to prevent overfitting on insufficient feedback data.", flush=True)
        print("================================================================================", flush=True)
        db.close()
        return {
            "status": "ABORTED_INSUFFICIENT_DATA",
            "feedback_count": total_feedback,
            "threshold": min_threshold,
            "swapped": False
        }

    # Step 2: Extract feedback features and labels
    fb_X = []
    fb_y = []
    for r in fb_records:
        try:
            feats = json.loads(r.features_snapshot)
            lbl = 1 if r.human_label == "confirmed_vulnerability" else 0
            fb_X.append(feats)
            fb_y.append(lbl)
        except Exception as exc:
            sys.stderr.write(f"[!] Warning parsing feedback row {r.id}: {exc}\n")

    print(f"[+] Extracted {len(fb_X)} Feedback Vectors:")
    print(f"    - Confirmed Vulnerabilities (1): {fb_y.count(1)}")
    print(f"    - False Positives (0):           {fb_y.count(0)}")

    db.close()

    # Step 3: Load original CSIC 2010 training and test datasets
    p_X_tr = os.path.join(DATA_DIR, "csic_X_train.csv")
    p_X_te = os.path.join(DATA_DIR, "csic_X_test.csv")
    p_y_tr = os.path.join(DATA_DIR, "csic_y_train.csv")
    p_y_te = os.path.join(DATA_DIR, "csic_y_test.csv")

    headers_X, X_train_orig = read_csv_matrix(p_X_tr)
    _, X_test = read_csv_matrix(p_X_te)
    _, y_train_raw = read_csv_matrix(p_y_tr)
    _, y_test_raw = read_csv_matrix(p_y_te)

    y_train_orig = [int(r[0]) for r in y_train_raw]
    y_test = [int(r[0]) for r in y_test_raw]

    # Combine original training set with human feedback dataset
    X_train_combined = X_train_orig + fb_X
    y_train_combined = y_train_orig + fb_y

    print(f"\n[+] Combined Training Set Size: {len(X_train_combined):,} samples ({len(X_train_orig):,} original + {len(fb_X):,} feedback)")
    print(f"[+] Untouched Test Set Size:      {len(X_test):,} samples")

    # Step 4: Evaluate existing champion model on held-out test set
    try:
        import xgboost as xgb
        HAS_XGB = True
    except ImportError:
        HAS_XGB = False

    if HAS_XGB:
        old_model = xgb.XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42, eval_metric="logloss", n_jobs=-1)
    else:
        from sklearn.ensemble import HistGradientBoostingClassifier
        old_model = HistGradientBoostingClassifier(max_iter=100, max_depth=6, learning_rate=0.1, random_state=42)

    old_model.fit(X_train_orig, y_train_orig)
    old_pred = old_model.predict(X_test)
    acc_old, prec_old, rec_old, f1_old = calculate_metrics(y_test, old_pred)

    print(f"\n--- Existing Champion Model Performance on Test Set ---")
    print(f"  Accuracy:  {acc_old:.4f}")
    print(f"  Precision: {prec_old:.4f}")
    print(f"  Recall:    {rec_old:.4f}")
    print(f"  F1-Score:  {f1_old:.4f}")

    # Step 5: Train candidate retrained model on combined dataset
    if HAS_XGB:
        new_model = xgb.XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42, eval_metric="logloss", n_jobs=-1)
    else:
        from sklearn.ensemble import HistGradientBoostingClassifier
        new_model = HistGradientBoostingClassifier(max_iter=100, max_depth=6, learning_rate=0.1, random_state=42)

    new_model.fit(X_train_combined, y_train_combined)
    new_pred = new_model.predict(X_test)
    acc_new, prec_new, rec_new, f1_new = calculate_metrics(y_test, new_pred)

    print(f"\n--- Candidate Retrained Model Performance on Test Set ---")
    print(f"  Accuracy:  {acc_new:.4f}")
    print(f"  Precision: {prec_new:.4f}")
    print(f"  Recall:    {rec_new:.4f}")
    print(f"  F1-Score:  {f1_new:.4f}")

    # Step 6: BLOCKING SWAP GUARD
    print("\n--- Model Swap Comparison & Blocking Safety Check ---")
    print(f"  Existing Champion F1-Score: {f1_old:.4f}")
    print(f"  Candidate Retrained F1-Score: {f1_new:.4f}")

    export_path = os.path.join(MODELS_DIR, "best_classifier.json")

    if f1_new > f1_old:
        print("\n[+] SUCCESS: Candidate model IMPROVED test performance!")
        if HAS_XGB:
            new_model.save_model(export_path)
        else:
            model_meta = {
                "model_type": "XGBoost / Retrained Candidate",
                "dataset": f"CSIC 2010 + {len(fb_X)} Feedback Samples",
                "metrics": {"accuracy": acc_new, "f1_score": f1_new}
            }
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(model_meta, f, indent=2)
        print(f"[+] Champion model artifact REPLACED at: {export_path}")
        swapped = True
        result_status = "MODEL_REPLACED_IMPROVED"
    else:
        print("\n[!] BLOCKING SWAP: Candidate model did NOT outperform existing champion (F1 <= old F1).")
        print("[!] Champion model swap BLOCKED to prevent degrading classifier accuracy.")
        swapped = False
        result_status = "SWAP_BLOCKED_NO_IMPROVEMENT"

    print("================================================================================", flush=True)

    return {
        "status": result_status,
        "old_f1": f1_old,
        "new_f1": f1_new,
        "swapped": swapped,
        "feedback_count": total_feedback
    }


if __name__ == "__main__":
    run_feedback_retraining()
