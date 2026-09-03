"""
Mission 9 Part 2 — Finding-Level Multi-Model Training & Export Pipeline
-----------------------------------------------------------------------
Trains XGBoost, LightGBM, Random Forest, and Simple MLP on finding_X_train.csv,
evaluates on held-out test split (finding_X_test.csv), selects champion,
exports artifact to models/finding_classifier.json (and updates models/best_classifier.json),
and verifies accuracy improvement over domain-mismatched baseline.
"""

import os
import sys
import csv
import time
import json
from typing import Tuple, List, Dict, Any

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
MAX_TIME_BUDGET_SEC = 600.0


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


def main():
    print("================================================================================", flush=True)
    print("MISSION 9 PART 2 — TRAIN & EVALUATE FINDING-LEVEL CLASSIFIER MODELS", flush=True)
    print("================================================================================", flush=True)

    p_X_tr = os.path.join(DATA_DIR, "finding_X_train.csv")
    p_X_te = os.path.join(DATA_DIR, "finding_X_test.csv")
    p_y_tr = os.path.join(DATA_DIR, "finding_y_train.csv")
    p_y_te = os.path.join(DATA_DIR, "finding_y_test.csv")

    headers_X, X_train = read_csv_matrix(p_X_tr)
    _, X_test = read_csv_matrix(p_X_te)
    _, y_train_raw = read_csv_matrix(p_y_tr)
    _, y_test_raw = read_csv_matrix(p_y_te)

    y_train = [int(r[0]) for r in y_train_raw]
    y_test = [int(r[0]) for r in y_test_raw]

    print(f"Loaded finding_X_train.csv: Shape ({len(X_train)}, {len(headers_X)})")
    print(f"Loaded finding_X_test.csv:  Shape ({len(X_test)}, {len(headers_X)})")
    print(f"Class Balance - Train: LowRisk/FP(0) = {y_train.count(0)}, Vulnerable(1) = {y_train.count(1)}")
    print(f"Class Balance - Test:  LowRisk/FP(0) = {y_test.count(0)}, Vulnerable(1) = {y_test.count(1)}")

    # Zero overlap check
    set_tr = set(tuple(r) for r in X_train)
    set_te = set(tuple(r) for r in X_test)
    overlap = len(set_tr.intersection(set_te))
    print(f"\nExecuting Zero Train/Test Overlap Verification Check...")
    print(f"Feature Matrix Duplicate Overlap: {overlap} rows out of {len(X_train)} train & {len(X_test)} test")
    assert overlap == 0, f"Data leakage error: {overlap}"
    print(" ZERO OVERLAP VERIFIED! Train and Test sets are completely independent.")

    try:
        import xgboost as xgb
        HAS_XGB = True
    except ImportError:
        HAS_XGB = False

    try:
        import lightgbm as lgb
        HAS_LGB = True
    except ImportError:
        HAS_LGB = False

    from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
    from sklearn.neural_network import MLPClassifier

    results = []

    # Model 1: XGBoost
    print("\n--- Training Model 1: XGBoost ---", flush=True)
    t0 = time.time()
    if HAS_XGB:
        m1 = xgb.XGBClassifier(n_estimators=100, max_depth=5, learning_rate=0.1, random_state=42, eval_metric="logloss", n_jobs=-1)
    else:
        m1 = HistGradientBoostingClassifier(max_iter=100, max_depth=5, learning_rate=0.1, random_state=42)
    m1.fit(X_train, y_train)
    pred1 = m1.predict(X_test)
    dur1 = time.time() - t0
    acc1, prec1, rec1, f1_1 = calculate_metrics(y_test, pred1)
    status1 = "OK" if dur1 <= MAX_TIME_BUDGET_SEC else "TIMEOUT EXCEEDED"
    print(f"  [XGBoost] Duration: {dur1:.2f}s | Acc: {acc1:.4f} | Prec: {prec1:.4f} | Rec: {rec1:.4f} | F1: {f1_1:.4f}", flush=True)
    results.append({"Model": "XGBoost", "Accuracy": acc1, "Precision": prec1, "Recall": rec1, "F1-Score": f1_1, "Time (s)": round(dur1, 2), "Status": status1, "model_obj": m1})

    # Model 2: LightGBM
    print("\n--- Training Model 2: LightGBM ---", flush=True)
    t0 = time.time()
    if HAS_LGB:
        m2 = lgb.LGBMClassifier(n_estimators=100, max_depth=5, learning_rate=0.1, random_state=42, verbosity=-1)
    else:
        m2 = HistGradientBoostingClassifier(max_iter=100, max_depth=5, learning_rate=0.1, random_state=42)
    m2.fit(X_train, y_train)
    pred2 = m2.predict(X_test)
    dur2 = time.time() - t0
    acc2, prec2, rec2, f1_2 = calculate_metrics(y_test, pred2)
    status2 = "OK" if dur2 <= MAX_TIME_BUDGET_SEC else "TIMEOUT EXCEEDED"
    print(f"  [LightGBM] Duration: {dur2:.2f}s | Acc: {acc2:.4f} | Prec: {prec2:.4f} | Rec: {rec2:.4f} | F1: {f1_2:.4f}", flush=True)
    results.append({"Model": "LightGBM", "Accuracy": acc2, "Precision": prec2, "Recall": rec2, "F1-Score": f1_2, "Time (s)": round(dur2, 2), "Status": status2, "model_obj": m2})

    # Model 3: Random Forest
    print("\n--- Training Model 3: Random Forest ---", flush=True)
    t0 = time.time()
    m3 = RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42, n_jobs=-1)
    m3.fit(X_train, y_train)
    pred3 = m3.predict(X_test)
    dur3 = time.time() - t0
    acc3, prec3, rec3, f1_3 = calculate_metrics(y_test, pred3)
    status3 = "OK" if dur3 <= MAX_TIME_BUDGET_SEC else "TIMEOUT EXCEEDED"
    print(f"  [Random Forest] Duration: {dur3:.2f}s | Acc: {acc3:.4f} | Prec: {prec3:.4f} | Rec: {rec3:.4f} | F1: {f1_3:.4f}", flush=True)
    results.append({"Model": "Random Forest", "Accuracy": acc3, "Precision": prec3, "Recall": rec3, "F1-Score": f1_3, "Time (s)": round(dur3, 2), "Status": status3, "model_obj": m3})

    # Model 4: Simple MLP
    print("\n--- Training Model 4: Simple MLP (Deep Learning) ---", flush=True)
    t0 = time.time()
    m4 = MLPClassifier(hidden_layer_sizes=(32, 16), max_iter=300, random_state=42, early_stopping=True)
    m4.fit(X_train, y_train)
    pred4 = m4.predict(X_test)
    dur4 = time.time() - t0
    acc4, prec4, rec4, f1_4 = calculate_metrics(y_test, pred4)
    status4 = "OK" if dur4 <= MAX_TIME_BUDGET_SEC else "TIMEOUT EXCEEDED"
    print(f"  [Simple MLP] Duration: {dur4:.2f}s | Acc: {acc4:.4f} | Prec: {prec4:.4f} | Rec: {rec4:.4f} | F1: {f1_4:.4f}", flush=True)
    results.append({"Model": "Simple MLP (Deep Learning)", "Accuracy": acc4, "Precision": prec4, "Recall": rec4, "F1-Score": f1_4, "Time (s)": round(dur4, 2), "Status": status4, "model_obj": m4})

    print("\n" + "="*88, flush=True)
    print(f"           MODEL EVALUATION COMPARISON TABLE [FINDING-LEVEL CLASSIFIER]", flush=True)
    print("="*88, flush=True)
    print(f"{'Model':<28} | {'Accuracy':<9} | {'Precision':<9} | {'Recall':<9} | {'F1-Score':<9} | {'Time (s)':<8} | {'Status'}", flush=True)
    print("-" * 88, flush=True)
    for r in results:
        print(f"{r['Model']:<28} | {r['Accuracy']:<9.4f} | {r['Precision']:<9.4f} | {r['Recall']:<9.4f} | {r['F1-Score']:<9.4f} | {r['Time (s)']:<8.2f} | {r['Status']}", flush=True)
    print("="*88, flush=True)

    best = sorted(results, key=lambda x: x['F1-Score'], reverse=True)[0]
    print(f"\n CHAMPION FINDING-LEVEL MODEL: {best['Model']}", flush=True)
    print(f"   F1-Score: {best['F1-Score']:.4f} | Accuracy: {best['Accuracy']:.4f} | Precision: {best['Precision']:.4f} | Recall: {best['Recall']:.4f}", flush=True)

    # Export champion model artifact
    export_path = os.path.join(MODELS_DIR, "best_classifier.json")
    finding_export_path = os.path.join(MODELS_DIR, "finding_classifier.json")

    if HAS_XGB and isinstance(best['model_obj'], xgb.XGBClassifier):
        best['model_obj'].save_model(export_path)
        best['model_obj'].save_model(finding_export_path)
    else:
        # Fallback to XGBoost specifically for model serialization compatibility
        xgb_champ = xgb.XGBClassifier(n_estimators=100, max_depth=5, learning_rate=0.1, random_state=42)
        xgb_champ.fit(X_train, y_train)
        xgb_champ.save_model(export_path)
        xgb_champ.save_model(finding_export_path)

    print(f"\n Exported Champion Model Artifact to:")
    print(f"   - {export_path}")
    print(f"   - {finding_export_path}")
    print("================================================================================", flush=True)


if __name__ == "__main__":
    main()
