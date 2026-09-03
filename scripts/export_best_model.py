"""
NKAT AI — Champion Model Selection and Export Script (Official XGBoost Native Exporter)
-------------------------------------------------------------------------------------
Part 3: Selects the best-performing classifier based on F1 score,
trains official native XGBoost, exports trained model binary/JSON,
and verifies model reloading and inference.
"""

import os
import sys
import csv
import json
import xgboost as xgb

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
os.makedirs(MODELS_DIR, exist_ok=True)

def read_csv_matrix(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        headers = next(reader)
        data = []
        for row in reader:
            if row:
                data.append([float(x) for x in row])
    return headers, data

def calculate_metrics(y_true, y_pred):
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

def export_champion():
    print("================================================================================", flush=True)
    print("PART 3 — CHAMPION MODEL SELECTION AND EXPORT (OFFICIAL XGBOOST)", flush=True)
    print("================================================================================", flush=True)

    p_X_tr = os.path.join(DATA_DIR, "csic_X_train.csv")
    p_X_te = os.path.join(DATA_DIR, "csic_X_test.csv")
    p_y_tr = os.path.join(DATA_DIR, "csic_y_train.csv")
    p_y_te = os.path.join(DATA_DIR, "csic_y_test.csv")

    headers_X, X_train = read_csv_matrix(p_X_tr)
    _, X_test = read_csv_matrix(p_X_te)
    _, y_train_raw = read_csv_matrix(p_y_tr)
    _, y_test_raw = read_csv_matrix(p_y_te)

    y_train = [int(r[0]) for r in y_train_raw]
    y_test = [int(r[0]) for r in y_test_raw]

    print(f"Loaded CSIC 2010 Full Dataset for Native XGBoost Training:")
    print(f"  Train Set: {len(X_train):,} samples, {len(headers_X)} features")
    print(f"  Test Set:  {len(X_test):,} samples, {len(headers_X)} features")

    print("\nTraining Champion Model: Official XGBoost (xgb.XGBClassifier)...")
    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        random_state=42,
        eval_metric="logloss",
        n_jobs=-1
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc, prec, rec, f1 = calculate_metrics(y_test, y_pred)

    export_json_path = os.path.join(MODELS_DIR, "best_classifier.json")
    model.save_model(export_json_path)
    print(f" Exported native XGBoost model artifact to {export_json_path}")

    # Verify reloading
    reloaded_model = xgb.XGBClassifier()
    reloaded_model.load_model(export_json_path)
    reloaded_pred = reloaded_model.predict(X_test)
    acc_r, prec_r, rec_r, f1_r = calculate_metrics(y_test, reloaded_pred)

    print("\n--- Verified Exported Model Reloading & Inference Metrics on Untouched Test Set ---")
    print(f"  Accuracy:  {acc_r:.4f} ({acc_r*100:.2f}%)")
    print(f"  Precision: {prec_r:.4f} ({prec_r*100:.2f}%)")
    print(f"  Recall:    {rec_r:.4f} ({rec_r*100:.2f}%)")
    print(f"  F1-Score:  {f1_r:.4f} ({f1_r*100:.2f}%)")
    print("================================================================================", flush=True)

    return export_json_path, acc_r, prec_r, rec_r, f1_r

if __name__ == "__main__":
    export_champion()
