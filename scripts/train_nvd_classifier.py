import os
import sys
import json
import joblib
import pandas as pd
import numpy as np
from scipy.sparse import hstack
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support

from extract_nvd_features import extract_cve_text_and_vector_features

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

def train_enhanced_nvd_classifier():
    data_path = os.path.join("data", "nvd_cve_dataset.json")
    if not os.path.exists(data_path):
        print(f"[!] Error: Dataset file {data_path} not found.")
        sys.exit(1)

    with open(data_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    print(f"[*] Loaded {len(records):,} verified NVD CVE records from {data_path}")

    feature_rows = []
    texts = []
    labels = []

    for r in records:
        f_dict = extract_cve_text_and_vector_features(r)
        sev = f_dict["ground_truth_severity"]
        if sev not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            continue

        desc = r.get("description", "").strip()
        if not desc:
            continue

        texts.append(desc)
        labels.append(sev)
        feature_rows.append(f_dict)

    df_feats = pd.DataFrame(feature_rows)
    
    # Select numerical/boolean structured feature columns (without exploitability_score)
    struct_cols = [
        "desc_len", "word_count", "is_injection", "is_overflow",
        "is_auth_bypass", "is_xss", "is_rce", "is_dos",
        "is_unauthenticated", "is_root_admin",
        "av_network", "av_adjacent", "av_local", "av_physical"
    ]
    X_struct = df_feats[struct_cols].values

    # 80/20 Train/Test Split
    indices = np.arange(len(labels))
    idx_train, idx_test, y_train, y_test = train_test_split(
        indices, labels, test_size=0.20, random_state=42, stratify=labels
    )

    X_text_train = [texts[i] for i in idx_train]
    X_text_test = [texts[i] for i in idx_test]
    X_struct_train = X_struct[idx_train]
    X_struct_test = X_struct[idx_test]

    print(f"[*] Training samples: {len(y_train):,} | Test samples: {len(y_test):,}")

    # TF-IDF Feature Extraction
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=1500,
        stop_words="english",
        sublinear_tf=True
    )
    X_text_train_vec = vectorizer.fit_transform(X_text_train)
    X_text_test_vec = vectorizer.transform(X_text_test)

    # Combine TF-IDF sparse matrix + Structured feature matrix
    X_train_combined = hstack([X_text_train_vec, X_struct_train])
    X_test_combined = hstack([X_text_test_vec, X_struct_test])

    # Fit LogisticRegression classifier
    clf = LogisticRegression(max_iter=1000, C=2.5, class_weight="balanced", random_state=42)
    clf.fit(X_train_combined, y_train)

    # Evaluate Model
    y_pred = clf.predict(X_test_combined)
    acc = accuracy_score(y_test, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="weighted")

    print("\n=======================================================================")
    print("  REAL NVD CVE COMBINED CLASSIFIER (TEXT + VECTOR FEATURES) EVALUATION ")
    print("=======================================================================")
    print(f"Accuracy:  {acc:.4f} ({acc*100:.2f}%)")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print("\n--- Detailed Classification Report ---")
    print(classification_report(y_test, y_pred, digits=4))

    # Save trained model pipeline artifacts
    os.makedirs("models", exist_ok=True)
    model_path = os.path.join("models", "nvd_cve_classifier.pkl")

    pipeline_data = {
        "vectorizer": vectorizer,
        "classifier": clf,
        "classes": clf.classes_.tolist(),
        "struct_cols": struct_cols,
        "metrics": {
            "accuracy": float(acc),
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1),
            "num_samples": len(labels)
        }
    }

    joblib.dump(pipeline_data, model_path)
    print(f"[+] Saved trained model artifact to {model_path}")

    # Also fit & save XGBoost model + LabelEncoder artifacts (nvd_large_classifier.json, label_encoder.pkl)
    from sklearn.preprocessing import LabelEncoder
    import xgboost as xgb

    le = LabelEncoder()
    y_train_encoded = le.fit_transform(y_train)
    y_test_encoded = le.transform(y_test)

    xgb_clf = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        random_state=42,
        eval_metric="mlogloss"
    )
    xgb_clf.fit(X_train_combined.tocsr(), y_train_encoded)

    json_model_path = os.path.join("models", "nvd_large_classifier.json")
    xgb_clf.save_model(json_model_path)
    print(f"[+] Saved XGBoost model artifact to {json_model_path}")

    le_path = os.path.join("models", "label_encoder.pkl")
    joblib.dump(le, le_path)
    print(f"[+] Saved LabelEncoder artifact to {le_path}")

if __name__ == "__main__":
    train_enhanced_nvd_classifier()
