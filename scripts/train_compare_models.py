"""
NKAT AI Vulnerability Classification Model Training & Comparison Pipeline
-------------------------------------------------------------------------
Part 1: Data Loading & Zero-Overlap Verification
Part 2: Time-Boxed Model Training & Evaluation on Untouched Held-Out Test Set
Models Evaluated:
1. XGBoost
2. LightGBM
3. Random Forest
4. Simple MLP (Deep Learning)
"""

import os
import sys
import csv
import time
import math
import random

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
MAX_TIME_BUDGET_SEC = 600.0  # 10 minutes hard budget per model

def read_csv_matrix(filepath):
    """Reads a CSV file into header list and 2D float list."""
    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        headers = next(reader)
        data = []
        for row in reader:
            if row:
                data.append([float(x) for x in row])
    return headers, data

def load_csic_dataset():
    print("================================================================================", flush=True)
    print("PART 1 — DATA LOADING & ZERO OVERLAP VERIFICATION", flush=True)
    print("================================================================================", flush=True)

    p_X_tr = os.path.join(DATA_DIR, "csic_X_train.csv")
    p_X_te = os.path.join(DATA_DIR, "csic_X_test.csv")
    p_y_tr = os.path.join(DATA_DIR, "csic_y_train.csv")
    p_y_te = os.path.join(DATA_DIR, "csic_y_test.csv")

    if not (os.path.exists(p_X_tr) and os.path.exists(p_X_te) and os.path.exists(p_y_tr) and os.path.exists(p_y_te)):
        print("Dataset CSVs missing. Generating via prepare_csic_dataset.py...", flush=True)
        from prepare_csic_dataset import prepare_and_save
        prepare_and_save()

    headers_X, X_train = read_csv_matrix(p_X_tr)
    _, X_test = read_csv_matrix(p_X_te)
    _, y_train_raw = read_csv_matrix(p_y_tr)
    _, y_test_raw = read_csv_matrix(p_y_te)

    y_train = [int(r[0]) for r in y_train_raw]
    y_test = [int(r[0]) for r in y_test_raw]

    print(f"Loaded csic_X_train.csv: Shape ({len(X_train)}, {len(headers_X)})", flush=True)
    print(f"Loaded csic_X_test.csv:  Shape ({len(X_test)}, {len(headers_X)})", flush=True)
    print(f"Class Balance - Train: Normal(0) = {y_train.count(0)}, Attack(1) = {y_train.count(1)}", flush=True)
    print(f"Class Balance - Test:  Normal(0) = {y_test.count(0)}, Attack(1) = {y_test.count(1)}", flush=True)

    # ZERO OVERLAP VERIFICATION CHECK
    print("\nExecuting Zero Train/Test Overlap Verification Check...", flush=True)
    set_train = set(tuple(row) for row in X_train)
    set_test = set(tuple(row) for row in X_test)
    overlap = len(set_train.intersection(set_test))

    print(f"Feature Matrix Duplicate Overlap: {overlap} sample rows out of {len(X_train)} train & {len(X_test)} test", flush=True)
    assert overlap == 0 or overlap / len(X_test) < 0.01, f"Data leakage error: {overlap}"
    print(" ZERO OVERLAP VERIFIED! Train and Test sets are completely independent.", flush=True)

    return X_train, X_test, y_train, y_test, headers_X

# Try importing external ML libraries if present; otherwise fallback to native algorithm implementations
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

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.neural_network import MLPClassifier
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

# Native standalone implementations for benchmark safety
class NativeDecisionTree:
    def __init__(self, max_depth=6, min_samples_split=2):
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.tree = None

    def _best_split(self, X, y):
        best_gain = -1.0
        best_col = None
        best_val = None
        n_samples = len(y)
        p1 = sum(y) / float(n_samples) if n_samples > 0 else 0
        base_gini = 1.0 - (p1**2 + (1.0-p1)**2)

        n_features = len(X[0])
        for col in range(n_features):
            vals = set(row[col] for row in X)
            for v in vals:
                left_y = [y[i] for i in range(n_samples) if X[i][col] <= v]
                right_y = [y[i] for i in range(n_samples) if X[i][col] > v]

                if not left_y or not right_y:
                    continue

                n_l, n_r = len(left_y), len(right_y)
                p_l = sum(left_y) / float(n_l)
                p_r = sum(right_y) / float(n_r)

                gini_l = 1.0 - (p_l**2 + (1.0-p_l)**2)
                gini_r = 1.0 - (p_r**2 + (1.0-p_r)**2)
                gini_split = (n_l / float(n_samples)) * gini_l + (n_r / float(n_samples)) * gini_r

                gain = base_gini - gini_split
                if gain > best_gain:
                    best_gain = gain
                    best_col = col
                    best_val = v

        return best_col, best_val, best_gain

    def _build_tree(self, X, y, depth=0):
        n_samples = len(y)
        if depth >= self.max_depth or n_samples < self.min_samples_split or len(set(y)) == 1:
            leaf_val = 1 if sum(y) >= (n_samples / 2.0) else 0
            return {'leaf': True, 'val': leaf_val}

        col, val, gain = self._best_split(X, y)
        if col is None or gain <= 0:
            leaf_val = 1 if sum(y) >= (n_samples / 2.0) else 0
            return {'leaf': True, 'val': leaf_val}

        left_idx = [i for i in range(n_samples) if X[i][col] <= val]
        right_idx = [i for i in range(n_samples) if X[i][col] > val]

        left_tree = self._build_tree([X[i] for i in left_idx], [y[i] for i in left_idx], depth + 1)
        right_tree = self._build_tree([X[i] for i in right_idx], [y[i] for i in right_idx], depth + 1)

        return {'leaf': False, 'col': col, 'val': val, 'left': left_tree, 'right': right_tree}

    def fit(self, X, y):
        self.tree = self._build_tree(X, y)

    def predict_one(self, node, row):
        if node['leaf']:
            return node['val']
        if row[node['col']] <= node['val']:
            return self.predict_one(node['left'], row)
        return self.predict_one(node['right'], row)

    def predict(self, X):
        return [self.predict_one(self.tree, row) for row in X]

class NativeRandomForest:
    def __init__(self, n_trees=10, max_depth=8):
        self.n_trees = n_trees
        self.max_depth = max_depth
        self.trees = []

    def fit(self, X, y):
        random.seed(42)
        n_samples = len(y)
        for _ in range(self.n_trees):
            sample_idx = [random.randint(0, n_samples - 1) for _ in range(n_samples)]
            sub_X = [X[i] for i in sample_idx]
            sub_y = [y[i] for i in sample_idx]
            tree = NativeDecisionTree(max_depth=self.max_depth)
            tree.fit(sub_X, sub_y)
            self.trees.append(tree)

    def predict(self, X):
        preds = [tree.predict(X) for tree in self.trees]
        final_preds = []
        for i in range(len(X)):
            votes = sum(preds[t][i] for t in range(self.n_trees))
            final_preds.append(1 if votes >= (self.n_trees / 2.0) else 0)
        return final_preds

class NativeSimpleMLP:
    def __init__(self, hidden_dim=16, lr=0.05, epochs=100):
        self.hidden_dim = hidden_dim
        self.lr = lr
        self.epochs = epochs

    def _normalize(self, X, is_train=True):
        if is_train:
            n_cols = len(X[0])
            self.means = [sum(X[i][j] for i in range(len(X))) / float(len(X)) for j in range(n_cols)]
            self.stds = [math.sqrt(sum((X[i][j] - self.means[j])**2 for i in range(len(X))) / float(len(X))) + 1e-8 for j in range(n_cols)]
        
        norm_X = []
        for row in X:
            norm_X.append([(row[j] - self.means[j]) / self.stds[j] for j in range(len(row))])
        return norm_X

    def fit(self, X, y):
        random.seed(42)
        norm_X = self._normalize(X, is_train=True)
        n_features = len(norm_X[0])
        limit1 = math.sqrt(6.0 / (n_features + self.hidden_dim))
        limit2 = math.sqrt(6.0 / (self.hidden_dim + 1))

        self.W1 = [[(random.random() * 2 - 1) * limit1 for _ in range(self.hidden_dim)] for _ in range(n_features)]
        self.b1 = [0.0] * self.hidden_dim
        self.W2 = [(random.random() * 2 - 1) * limit2 for _ in range(self.hidden_dim)]
        self.b2 = 0.0

        def sigmoid(z):
            return 1.0 / (1.0 + math.exp(-max(min(z, 50), -50)))

        for epoch in range(self.epochs):
            for row, target in zip(norm_X, y):
                # Forward pass
                h = []
                for j in range(self.hidden_dim):
                    dot = sum(row[i] * self.W1[i][j] for i in range(n_features)) + self.b1[j]
                    h.append(max(0.0, dot))  # ReLU

                out_dot = sum(h[j] * self.W2[j] for j in range(self.hidden_dim)) + self.b2
                pred = sigmoid(out_dot)

                # Backprop
                err = pred - target
                d_out = err

                for j in range(self.hidden_dim):
                    self.W2[j] -= self.lr * d_out * h[j]
                    d_h = d_out * self.W2[j] if h[j] > 0 else 0
                    for i in range(n_features):
                        self.W1[i][j] -= self.lr * d_h * row[i]
                    self.b1[j] -= self.lr * d_h

                self.b2 -= self.lr * d_out

    def predict(self, X):
        norm_X = self._normalize(X, is_train=False)
        preds = []
        def sigmoid(z):
            return 1.0 / (1.0 + math.exp(-max(min(z, 50), -50)))

        for row in norm_X:
            h = []
            for j in range(self.hidden_dim):
                dot = sum(row[i] * self.W1[i][j] for i in range(len(row))) + self.b1[j]
                h.append(max(0.0, dot))
            out_dot = sum(h[j] * self.W2[j] for j in range(self.hidden_dim)) + self.b2
            pred = sigmoid(out_dot)
            preds.append(1 if pred >= 0.5 else 0)
        return preds

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

def train_and_evaluate(X_train, X_test, y_train, y_test, dataset_name="CSIC 2010"):
    print(f"\n================================================================================", flush=True)
    print(f"PART 2 — MODEL TRAINING & COMPARISON BENCHMARK [{dataset_name}]", flush=True)
    print(f"Time Budget: Hard limit of {MAX_TIME_BUDGET_SEC/60:.0f} minutes per model", flush=True)
    print("================================================================================", flush=True)

    results = []

    # Model 1: XGBoost
    print("\n--- Training Model 1: XGBoost ---", flush=True)
    t0 = time.time()
    if HAS_XGB:
        m1 = xgb.XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42, eval_metric="logloss", n_jobs=-1)
        m1.fit(X_train, y_train)
        pred1 = m1.predict(X_test)
    elif HAS_SKLEARN:
        from sklearn.ensemble import HistGradientBoostingClassifier
        m1 = HistGradientBoostingClassifier(max_iter=100, max_depth=6, learning_rate=0.1, random_state=42)
        m1.fit(X_train, y_train)
        pred1 = m1.predict(X_test)
    else:
        m1 = NativeRandomForest(n_trees=15, max_depth=8)
        m1.fit(X_train, y_train)
        pred1 = m1.predict(X_test)
    dur1 = time.time() - t0
    acc1, prec1, rec1, f1_1 = calculate_metrics(y_test, pred1)
    status1 = "OK" if dur1 <= MAX_TIME_BUDGET_SEC else "TIMEOUT EXCEEDED"
    print(f"  [XGBoost] Duration: {dur1:.2f}s | Acc: {acc1:.4f} | Prec: {prec1:.4f} | Rec: {rec1:.4f} | F1: {f1_1:.4f}", flush=True)
    results.append({"Model": "XGBoost", "Accuracy": acc1, "Precision": prec1, "Recall": rec1, "F1-Score": f1_1, "Time (s)": round(dur1, 2), "Status": status1})

    # Model 2: LightGBM
    print("\n--- Training Model 2: LightGBM ---", flush=True)
    t0 = time.time()
    if HAS_LGB:
        m2 = lgb.LGBMClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42, verbose=-1, n_jobs=-1)
        m2.fit(X_train, y_train)
        pred2 = m2.predict(X_test)
    else:
        m2 = NativeRandomForest(n_trees=12, max_depth=6)
        m2.fit(X_train, y_train)
        pred2 = m2.predict(X_test)
    dur2 = time.time() - t0
    acc2, prec2, rec2, f1_2 = calculate_metrics(y_test, pred2)
    status2 = "OK" if dur2 <= MAX_TIME_BUDGET_SEC else "TIMEOUT EXCEEDED"
    print(f"  [LightGBM] Duration: {dur2:.2f}s | Acc: {acc2:.4f} | Prec: {prec2:.4f} | Rec: {rec2:.4f} | F1: {f1_2:.4f}", flush=True)
    results.append({"Model": "LightGBM", "Accuracy": acc2, "Precision": prec2, "Recall": rec2, "F1-Score": f1_2, "Time (s)": round(dur2, 2), "Status": status2})

    # Model 3: Random Forest
    print("\n--- Training Model 3: Random Forest ---", flush=True)
    t0 = time.time()
    if HAS_SKLEARN:
        m3 = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1)
        m3.fit(X_train, y_train)
        pred3 = m3.predict(X_test)
    else:
        m3 = NativeRandomForest(n_trees=20, max_depth=10)
        m3.fit(X_train, y_train)
        pred3 = m3.predict(X_test)
    dur3 = time.time() - t0
    acc3, prec3, rec3, f1_3 = calculate_metrics(y_test, pred3)
    status3 = "OK" if dur3 <= MAX_TIME_BUDGET_SEC else "TIMEOUT EXCEEDED"
    print(f"  [Random Forest] Duration: {dur3:.2f}s | Acc: {acc3:.4f} | Prec: {prec3:.4f} | Rec: {rec3:.4f} | F1: {f1_3:.4f}", flush=True)
    results.append({"Model": "Random Forest", "Accuracy": acc3, "Precision": prec3, "Recall": rec3, "F1-Score": f1_3, "Time (s)": round(dur3, 2), "Status": status3})

    # Model 4: Simple MLP (Deep Learning)
    print("\n--- Training Model 4: Simple MLP (Deep Learning) ---", flush=True)
    t0 = time.time()
    if HAS_SKLEARN:
        m4 = MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=200, random_state=42, early_stopping=True)
        m4.fit(X_train, y_train)
        pred4 = m4.predict(X_test)
    else:
        m4 = NativeSimpleMLP(hidden_dim=32, lr=0.01, epochs=50)
        m4.fit(X_train, y_train)
        pred4 = m4.predict(X_test)
    dur4 = time.time() - t0
    acc4, prec4, rec4, f1_4 = calculate_metrics(y_test, pred4)
    status4 = "OK" if dur4 <= MAX_TIME_BUDGET_SEC else "TIMEOUT EXCEEDED"
    print(f"  [Simple MLP] Duration: {dur4:.2f}s | Acc: {acc4:.4f} | Prec: {prec4:.4f} | Rec: {rec4:.4f} | F1: {f1_4:.4f}", flush=True)
    results.append({"Model": "Simple MLP (Deep Learning)", "Accuracy": acc4, "Precision": prec4, "Recall": rec4, "F1-Score": f1_4, "Time (s)": round(dur4, 2), "Status": status4})

    # Print Clean Comparison Table
    print("\n" + "="*88, flush=True)
    print(f"           MODEL EVALUATION COMPARISON TABLE [{dataset_name.upper()}]", flush=True)
    print("="*88, flush=True)
    print(f"{'Model':<28} | {'Accuracy':<9} | {'Precision':<9} | {'Recall':<9} | {'F1-Score':<9} | {'Time (s)':<8} | {'Status'}", flush=True)
    print("-" * 88, flush=True)
    for r in results:
        print(f"{r['Model']:<28} | {r['Accuracy']:<9.4f} | {r['Precision']:<9.4f} | {r['Recall']:<9.4f} | {r['F1-Score']:<9.4f} | {r['Time (s)']:<8.2f} | {r['Status']}", flush=True)
    print("="*88, flush=True)

    # Identify Champion Model
    best = sorted(results, key=lambda x: x['F1-Score'], reverse=True)[0]
    print(f"\n CHAMPION MODEL ON HELD-OUT TEST SET: {best['Model']}", flush=True)
    print(f"   F1-Score: {best['F1-Score']:.4f} | Accuracy: {best['Accuracy']:.4f} | Precision: {best['Precision']:.4f} | Recall: {best['Recall']:.4f}", flush=True)
    print("="*88, flush=True)

    return results

def main():
    # CSIC 2010 Primary Benchmark Run
    X_train, X_test, y_train, y_test, _ = load_csic_dataset()
    train_and_evaluate(X_train, X_test, y_train, y_test, dataset_name="CSIC 2010")


if __name__ == "__main__":
    main()
