# NKAT AI — Next-Gen AI-Powered Web Security Scanner & Triage Engine

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![XGBoost](https://img.shields.io/badge/ML-XGBoost%20%7C%20Random%20Forest-orange.svg)](https://xgboost.readthedocs.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**NKAT AI** is an advanced, multi-tier web vulnerability scanner, WAF traffic analyzer, static analysis (SAST) engine, and automated finding triage platform. It combines high-throughput dynamic crawling, active payload execution, static code auditing, and dedicated ML/heuristic classification pipelines.

---

## 🏗️ Architecture & Three-Tier AI Classification Engine

NKAT AI implements a **Three-Tier Classification Architecture** to eliminate domain mismatch and deliver realistic, domain-specific security intelligence across web traffic, source code, and scanner finding metadata.

```
                                  +---------------------------------------+
                                  |         NKAT AI SCAN ENGINE           |
                                  +---------------------------------------+
                                                      |
         +--------------------------------------------+--------------------------------------------+
         |                                            |                                            |
         v                                            v                                            v
+----------------------------------+     +----------------------------------+     +----------------------------------+
|              TIER 1              |     |              TIER 2              |     |              TIER 3              |
|      HTTP Traffic Classifier     |     |       Source Code SAST Model     |     |   Rule-Based Finding Triage      |
|         (CSIC 2010)              |     |      (OWASP BenchmarkJava)       |     |      (EPSS & Heuristics)         |
+----------------------------------+     +----------------------------------+     +----------------------------------+
| • Engine: XGBoost                |     | • Engine: Random Forest          |     | • Engine: Rule-Based Heuristic   |
| • Target: Raw GET/POST WAF Text  |     | • Target: Static Java Source     |     | • Target: Finding Metadata       |
| • F1-Score: 0.9283 (Accuracy: 87%)|    | • F1-Score: 0.6995 (Accuracy: 66%)|    | • Interface: XGBoost Wrapper     |
+----------------------------------+     +----------------------------------+     +----------------------------------+
```

### Classification Tier Breakdown

| Tier | Component Domain | Core Model / Engine | Training Corpus | Key Benchmark Metrics |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1** | **WAF HTTP Traffic** | XGBoost (`xgb.XGBClassifier`) | 15,300 CSIC 2010 Payloads | **F1: 0.9283** \| Acc: 87.10% \| Recall: 98.48% |
| **Tier 2** | **Static SAST Code** | Random Forest (`RandomForestClassifier`) | 2,740 OWASP Java Files | **F1: 0.6995** \| Acc: 66.46% \| Recall: 75.83% |
| **Tier 3** | **Finding Triage** | Rule-Based Heuristic Classifier | Live Scanner Metadata | Real-time EPSS & severity prioritization |

---

## 🔥 Key Capabilities

- **⚡ Dynamic Scanning (DAST)**: Integrated with **Katana** for headless crawling & endpoint discovery, and **Nuclei** for template-driven vulnerability scans.
- **🛡️ Strict Scope Policy**: Hardware-level scope validation via `docs/AUTHORIZED_TARGETS.md` preventing accidental or unauthorized scanning outside approved boundaries.
- **🔍 Embedded Secret Detection**: Built-in SAST secret detector powered by **Gitleaks** regex entropy scanning.
- **🤖 Continuous ML Feedback Loop**: Automated retraining pipeline (`scripts/retrain_from_feedback.py`) that incorporates human analyst approvals and rejections into candidate models.
- **📊 Real-time Dashboard & REST API**: High-performance FastAPI backend with SQLite/PostgreSQL persistence, JWT authentication, and interactive web dashboard.

---

## ⚡ Quick Start

### 1. Prerequisites & Installation

```bash
# Clone repository
git clone https://github.com/your-org/nqat-ai.git
cd nqat-ai

# Create virtual environment & install dependencies
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure Authorization Policy

Ensure your target host is authorized in `docs/AUTHORIZED_TARGETS.md`:

```markdown
# AUTHORIZED TARGETS
- http://localhost:3000
- http://127.0.0.1:8000
```

### 3. Run Dynamic Vulnerability Scan (CLI)

```bash
# Execute authorized scan
python main.py --policy docs/AUTHORIZED_TARGETS.md --output data --strict
```

### 4. Launch API Backend & Web Dashboard

```bash
# Start FastAPI Backend Server
python backend/main.py

# Start Interactive Web Dashboard (in a separate terminal)
python dashboard/server.py
```

Access the dashboard at `http://localhost:8000`.

---

## 🧪 Verification & Testing

Run unit & async integration tests to verify the scanner pipeline:

```bash
# Run scanner test suite
pytest tests/ -v
```

---

## 📚 Documentation Index

- [`NKAT_SYSTEM_ARCHITECTURE.md`](NKAT_SYSTEM_ARCHITECTURE.md) — Comprehensive technical architecture & design specs.
- [`docs/MODEL_EVALUATION.md`](docs/MODEL_EVALUATION.md) — Benchmark comparison tables, data leakage audits, and F1 evaluation details.
- [`docs/AUTHORIZED_TARGETS.md`](docs/AUTHORIZED_TARGETS.md) — Scanner target scope authorization configuration.
- [`docs/DATA_PRIVACY.md`](docs/DATA_PRIVACY.md) — Privacy policies & telemetry governance.

---

## 📄 License

Distributed under the [MIT License](LICENSE).

#   n i k a t - a i