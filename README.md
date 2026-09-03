# Real-Time Agentic Website Vulnerability Assistant & Management

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/Frontend-React%20%7C%20Vite-61DAFB.svg)](https://vitejs.dev/)
[![ML](https://img.shields.io/badge/ML-XGBoost%20%7C%20Random%20Forest-orange.svg)](https://xgboost.readthedocs.io/)
[![Engine](https://img.shields.io/badge/DAST%2FSAST-Nuclei%20%7C%20Katana%20%7C%20Gitleaks-purple.svg)](https://github.com/projectdiscovery)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 💬 A Note from the Creator

> *"Security tools often feel like they're built to fight developers rather than help them. You run a scanner, get bombarded with hundreds of noisy alerts, half of which are false positives, and then spend hours figuring out what actually matters in real-time.*
>
> *We built **Real-Time Agentic Website Vulnerability Assistant & Management** because we believed there was a better way. We wanted an intelligent assistant that doesn't just throw raw vulnerability data at you, but acts like a real-time partner—crawling endpoints intelligently, sniffing out exposed secrets in your code, evaluating HTTP traffic with specialized machine learning models, and prioritizing critical threats using real EPSS metrics and human analyst feedback.*
>
> *No fluff, no misleading AI hype—just an honest, transparent 3-tier intelligence system designed to keep your web applications secure while keeping you in complete control. We hope this platform saves you hours of manual triage and helps you ship secure code with confidence!"*

---

## 🌟 Overview

**Real-Time Agentic Website Vulnerability Assistant & Management** is a state-of-the-art, open-source security intelligence platform designed for web applications. It bridges the gap between high-speed dynamic scanning (**DAST**), static code auditing (**SAST**), and real-time machine learning triage (**AI Triage**).

The platform continuously monitors, scans, and triages vulnerabilities, serving as an active security assistant for developers, DevOps teams, and security researchers.

```
       +-----------------------------------------------------------------+
       |  REAL-TIME AGENTIC WEBSITE VULNERABILITY ASSISTANT & MANAGEMENT |
       +-----------------------------------------------------------------+
                                       |
    +----------------------------------+----------------------------------+
    |                                  |                                  |
    v                                  v                                  v
+-----------------------+  +-----------------------+  +-----------------------+
|    DYNAMIC (DAST)     |  |     STATIC (SAST)     |  |    REAL-TIME AGENT    |
|   Katana & Nuclei     |  | Gitleaks & Code Audit |  | ML & Heuristic Triage |
+-----------------------+  +-----------------------+  +-----------------------+
```

---

## 🧠 3-Tier AI & Machine Learning Classification Engine

To avoid the pitfall of generic "one-size-fits-all" AI models, the platform uses a specialized **Three-Tier Architecture**, routing security data to domain-tailored models:

```
                                  +---------------------------------------+
                                  |         SCAN ENGINE & AGENT           |
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
| • Model: XGBoost                 |     | • Model: Random Forest           |     | • Type: Heuristic & Rule Engine  |
| • Target: Raw GET/POST WAF Text  |     | • Target: Static Code & Files    |     | • Target: Live Scanner Metadata  |
| • F1 Score: 0.9283 (Accuracy: 87%)|    | • F1 Score: 0.6995 (Accuracy: 66%)|    | • Feature: EPSS Prioritization   |
+----------------------------------+     +----------------------------------+     +----------------------------------+
```

### Classification Tier Summary

| Tier | Component Domain | ML Model / Engine | Training Corpus | Key Performance Metrics |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1** | **WAF HTTP Traffic** | XGBoost (`xgb.XGBClassifier`) | 15,300 CSIC 2010 Payloads | **F1: 0.9283** \| Accuracy: 87.10% \| Recall: 98.48% |
| **Tier 2** | **Static SAST Code** | Random Forest (`RandomForestClassifier`) | 2,740 OWASP Java Files | **F1: 0.6995** \| Accuracy: 66.46% \| Recall: 75.83% |
| **Tier 3** | **Finding Triage** | EPSS Heuristic & Rule-Based Engine | Live Metadata & Feedback | Real-time EPSS scoring & analyst feedback retraining |

---

## 🔥 Key Capabilities

- **⚡ Agentic & Real-Time Security Assistant**: Monitors target domains, streams findings via WebSockets, and provides automated risk scoring with human-in-the-loop confirmation.
- **🌐 High-Throughput Dynamic Scanning (DAST)**: Integrated with **Katana** for headless JavaScript rendering and deep endpoint discovery, and **Nuclei** for template-driven vulnerability scans.
- **🔑 Embedded Secret & Static Analysis (SAST)**: Powered by **Gitleaks** regex entropy auditing to detect leaked API keys, tokens, and hardcoded secrets in source trees.
- **🛡️ Hardware Scope Enforcement**: Built-in strict scope validator (`docs/AUTHORIZED_TARGETS.md`) preventing unauthorized or accidental out-of-scope scans.
- **🔄 Continuous ML Feedback Loop**: Automated model retraining script (`scripts/retrain_from_feedback.py`) that learns from human analyst approvals and dismissals over time.
- **📊 Modern Web Dashboard & REST API**: High-performance FastAPI backend paired with an interactive React dashboard for domain management, scan history, threat graphs, and real-time notifications.

---

## 🏗️ System Workflow

1. **Scope Verification**: Target URL is checked against `docs/AUTHORIZED_TARGETS.md`.
2. **Crawl & Discovery**: Katana discovers endpoints, parameters, and application paths.
3. **Vulnerability Audit**: Nuclei runs curated security templates while Gitleaks inspects source code for exposed credentials.
4. **Agentic AI Triage**: Tier 1 (XGBoost) evaluates HTTP traffic vectors, Tier 2 inspects static code, and Tier 3 prioritizes findings based on EPSS exploitability scores.
5. **Real-Time Notification & Management**: Findings stream directly to the web dashboard and REST API endpoints.
6. **Analyst Feedback Loop**: Human analyst reviews update candidate models for continuous self-improvement.

---

## ⚡ Quick Start

### 1. Prerequisites & Setup

Ensure you have Python 3.10+ and Node.js installed.

```bash
# Clone the repository
git clone https://github.com/your-org/nqat-ai.git
cd nqat-ai

# Create virtual environment and install backend dependencies
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure Authorized Target Scope

For safety, scans only run against authorized targets. Add your target to `docs/AUTHORIZED_TARGETS.md`:

```markdown
# AUTHORIZED TARGETS
- http://localhost:3000
- http://127.0.0.1:8000
```

### 3. Run a Scan (CLI)

```bash
# Launch dynamic scanning agent with strict scope checking
python main.py --policy docs/AUTHORIZED_TARGETS.md --output data --strict
```

### 4. Start Backend API & Web Dashboard

```bash
# Terminal 1: Launch FastAPI Backend Server
python backend/main.py

# Terminal 2: Launch Frontend Dashboard
cd frontend
npm install
npm run dev
```

Open your browser to `http://localhost:5173` (or `http://localhost:8000`) to view the interactive management platform.

---

## 🧪 Verification & Testing

Run unit and async integration test suites:

```bash
# Run test suite
pytest tests/ -v
```

---

## 📚 Technical Documentation Index

- [`NKAT_SYSTEM_ARCHITECTURE.md`](NKAT_SYSTEM_ARCHITECTURE.md) — Comprehensive technical architecture & system specifications.
- [`docs/MODEL_EVALUATION.md`](docs/MODEL_EVALUATION.md) — Model evaluation benchmark tables, data leakage audits, and metrics.
- [`docs/AUTHORIZED_TARGETS.md`](docs/AUTHORIZED_TARGETS.md) — Target authorization and policy configuration.
- [`docs/DATA_PRIVACY.md`](docs/DATA_PRIVACY.md) — Privacy principles & telemetry governance.

---

## 📄 License

Distributed under the [MIT License](LICENSE).