# NKAT AI Security Platform — Project Progress & Execution Guide

## Executive Overview
**NKAT AI** is an enterprise-grade web application security platform combining **SAST**, **DAST**, **Secret Detection**, **Machine Learning Vulnerability Triage**, **Real-Time Threat Intelligence**, **Agentic AI Remediation**, and **Deterministic Patch Verification**.

---

## 🚀 System Verification & Quality Status
- **Test Suite Pass Rate**: **100% (174 / 174 tests passing)**
- **Architecture Integrity**: Non-negotiable policy enforcement (`AI CLAIM != SECURITY VERIFICATION`).
- **Policy Enforcement**: Deny-by-default execution policy gate, scope-bound checks (`DOCS/AUTHORIZED_TARGETS.md`), and strict shell execution block (`AI -> shell` prohibited).

---

## 🛡️ Comprehensive Web Attack & Vulnerability Inventory

NKAT AI scans for, discovers, and remediates security threats across multiple application layers:

### 1. Dynamic Web & API Vulnerabilities (DAST Engine)
* **SQL Injection (SQLi) — CWE-89**:
  * Active parameter probe injection (`' OR '1'='1`, `apple' OR 1=1--`, `1' UNION SELECT NULL, NULL, NULL--`).
  * Database error string detection across SQLite, PostgreSQL, MySQL, MSSQL, and ORMs (Sequelize, SQLAlchemy).
* **Reflected Cross-Site Scripting (XSS) — CWE-79**:
  * Script payload injection (`<script>alert('NKAT_AI_XSS')</script>`, `<iframe src="javascript:alert(...)">`, `"><script>...`).
  * Unescaped HTML/JS parameter reflection audits in web responses.
* **Clickjacking & Frame Hijacking — CWE-1021**:
  * Missing or weak `X-Frame-Options` (`DENY`, `SAMEORIGIN`) and Content Security Policy `frame-ancestors` directives.
* **Security Header Hardening & Transport Risks — CWE-523, CWE-693, CWE-200**:
  * Missing HSTS (`Strict-Transport-Security`).
  * Missing MIME-sniffing protection (`X-Content-Type-Options: nosniff`).
  * Weak or missing `Referrer-Policy`.
  * Missing Content Security Policy (`Content-Security-Policy`).
* **Exposed Backup Archives & Hidden Endpoints — SecLists Integration**:
  * Dictionary scanning (`raft-large-files.txt`, `common.txt`) for exposed sensitive files:
    `.env`, `.git/config`, `.bak`, `.zip`, `.tar.gz`, `.sql`, `.db`, `.log`, `.key`, `database.sql`, `config.bak`, `db.sqlite`.
* **Information Exposure & Server Banner Leaks — CWE-200**:
  * Server banner version disclosures (`Server: Apache/2.4.41`, `Server: nginx/1.18.0`).
  * `X-Powered-By` technology stack leaks (`Express`, `PHP/8.1`, `ASP.NET`).
  * Exposed public Swagger/OpenAPI docs (`/swagger-ui`, `/api-docs`) and unauthenticated metrics endpoints (`/metrics`, `/prometheus`).
* **Dynamic Route Discovery & Vulnerability Templates (Katana + Nuclei)**:
  * Katana web crawling for hidden JS endpoints.
  * Nuclei scanner template execution tagged with `cve`, `misconfiguration`, `exposure`, `cisa-kev`, and `epss`.

### 2. Static Code & Secret Vulnerabilities (SAST & Gitleaks Engine)
* **Raw SQL String Interpolation (SAST)**:
  * AST syntax parsing and regex pattern matching for unsafe string formatting in query strings (e.g., `f"SELECT ... WHERE username = '{username}'"`).
* **Secret & Credential Leak Detection (Gitleaks)**:
  * Automated extraction of leaked API keys, AWS credentials, JWT secrets, private RSA keys, database connection strings, and OAuth bearer tokens from exposed repositories (`.git`).
* **Protected System Resource Boundaries**:
  * Policy checks prohibiting modifications to protected system paths (`.env`, credentials, production database configs, deployment specs).

### 3. Real-Time Threat Intelligence & Malicious Infrastructure Matching
* **CISA Known Exploited Vulnerabilities (KEV)**: Automated cross-referencing against CISA's catalog of actively exploited CVEs.
* **FIRST EPSS (Exploit Prediction Scoring System)**: Real-time scoring of exploit probability percentiles.
* **Malicious Infrastructure (URLhaus & ThreatFox IOC Feeds)**: Cross-referencing discovered assets against active malware URLs, C2 botnet servers, and payload indicators.
* **AI/ML Vulnerability Triage (NVD Classifier)**: Scikit-Learn TF-IDF + LabelEncoder model assigning OWASP Top 10 categories, CWE mappings, and priority tiers (`P1`–`P4`).

---

## ⚡ Real-Time Telemetry & Real Platform Integrity

NKAT AI enforces strict integrity guarantees to eliminate fake claims and hallucinated AI fixes:

### 1. Mandatory Security Invariant: `AI CLAIM != SECURITY VERIFICATION`
NKAT AI **never** marks a vulnerability as fixed simply because an AI generated a code patch. To achieve `VERIFIED` status, every generated patch undergoes a 5-stage verification pipeline:

```text
[AI Proposed Patch]
       │
       ▼
 1. AST Syntax Check (ast.parse)
       │ (Pass)
       ▼
 2. Unit Test Suite Execution
       │ (Pass)
       ▼
 3. SAST Pattern Re-Audit (Vulnerable code present?)
       │ (Pass)
       ▼
 4. Active DAST Rescan against Test Application
       │ (Pass)
       ▼
 5. Regression Check
       │
  ┌────┴──────────────────────────┐
  ▼                               ▼
[PASSED]                       [FAILED]
Mark Finding RESOLVED          Rollback Isolated Branch
Status: VERIFIED               Status: ROLLED_BACK
```

If **any** stage fails, the engine automatically triggers `rollback_remediation` to revert the repository back to its base commit.

### 2. Real-Time Event & Telemetry Feeding
* **CI/CD Event Webhooks (`/api/v1/events/webhook`)**:
  * Ingests real-time Git push events and commit SHAs, spawning asynchronous background re-scans upon code changes.
* **Continuous Threat Intel Scheduler (`ContinuousMonitoringScheduler`)**:
  * Runs background sync loops against CISA KEV, FIRST EPSS, URLhaus, and ThreatFox, updating finding priority tiers in real time.
* **Audit Trail Feed (`AuditLog`)**:
  * Logs every capability invocation, scope check, patch attempt, and verification event with `actor="agent"` or `actor="remediation_engine"`.
* **Deny-by-Default Capability Gateway (`AgentCapabilityGateway`)**:
  * Enforces a 10-step authorization pipeline:
    `REGISTERED -> ENABLED -> AGENT_ALLOWED -> POLICY_ALLOWED -> TARGET_AUTHORIZED -> ARGUMENTS_VALIDATED -> RESOURCE_LIMITS -> EXECUTE -> NORMALIZE -> AUDIT`
  * Strictly denies arbitrary shell execution (`AI -> shell` prohibited) and enforces target domain scope validation (`DOCS/AUTHORIZED_TARGETS.md`).

---

## 📦 Core Platform Capabilities Summary

- **Agent Capability Gateway**: 12 registered capabilities with deny-by-default policy execution.
- **Remediation Engine**: Automatic diff patch generation, AST syntax validation, unit test verification, SAST re-audit, active DAST rescan, and automatic Git rollback (`security/remediation/<id>`).
- **Claude Agentic Orchestrator**: Anthropic Claude tool calling with local Heuristic Fallback Engine for offline resilience.
- **Enterprise Control Panel UI**: React 18 + Vite dashboard with real-time trajectory logging and capability indicators.

---

## 🛠️ Step-by-Step Instructions to Run NKAT AI

### Prerequisites
- **Python 3.10+** (Python 3.11/3.14 compatible)
- **Node.js 18+** & **npm**

---

### Step 1: Environment Setup & Dependencies

1. **Navigate to Repository Root**:
   ```bash
   cd c:\Users\hp\Desktop\nqat-ai
   ```

2. **Set Up Python Virtual Environment**:
   ```bash
   python -m venv venv
   # On Windows (PowerShell / CMD):
   .\venv\Scripts\activate
   ```

3. **Install Python Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Install Frontend Dependencies**:
   ```bash
   cd frontend
   npm install
   cd ..
   ```

5. **Configure Environment Variables (`.env`)**:
   Verify or copy `.env.example` to `.env`:
   ```ini
   DATABASE_URL=sqlite:///./nkat_dev.db
   USE_SQLITE=true
   ENFORCE_HTTPS=false
   SECRET_KEY=nkat_secret_api_key_2026
   ANTHROPIC_API_KEY=mock_anthropic_key
   ```

---

### Step 2: Start Backend Server

Run the FastAPI backend server on **port 8000**:

```bash
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

- **Interactive Swagger Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **OpenAPI Schema**: [http://127.0.0.1:8000/openapi.json](http://127.0.0.1:8000/openapi.json)

---

### Step 3: Start Frontend Control Panel UI

In a separate terminal, start the React + Vite development server on **port 3000**:

```bash
cd frontend
npm run dev
```

Open your browser to: **[http://localhost:3000](http://localhost:3000)**

---

### Step 4: Run CLI Security Scanner (Standalone Audit)

To run a standalone CLI security scan against authorized scope in `docs/AUTHORIZED_TARGETS.md`:

```bash
python main.py
```

---

### Step 5: Execute Autonomous Agentic Orchestrator

To trigger an autonomous SAST/DAST assessment, finding correlation, and patch verification loop:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/assessments/1/orchestrate \
  -H "X-API-Key: nkat_secret_api_key_2026"
```

Or access the **Orchestrator Control Panel** tab in the web interface.

---

### Step 6: Run Full Automated Test Suite

To verify all 174 unit and integration tests across the platform:

```bash
pytest tests/
```

---

## 📂 Repository Directory Map

```text
nqat-ai/
├── backend/                  # FastAPI Application, Routers, Services & Database Models
│   ├── main.py               # Backend Server Entrypoint & Lifespan Migrations
│   ├── models.py             # SQLAlchemy Database Models (Assessment, Scan, Finding, Remediation)
│   ├── routers/              # API Endpoints (scans, findings, agent, events, auth)
│   └── services/             # Core Services (agent_loop, remediation_engine, threat_feed_client)
├── scanner/                  # Security Scanner Modules
│   ├── core.py               # Primary Scanner Execution Engine
│   └── checks/               # DAST Checks (sqli, xss, security_headers, info_leak, backup_discovery)
├── frontend/                 # React 18 + Vite Control Panel Dashboard
│   ├── src/components/       # React UI Components (OrchestratorControlPanel, RemediationModal)
│   └── package.json          # Frontend Dependencies & Build Scripts
├── docs/                     # Documentation & Scope Policies
│   └── AUTHORIZED_TARGETS.md # Mandatory Authorized Target Scope Policy
├── tests/                    # 100% Verified Automated Test Suite (174 tests)
├── main.py                   # Standalone CLI Scanner Entrypoint
└── requirements.txt          # Python Dependencies
```
