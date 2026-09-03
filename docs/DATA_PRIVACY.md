# NKAT Security Platform — Local-First Data Privacy Statement

## 1. Single-Machine Local Operation & Scope Isolation

- **Local Storage Policy**: All database records, user accounts, password hashes (`bcrypt`), organization definitions, scan configurations, target endpoints, vulnerability findings, and audit logs are stored **strictly 100% on the local host machine** (e.g. SQLite / local PostgreSQL database on `127.0.0.1`).
- **Zero External Network Transmission**: No user data, scan results, or credential hashes are ever transmitted, synced, or backed up to any cloud service, external telemetry server, or remote network endpoint.
- **Local Authentication**: User authentication and session management resolve entirely on the local machine using locally generated, signed HS256 JWT tokens. No external OAuth, OpenID, or identity providers are queried.

---

## 2. Authorized Exception: Public CVE Reference Lookups

- **NIST NVD REST API**: The only external HTTP query performed by the backend service is fetching public vulnerability reference metadata (CVSS base score, vector strings, and official descriptions) from the NIST National Vulnerability Database (`https://services.nvd.nist.gov/`).
- **Data Transmitted in NIST Queries**: Outbound queries contain **only generic CVE identifier strings** (e.g. `CVE-2021-44228`). No internal IP addresses, subdomains, user identities, or local findings evidence are included in NIST API requests.

---

## 3. Compliance Verification

- **Database Inspection**: Inspecting table contents confirms `organizations`, `users`, `scans`, `subdomains`, `findings`, and `audit_logs` exist exclusively on the local filesystem.
- **Network Traffic Audit**: Monitoring network activity confirms all API traffic resolves to loopback host `127.0.0.1` / `localhost`.
