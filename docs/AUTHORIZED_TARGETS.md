# Authorized Targets Policy

> [!IMPORTANT]
> **STRICT SECURITY SCOPE ENFORCEMENT (HTTPS PRIORITIZED)**
> Scans performed by this framework MUST adhere strictly to the explicit authorization policy outlined below. Scanning unauthorized targets or non-TLS external sites is strictly prohibited.

---

## Current Authorized Targets (Phase 1)

| Target Name | URL / Scope | Protocol | Environment | Authorization Status |
| :--- | :--- | :--- | :--- | :--- |
| OWASP Juice Shop (HTTP) | `http://localhost:3000` | HTTP | Local Docker / Test | **AUTHORIZED** |
| OWASP Juice Shop (HTTPS) | `https://localhost:3000` | HTTPS (TLS) | Local Docker / Test | **AUTHORIZED** |
| NKAT AI Dashboard (HTTPS) | `https://localhost:8443` | HTTPS (TLS) | Local Web App | **AUTHORIZED** |
| Loopback Interface (HTTPS) | `https://127.0.0.1:3000` | HTTPS (TLS) | Local Docker / Test | **AUTHORIZED** |

---

## Explicitly Prohibited Targets & Out-of-Scope Rules

- Any external IPv4 / IPv6 addresses or domain names not resolving strictly to local loopback (`127.0.0.1` / `localhost`).
- Port numbers other than `3000` or `8443` unless explicitly added and approved in this document.
- Unencrypted HTTP communication when `ENFORCE_HTTPS=true` is mandated by policy.
- Production systems, public APIs, cloud infrastructure, or third-party web services.

---

## Scanner Enforcement Protocol

1. The scanner module reads `ALLOWED_HOSTS`, `TARGET_URL`, and `ENFORCE_HTTPS` from `.env`.
2. Prior to dispatching any request, target URLs are validated against `docs/AUTHORIZED_TARGETS.md` rules.
3. If an outbound URL resolves outside the loopback scope or violates HTTPS enforcement, the request engine aborts with a `ScopeViolationError`.
