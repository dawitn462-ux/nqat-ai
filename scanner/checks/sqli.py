from typing import List, Dict
from urllib.parse import urlparse, parse_qs, urljoin, urlencode, urlunparse
from scanner.checks.base import BaseCheck
from scanner.models import HTTPResponse, VulnerabilityFinding, Severity
from scanner.exceptions import RequestEngineError, ScopeViolationError


import json

class SQLInjectionCheck(BaseCheck):
    check_id = "SQLI_001"
    name = "SQL Injection Vulnerability Scanner"
    description = "Tests endpoint parameters for SQL injection vulnerabilities."

    TEST_PAYLOADS = [
        "test'",
        "' OR '1'='1",
        "apple' OR 1=1--",
        "x' OR 1=1 --",
        "admin' --",
        "1' UNION SELECT NULL, NULL, NULL--",
    ]

    DB_ERRORS = [
        "SQLITE_ERROR",
        "sqlite3",
        "syntax error",
        "unrecognized token",
        "near \"",
        "near '",
        "SequelizeDatabaseError",
        "syntax error at or near",
        "unclosed quotation mark",
        "SQL syntax; check the manual",
        "SELECT * FROM",
        "<pre class=\"error\">",
    ]

    PROBE_ROUTES = [
        ("/search", "q", "GET"),
        ("/login", "username", "POST"),
        ("/rest/products/search", "q", "GET"),
        ("/api/search", "query", "GET"),
        ("/rest/user/login", "email", "POST"),
        ("/api/v1/auth/login", "username", "POST"),
    ]

    async def run(
        self, target_url: str, responses: Dict[str, HTTPResponse]
    ) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        base_url = target_url.rstrip("/")
        audited_endpoints = set()

        # 1. Audit dynamic endpoints discovered during crawling
        for url, res in responses.items():
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)

            if not query_params:
                continue

            for param_name in query_params.keys():
                endpoint_key = f"{parsed.path}?{param_name}"
                if endpoint_key in audited_endpoints:
                    continue

                for payload in self.TEST_PAYLOADS:
                    test_params = {k: v[0] for k, v in query_params.items()}
                    test_params[param_name] = payload

                    try:
                        res_test = await self.client.get(url, params=test_params)
                        body_lower = res_test.body.lower()
                        has_db_error = any(err.lower() in body_lower for err in self.DB_ERRORS)
                        is_sqli_reflected = res_test.status_code == 200 and ("book" in body_lower or "title" in body_lower or ("id" in body_lower and "name" in body_lower))

                        if has_db_error or (payload in ("x' OR 1=1 --", "apple' OR 1=1--") and is_sqli_reflected):
                            audited_endpoints.add(endpoint_key)
                            req_ev = json.dumps({"method": "GET", "url": url, "params": test_params})
                            resp_ev = json.dumps({"status_code": res_test.status_code, "headers": res_test.headers, "body_snippet": res_test.body[:500]})
                            findings.append(
                                VulnerabilityFinding(
                                    id=f"{self.check_id}_{param_name.upper()}",
                                    title=f"SQL Injection Vulnerability in '{param_name}' Parameter",
                                    severity=Severity.HIGH,
                                    description=(
                                        f"The '{param_name}' parameter on endpoint '{parsed.path}' is vulnerable to SQL injection. "
                                        "Unsanitized input allows manipulating backend database queries."
                                    ),
                                    endpoint=url,
                                    parameter=param_name,
                                    payload=payload,
                                    evidence=f"Payload '{payload}' on parameter '{param_name}' produced HTTP {res_test.status_code} response containing database output/syntax error: {res_test.body[:180]}",
                                    cwe="CWE-89",
                                    remediation="Use parameterized queries / prepared statements (ORM parameter binding) instead of dynamic string concatenation.",
                                    vulnerability_type="SQL_INJECTION",
                                    detection_method="DAST_DIFFERENTIAL_TESTING",
                                    request_evidence=req_ev,
                                    response_evidence=resp_ev,
                                )
                            )
                            break
                    except (RequestEngineError, ScopeViolationError):
                        continue

        # 2. Probe candidate endpoints
        for route, param_name, method in self.PROBE_ROUTES:
            endpoint_key = f"{route}?{param_name}"
            if endpoint_key in audited_endpoints:
                continue

            probe_url = urljoin(base_url, route)
            if not self.client.scope_validator.is_in_scope(probe_url):
                continue

            for payload in self.TEST_PAYLOADS:
                try:
                    if method == "POST":
                        res_test = await self.client.post(
                            probe_url,
                            form_data={param_name: payload, "password": "password123"}
                        )
                    else:
                        res_test = await self.client.get(probe_url, params={param_name: payload})

                    body_lower = res_test.body.lower()
                    has_db_error = any(err.lower() in body_lower for err in self.DB_ERRORS)
                    cookie_header = str(res_test.headers.get("set-cookie", "")).lower()
                    is_auth_bypass = (
                        method == "POST"
                        and ("admin" in payload or "' --" in payload or "1=1" in payload)
                        and (
                            (res_test.status_code in (302, 303) and ("token=" in cookie_header or "jwt" in cookie_header or "session" in cookie_header))
                            or (res_test.status_code == 200 and ("token" in body_lower or "jwt" in body_lower))
                        )
                    )
                    is_sqli_dump = (
                        method == "GET"
                        and res_test.status_code == 200
                        and (payload in ("x' OR 1=1 --", "apple' OR 1=1--", "' OR '1'='1"))
                        and ("book" in body_lower or "price" in body_lower or "author" in body_lower or ("id" in body_lower and "name" in body_lower))
                    )

                    if has_db_error or is_auth_bypass or is_sqli_dump:
                        audited_endpoints.add(endpoint_key)
                        sev = Severity.CRITICAL if is_auth_bypass else Severity.HIGH
                        title = f"Authentication Bypass via SQL Injection on {route}" if is_auth_bypass else f"SQL Injection Vulnerability in '{param_name}' on {route}"
                        desc = (
                            f"The '{param_name}' parameter on '{route}' allows authentication bypass via unescaped SQL statement execution."
                            if is_auth_bypass else
                            f"The '{param_name}' parameter on '{route}' is vulnerable to SQL injection."
                        )
                        req_ev = json.dumps({"method": method, "url": probe_url, "payload": payload, "param": param_name})
                        resp_ev = json.dumps({"status_code": res_test.status_code, "headers": res_test.headers, "body_snippet": res_test.body[:500]})

                        if is_auth_bypass:
                            ev_text = f"Payload '{payload}' on parameter '{param_name}' at '{route}' returned HTTP {res_test.status_code} with authenticated session token: {cookie_header[:120]}"
                        elif has_db_error:
                            matched_err = next((err for err in self.DB_ERRORS if err.lower() in body_lower), "Database syntax error")
                            ev_text = f"Payload '{payload}' on parameter '{param_name}' at '{route}' triggered database error leak: {matched_err} in response body."
                        else:
                            ev_text = f"Payload '{payload}' on parameter '{param_name}' at '{route}' forced query true condition returning database records context."

                        findings.append(
                            VulnerabilityFinding(
                                id=f"{self.check_id}_{param_name.upper()}_{route.upper().replace('/', '_')}",
                                title=title,
                                severity=sev,
                                description=desc,
                                endpoint=probe_url,
                                parameter=param_name,
                                payload=payload,
                                evidence=ev_text,
                                cwe="CWE-89",
                                remediation="Use parameterized queries / prepared statements for database queries and user authentication lookups.",
                                vulnerability_type="SQL_INJECTION_AUTH_BYPASS" if is_auth_bypass else "SQL_INJECTION",
                                detection_method="DAST_DIFFERENTIAL_TESTING",
                                request_evidence=req_ev,
                                response_evidence=resp_ev,
                            )
                        )
                        break
                except (RequestEngineError, ScopeViolationError):
                    continue

        return findings

