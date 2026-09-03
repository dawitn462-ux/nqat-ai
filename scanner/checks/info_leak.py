"""
Information Disclosure and Sensitive Endpoint Vulnerability Check.
Detects server banner leakage, exposed API documentation, and sensitive file paths.
"""

from typing import List, Dict
from urllib.parse import urljoin
from scanner.checks.base import BaseCheck
from scanner.models import HTTPResponse, VulnerabilityFinding, Severity
from scanner.exceptions import RequestEngineError, ScopeViolationError


class InfoLeakCheck(BaseCheck):
    check_id = "INFO_LEAK_001"
    name = "Information Disclosure & Endpoint Audit"
    description = "Scans for server banner exposure, sensitive endpoints, and public API docs."

    SENSITIVE_PATHS = [
        ("/api-docs", Severity.INFO, "Exposed API Documentation", "Publicly accessible OpenAPI / Swagger documentation."),
        ("/swagger-ui", Severity.INFO, "Exposed Swagger UI", "Public Swagger UI endpoint."),
        ("/ftp", Severity.LOW, "Exposed FTP Directory", "Publicly accessible FTP directory/file browser."),
        ("/.git/HEAD", Severity.HIGH, "Exposed Git Repository", "Exposed .git directory allows source code download."),
        ("/metrics", Severity.LOW, "Exposed Metrics Endpoint", "Exposed Prometheus/application metrics endpoint."),
    ]

    async def run(
        self, target_url: str, responses: Dict[str, HTTPResponse]
    ) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []

        # 1. Server banner leakage check from existing responses
        reported_leaks = set()
        for url, res in responses.items():
            headers_lower = {k.lower(): v for k, v in res.headers.items()}

            if "x-powered-by" in headers_lower and "x-powered-by" not in reported_leaks:
                reported_leaks.add("x-powered-by")
                findings.append(
                    VulnerabilityFinding(
                        id=f"{self.check_id}_X_POWERED_BY",
                        title="Information Exposure Through X-Powered-By Header",
                        severity=Severity.LOW,
                        description=f"Server exposes technology stack via X-Powered-By: {headers_lower['x-powered-by']}",
                        endpoint=target_url,
                        evidence=f"X-Powered-By: {headers_lower['x-powered-by']}",
                        cwe="CWE-200",
                        remediation="Remove or obscure the X-Powered-By HTTP response header.",
                    )
                )

            if "server" in headers_lower and any(char.isdigit() for char in headers_lower["server"]) and "server" not in reported_leaks:
                reported_leaks.add("server")
                findings.append(
                    VulnerabilityFinding(
                        id=f"{self.check_id}_SERVER_BANNER",
                        title="Server Banner Version Disclosure",
                        severity=Severity.LOW,
                        description=f"Server header discloses software version: {headers_lower['server']}",
                        endpoint=target_url,
                        evidence=f"Server: {headers_lower['server']}",
                        cwe="CWE-200",
                        remediation="Disable detailed server banner disclosure in web server configuration.",
                    )
                )

        # 2. Probe specific sensitive paths safely within scope
        base_url = target_url.rstrip("/")
        for path, severity, title, desc in self.SENSITIVE_PATHS:
            probe_url = urljoin(base_url, path)
            if not self.client.scope_validator.is_in_scope(probe_url):
                continue

            try:
                res = await self.client.get(probe_url)
                if res.status_code == 200 and len(res.body) > 10:
                    evidence_str = f"HTTP 200 OK (Response size: {len(res.body)} bytes)"
                    
                    # If exposed git repo check fires, run gitleaks secret detection
                    if path == "/.git/HEAD":
                        try:
                            from backend.services.gitleaks_scanner import scan_exposed_git_repo_with_gitleaks
                            secrets_found = scan_exposed_git_repo_with_gitleaks(target_url)
                            if secrets_found:
                                secret_summary = "; ".join(f"[{s['rule_id']}] {s['file']}:{s['start_line']}" for s in secrets_found[:5])
                                evidence_str += f" | Gitleaks Secrets Found: {len(secrets_found)} secret(s) detected ({secret_summary})"
                        except Exception as exc:
                            pass

                    findings.append(
                        VulnerabilityFinding(
                            id=f"{self.check_id}_{path.upper().replace('/', '_').replace('.', '')}",
                            title=title,
                            severity=severity,
                            description=f"{desc} Found at {probe_url}",
                            endpoint=probe_url,
                            evidence=evidence_str,
                            cwe="CWE-200",
                            remediation=f"Restrict unauthenticated access to '{path}' endpoint if not intended for public access.",
                        )
                    )
            except (RequestEngineError, ScopeViolationError):
                continue

        return findings
