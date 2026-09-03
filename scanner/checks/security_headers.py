"""
Security Headers Vulnerability Check.
Inspects target responses for missing security hardeners (CSP, HSTS, X-Frame-Options, etc.).
"""

from typing import List, Dict
from scanner.checks.base import BaseCheck
from scanner.models import HTTPResponse, VulnerabilityFinding, Severity


class SecurityHeadersCheck(BaseCheck):
    check_id = "SEC_HDR_001"
    name = "Security Headers Audit"
    description = "Checks HTTP response headers for missing or weak security configurations."

    RECOMMENDED_HEADERS = {
        "strict-transport-security": (
            Severity.LOW,
            "Missing Strict-Transport-Security (HSTS) header.",
            "CWE-523",
            "Enable HSTS in web server response headers (e.g. Strict-Transport-Security: max-age=31536000; includeSubDomains).",
        ),
        "content-security-policy": (
            Severity.MEDIUM,
            "Missing Content-Security-Policy (CSP) header.",
            "CWE-1021",
            "Define a restrictive Content-Security-Policy header to prevent XSS and data injection attacks.",
        ),
        "x-frame-options": (
            Severity.MEDIUM,
            "Missing X-Frame-Options header (Clickjacking Risk).",
            "CWE-1021",
            "Configure X-Frame-Options: DENY or SAMEORIGIN to protect against clickjacking attacks.",
        ),
        "x-content-type-options": (
            Severity.LOW,
            "Missing X-Content-Type-Options header.",
            "CWE-693",
            "Set X-Content-Type-Options: nosniff to prevent MIME-type sniffing.",
        ),
        "referrer-policy": (
            Severity.INFO,
            "Missing Referrer-Policy header.",
            "CWE-200",
            "Set Referrer-Policy: strict-origin-when-cross-origin to limit referrer leakage.",
        ),
    }

    async def run(
        self, target_url: str, responses: Dict[str, HTTPResponse]
    ) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        reported_headers = set()

        for url, res in responses.items():
            if res.status_code >= 400:
                continue

            resp_headers = {k.lower(): v for k, v in res.headers.items()}

            for header_name, (severity, desc, cwe, remediation) in self.RECOMMENDED_HEADERS.items():
                if header_name not in resp_headers and header_name not in reported_headers:
                    reported_headers.add(header_name)
                    findings.append(
                        VulnerabilityFinding(
                            id=f"{self.check_id}_{header_name.upper().replace('-', '_')}",
                            title=f"Missing Security Header: {header_name.title()}",
                            severity=severity,
                            description=f"{desc} (Target: {target_url})",
                            endpoint=target_url,
                            evidence=f"HTTP/{res.status_code} response headers missing '{header_name}'.",
                            cwe=cwe,
                            remediation=remediation,
                        )
                    )

        return findings
