"""
Outdated Software & Technology Fingerprinting Vulnerability Check.
Inspects HTTP headers and response artifacts for software versions and outdated technology exposure.
"""

import re
from typing import List, Dict
from scanner.checks.base import BaseCheck
from scanner.models import HTTPResponse, VulnerabilityFinding, Severity
from scanner.sanitizer import ResponseSanitizer


class SoftwareFingerprintCheck(BaseCheck):
    check_id = "FINGERPRINT_001"
    name = "Outdated Software & Tech Fingerprint Audit"
    description = "Detects technology stack fingerprint disclosures and outdated software versions."

    KNOWN_STACK_PATTERNS = [
        ("express", r"Express", Severity.LOW, "Express.js Web Framework Disclosed", "Server discloses Express.js framework usage in headers/body."),
        ("node", r"Node\.js|node_modules", Severity.LOW, "Node.js Environment Disclosed", "Target discloses Node.js backend runtime environment."),
        ("angular", r"ng-version|angular", Severity.INFO, "Angular Frontend Framework Disclosed", "Target frontend uses Angular framework."),
        ("sqlite", r"SQLite|sqlite3", Severity.LOW, "SQLite Database Engine Disclosed", "Target discloses SQLite database engine."),
        ("swagger", r"Swagger|OpenAPI", Severity.INFO, "Swagger / OpenAPI Specification Disclosed", "API documentation framework disclosed."),
    ]

    async def run(
        self, target_url: str, responses: Dict[str, HTTPResponse]
    ) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        reported_tech = set()

        for url, res in responses.items():
            # Combine headers and body snippet for fingerprint scanning
            headers_str = " ".join(f"{k}: {v}" for k, v in res.headers.items())
            sample_body = res.body[:2000]
            combined = f"{headers_str} {sample_body}"

            for tech_key, pattern, severity, title, desc in self.KNOWN_STACK_PATTERNS:
                if tech_key not in reported_tech and re.search(pattern, combined, re.IGNORECASE):
                    reported_tech.add(tech_key)
                    match = re.search(pattern, combined, re.IGNORECASE)
                    evidence_raw = match.group(0) if match else tech_key
                    clean_evidence = ResponseSanitizer.sanitize(evidence_raw, max_len=100)

                    findings.append(
                        VulnerabilityFinding(
                            id=f"{self.check_id}_{tech_key.upper()}",
                            title=title,
                            severity=severity,
                            description=f"{desc} (Target: {target_url})",
                            endpoint=target_url,
                            evidence=f"Discovered pattern '{clean_evidence}' in response headers/body.",
                            cwe="CWE-200",
                            remediation="Obscure framework/software version disclosures in HTTP headers and client-side bundles.",
                        )
                    )

        return findings
