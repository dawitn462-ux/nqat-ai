from typing import List, Dict
from urllib.parse import urlparse, parse_qs, urljoin
from scanner.checks.base import BaseCheck
from scanner.models import HTTPResponse, VulnerabilityFinding, Severity
from scanner.exceptions import RequestEngineError, ScopeViolationError


class XSSCheck(BaseCheck):
    check_id = "XSS_001"
    name = "Reflected Cross-Site Scripting (XSS) Scanner"
    description = "Tests input parameters for unescaped HTML/JavaScript reflection."

    TEST_PAYLOADS = [
        "<script>alert('NKAT_AI_XSS')</script>",
        "<iframe src=\"javascript:alert('NKAT_AI_XSS')\">",
        "\"><script>alert('XSS')</script>",
    ]

    PROBE_ROUTES = [
        ("/rest/products/search", "q"),
        ("/search", "q"),
        ("/api/search", "query"),
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
                        if res_test.status_code == 200 and payload in res_test.body:
                            audited_endpoints.add(endpoint_key)
                            findings.append(
                                VulnerabilityFinding(
                                    id=f"{self.check_id}_{param_name.upper()}",
                                    title=f"Reflected Cross-Site Scripting (XSS) in '{param_name}' Parameter",
                                    severity=Severity.HIGH,
                                    description=(
                                        f"The '{param_name}' parameter on endpoint '{parsed.path}' reflects user input without HTML entity encoding. "
                                        "This allows executing arbitrary JavaScript in the victim's browser."
                                    ),
                                    endpoint=url,
                                    parameter=param_name,
                                    payload=payload,
                                    evidence=f"Payload '{payload}' on parameter '{param_name}' at '{parsed.path}' reflected unescaped in HTTP response body.",
                                    cwe="CWE-79",
                                    remediation="Contextually encode all user-supplied input before rendering it in HTML/JSON responses.",
                                )
                            )
                            break
                    except (RequestEngineError, ScopeViolationError):
                        continue

        # 2. Probe candidate endpoints if no dynamic parameters triggered findings
        if not findings:
            for route, param_name in self.PROBE_ROUTES:
                probe_url = urljoin(base_url, route)
                if not self.client.scope_validator.is_in_scope(probe_url):
                    continue

                for payload in self.TEST_PAYLOADS:
                    try:
                        res_test = await self.client.get(probe_url, params={param_name: payload})
                        if res_test.status_code == 200 and payload in res_test.body:
                            findings.append(
                                VulnerabilityFinding(
                                    id=f"{self.check_id}_{param_name.upper()}_{route.upper().replace('/', '_')}",
                                    title=f"Reflected Cross-Site Scripting (XSS) in '{param_name}' on {route}",
                                    severity=Severity.HIGH,
                                    description=f"The '{param_name}' parameter on endpoint '{route}' reflects user input without HTML entity encoding.",
                                    endpoint=probe_url,
                                    parameter=param_name,
                                    payload=payload,
                                    evidence=f"Payload '{payload}' on parameter '{param_name}' at '{route}' reflected unescaped in HTTP response body.",
                                    cwe="CWE-79",
                                    remediation="Contextually encode all user-supplied input before rendering it in HTML/JSON responses.",
                                )
                            )
                            break
                    except (RequestEngineError, ScopeViolationError):
                        continue

        return findings

