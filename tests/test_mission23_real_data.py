"""
Mission 23 Part 1 — Unit & Integration Test Suite
--------------------------------------------------
Verifies that:
1. SQLInjectionCheck & XSSCheck produce real dynamic findings and evidence strings from actual HTTP responses without hardcoded Juice Shop strings.
2. SubdomainEnumModule performs real DNS host resolution.
3. RemediationAdvisor dynamically parameterizes target URLs in human guide verification steps.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from scanner.models import HTTPResponse, Severity
from scanner.checks.sqli import SQLInjectionCheck
from scanner.checks.xss import XSSCheck
from backend.services.scan_service import SubdomainEnumModule
from backend.services.remediation_advisor import generate_recommendation


@pytest.mark.asyncio
async def test_sqli_check_dynamic_evidence_generation():
    client_mock = MagicMock()
    client_mock.scope_validator.is_in_scope.return_value = True

    # Mock response for a dynamic target: http://my-custom-domain.com/search?q=test
    mock_http_res = HTTPResponse(
        url="http://my-custom-domain.com/search?q=test",
        status_code=200,
        headers={"content-type": "text/html"},
        body="SQLITE_ERROR: syntax error near 'SELECT * FROM users'"
    )
    client_mock.get = AsyncMock(return_value=mock_http_res)

    check = SQLInjectionCheck(client_mock)
    responses = {
        "http://my-custom-domain.com/search?q=test": mock_http_res
    }

    findings = await check.run("http://my-custom-domain.com", responses)

    assert len(findings) >= 1
    f = findings[0]

    # Verify finding title and evidence dynamically reflect the queried parameter and host
    assert "q" in f.title or "q" in f.parameter
    assert f.endpoint == "http://my-custom-domain.com/search?q=test"
    assert "my-custom-domain.com" not in f.title  # Clean title
    assert "Juice Shop" not in f.description
    assert "Product Search" not in f.title
    assert "produced HTTP 200" in f.evidence


@pytest.mark.asyncio
async def test_xss_check_dynamic_evidence_generation():
    client_mock = MagicMock()
    client_mock.scope_validator.is_in_scope.return_value = True

    payload_xss = "<script>alert('NKAT_AI_XSS')</script>"
    mock_http_res = HTTPResponse(
        url="https://app.verified-target.org/comments?comment=hello",
        status_code=200,
        headers={"content-type": "text/html"},
        body=f"<div>Comment: {payload_xss}</div>"
    )
    client_mock.get = AsyncMock(return_value=mock_http_res)

    check = XSSCheck(client_mock)
    responses = {
        "https://app.verified-target.org/comments?comment=hello": mock_http_res
    }

    findings = await check.run("https://app.verified-target.org", responses)

    assert len(findings) >= 1
    f = findings[0]

    # Verify finding parameters and evidence reflect real target route
    assert f.parameter == "comment"
    assert "Product Search" not in f.title
    assert "/comments" in f.evidence or "comment" in f.evidence
    assert payload_xss in f.payload


def test_subdomain_enum_dns_resolution():
    enum_module = SubdomainEnumModule()
    
    with patch("socket.gethostbyname", return_value="93.184.216.34"):
        res = enum_module.enumerate_subdomains("http://example.com")
        assert len(res) == 1
        assert res[0]["hostname"] == "example.com"
        assert res[0]["ip_address"] == "93.184.216.34"


def test_remediation_advisor_dynamic_target_url():
    finding = {
        "id": 101,
        "check_name": "Missing Security Header: Content-Security-Policy",
        "evidence": "Header missing",
        "endpoint": "https://secure-corp.org/api/v1"
    }

    rec = generate_recommendation(finding)
    assert rec["remediation_type"] == "HEADER_CONFIG"
    guide = rec["full_fix_guide"]
    assert "https://secure-corp.org/api/v1" in guide["verification_steps"]
    assert "http://localhost:3000" not in guide["verification_steps"]
