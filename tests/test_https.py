"""
Unit tests for HTTPS enforcement, TLS certificate generation, and scope validation.
"""

import os
import pytest
from engine.cert_generator import generate_self_signed_cert
from scanner.scope import ScopeValidator
from scanner.client import AsyncScannerClient
from scanner.exceptions import ScopeViolationError


def test_tls_certificate_generation():
    cert_path, key_path = generate_self_signed_cert(cert_dir="certs_test")
    assert os.path.exists(cert_path)
    assert os.path.exists(key_path)
    assert os.path.getsize(cert_path) > 0
    assert os.path.getsize(key_path) > 0


def test_https_scope_validation_pass():
    validator = ScopeValidator(target_url="https://localhost:3000", enforce_https=True)
    assert validator.validate_url("https://localhost:3000") is True
    assert validator.validate_url("https://127.0.0.1:3000/api/Challenges") is True
    assert validator.validate_url("https://localhost:8443/dashboard") is True


def test_https_enforcement_blocks_http():
    validator = ScopeValidator(target_url="https://localhost:3000", enforce_https=True)

    with pytest.raises(ScopeViolationError) as exc_info:
        validator.validate_url("http://localhost:3000")
    assert "HTTPS enforcement is enabled" in str(exc_info.value)


@pytest.mark.asyncio
async def test_https_client_request_enforcement():
    validator = ScopeValidator(target_url="https://localhost:3000", enforce_https=True)

    async with AsyncScannerClient(scope_validator=validator) as client:
        with pytest.raises(ScopeViolationError):
            await client.get("http://localhost:3000")


def test_load_latest_scan_data_scoping():
    from dashboard.server import load_latest_scan_data
    scan_data = load_latest_scan_data()
    assert "target_url" in scan_data
    assert "findings" in scan_data
    assert "total_vulnerabilities" in scan_data

    # Ensure findings list length matches total_vulnerabilities count and titles are distinct
    findings = scan_data["findings"]
    assert scan_data["total_vulnerabilities"] == len(findings)
    titles = [f["title"].strip().lower() for f in findings]
    assert len(titles) == len(set(titles))

