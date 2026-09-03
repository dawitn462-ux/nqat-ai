"""
Unit tests for AsyncScannerClient HTTP/HTTPS engine and scope integration.
"""

import pytest
from scanner.client import AsyncScannerClient
from scanner.scope import ScopeValidator
from scanner.exceptions import ScopeViolationError, RequestEngineError


@pytest.mark.asyncio
async def test_client_scope_enforcement_on_request():
    validator = ScopeValidator(target_url="https://localhost:3000")

    async with AsyncScannerClient(scope_validator=validator) as client:
        with pytest.raises(ScopeViolationError):
            await client.get("https://evil.com")


@pytest.mark.asyncio
async def test_client_insecure_http_rejected():
    validator = ScopeValidator(target_url="https://localhost:3000", enforce_https=True)

    async with AsyncScannerClient(scope_validator=validator) as client:
        with pytest.raises(ScopeViolationError):
            await client.get("http://localhost:3000")


@pytest.mark.asyncio
async def test_client_successful_request():
    validator = ScopeValidator(target_url="http://localhost:3000", enforce_https=False)

    async with AsyncScannerClient(scope_validator=validator) as client:
        response = await client.get("http://localhost:3000")
        assert response.status_code == 200
        assert response.elapsed_ms > 0
