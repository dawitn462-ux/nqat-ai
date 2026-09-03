"""
Unit tests for ScopeValidator security guardrails and HTTPS enforcement.
"""

import pytest
from scanner.scope import ScopeValidator
from scanner.exceptions import ScopeViolationError, ScanConfigError


def test_scope_validator_default_target_pass():
    validator = ScopeValidator(target_url="https://localhost:3000")
    assert validator.validate_url("https://localhost:3000") is True
    assert validator.validate_url("https://localhost:3000/rest/user/login") is True
    assert validator.validate_url("https://127.0.0.1:3000/api/Challenges") is True


def test_scope_validator_external_domain_blocked():
    validator = ScopeValidator(target_url="https://localhost:3000")

    with pytest.raises(ScopeViolationError) as exc_info:
        validator.validate_url("https://google.com")
    assert "not in authorized host list" in str(exc_info.value)

    with pytest.raises(ScopeViolationError):
        validator.validate_url("https://example.org:3000")


def test_scope_validator_unauthorized_port_blocked():
    validator = ScopeValidator(target_url="https://localhost:3000", strict_enforcement=True)

    with pytest.raises(ScopeViolationError) as exc_info:
        validator.validate_url("https://localhost:8080")
    assert "Port 8080 is not in authorized target port list" in str(exc_info.value)


def test_scope_validator_unauthorized_scheme_blocked():
    validator = ScopeValidator(target_url="https://localhost:3000")

    with pytest.raises(ScopeViolationError) as exc_info:
        validator.validate_url("ftp://localhost:3000")
    assert "Unauthorized scheme 'ftp'" in str(exc_info.value)


def test_scope_validator_insecure_http_blocked_when_https_enforced():
    validator = ScopeValidator(target_url="https://localhost:3000", enforce_https=True)

    with pytest.raises(ScopeViolationError) as exc_info:
        validator.validate_url("http://localhost:3000")
    assert "HTTPS enforcement is enabled" in str(exc_info.value)


def test_scope_validator_is_in_scope_boolean():
    validator = ScopeValidator(target_url="https://localhost:3000")
    assert validator.is_in_scope("https://localhost:3000/ftp") is True
    assert validator.is_in_scope("https://malicious-site.com") is False
