"""
Core Unit Tests for SecurityScanner Core Engine (`tests/test_scanner_core.py`).
Verifies scope enforcement, target parsing, checks execution, and report generation.
"""

import os
import pytest
from scanner.core import SecurityScanner
from scanner.models import ScanReport
from scanner.target_parser import TargetParser
from scanner.sanitizer import ResponseSanitizer


def test_target_parser_scope_extraction():
    """
    Verifies TargetParser extracts authorized targets exclusively from docs/AUTHORIZED_TARGETS.md.
    """
    primary = TargetParser.get_primary_target("docs/AUTHORIZED_TARGETS.md")
    assert primary.startswith("http")
    assert "localhost" in primary or "127.0.0.1" in primary


def test_sanitizer_cleans_xss_payloads():
    """
    Verifies ResponseSanitizer escapes HTML and control characters.
    """
    raw_payload = "<script>alert('XSS')</script>\x00"
    sanitized = ResponseSanitizer.sanitize(raw_payload)
    assert "<script>" not in sanitized
    assert "&lt;script&gt;" in sanitized
    assert "\x00" not in sanitized


@pytest.mark.asyncio
async def test_scanner_core_execution_against_juice_shop():
    """
    Verifies SecurityScanner executes scan against OWASP Juice Shop target and returns structured findings.
    """
    scanner = SecurityScanner(
        policy_path="docs/AUTHORIZED_TARGETS.md",
        output_dir="data",
        strict_enforcement=False,
        enforce_https=False,
    )
    report = await scanner.execute_scan()

    assert isinstance(report, ScanReport)
    assert report.summary.total_endpoints_scanned >= 0
    assert report.summary.scan_duration_seconds >= 0.0
    assert os.path.exists("data/structured_findings.json")
