"""
Integration tests for SecurityScanner against policy-authorized targets.
"""

import os
import pytest
from scanner.core import SecurityScanner
from scanner.models import ScanReport


@pytest.mark.asyncio
async def test_full_security_scan():
    scanner = SecurityScanner(policy_path="docs/AUTHORIZED_TARGETS.md", output_dir="data", strict_enforcement=False, enforce_https=False)
    report = await scanner.execute_scan()

    assert isinstance(report, ScanReport)
    assert report.target_url.startswith("http")
    assert report.summary.total_endpoints_scanned > 0
    assert report.summary.total_vulnerabilities > 0
    assert len(report.structured_findings) > 0

    # Verify structured JSON format schema: {target, check_name, severity, evidence, timestamp}
    first_sf = report.structured_findings[0]
    assert hasattr(first_sf, "target")
    assert hasattr(first_sf, "check_name")
    assert hasattr(first_sf, "severity")
    assert hasattr(first_sf, "evidence")
    assert hasattr(first_sf, "timestamp")

    assert os.path.exists("data/structured_findings.json")
