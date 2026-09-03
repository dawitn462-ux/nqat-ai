"""
Unit tests for TargetParser (extracting targets strictly from docs/AUTHORIZED_TARGETS.md).
"""

import pytest
from scanner.target_parser import TargetParser
from scanner.exceptions import ScopeViolationError, ScanConfigError


def test_target_parser_reads_authorized_targets():
    targets = TargetParser.get_authorized_targets("docs/AUTHORIZED_TARGETS.md")
    assert isinstance(targets, list)
    assert len(targets) > 0
    assert "https://localhost:3000" in targets or "http://localhost:3000" in targets


def test_target_parser_primary_target():
    primary = TargetParser.get_primary_target("docs/AUTHORIZED_TARGETS.md")
    assert primary.startswith("http")
    assert "localhost" in primary or "127.0.0.1" in primary


def test_target_parser_nonexistent_policy_raises_error():
    with pytest.raises(ScanConfigError):
        TargetParser.get_authorized_targets("docs/NON_EXISTENT_POLICY.md")
