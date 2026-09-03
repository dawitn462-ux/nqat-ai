"""
Mission 21 Part 3 Test Suite — Gitleaks Secret Leak Scanner
------------------------------------------------------------
Tests for gitleaks binary execution, secret detection parser,
and timeout/size guardrails on exposed git repositories.
"""

import os
import sys
import json
import pytest
from unittest.mock import patch, MagicMock, mock_open

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.services.gitleaks_scanner import (
    scan_exposed_git_repo_with_gitleaks,
    GITLEAKS_PATH,
)


def test_gitleaks_binary_exists():
    """Verify gitleaks.exe binary exists in workspace."""
    assert os.path.exists(GITLEAKS_PATH), f"gitleaks.exe should exist at '{GITLEAKS_PATH}'"


def test_gitleaks_scanner_handles_unreachable_target():
    """Verify gitleaks scanner safely returns empty list on invalid/unreachable git repo."""
    secrets = scan_exposed_git_repo_with_gitleaks(
        "http://invalid-non-existent-git-repo-host.local",
        max_time_seconds=2
    )
    assert isinstance(secrets, list)
    assert len(secrets) == 0


def test_gitleaks_scanner_mocked_detection():
    """Verify gitleaks scanner parses report findings cleanly when secrets are detected."""
    mock_gitleaks_json = [
        {
            "RuleID": "aws-access-token",
            "Description": "AWS Access Token Leak",
            "Secret": "AKIAIOSFODNN7EXAMPLE",
            "File": "config/aws.json",
            "StartLine": 14
        }
    ]
    json_bytes = json.dumps(mock_gitleaks_json)

    with patch("subprocess.run") as mock_run, \
         patch("builtins.open", mock_open(read_data=json_bytes)), \
         patch("os.path.exists", return_value=True):
        
        mock_run.return_value = MagicMock(returncode=0)
        secrets = scan_exposed_git_repo_with_gitleaks("http://localhost:3000")
        assert len(secrets) >= 1
        assert secrets[0]["rule_id"] == "aws-access-token"
        assert secrets[0]["file"] == "config/aws.json"
