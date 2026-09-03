"""
Mission 21 Part 1 Verification Test Suite — Katana Deep Crawling & Endpoint Discovery
"""

import os
import sys
import pytest
from sqlalchemy.orm import Session

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.services.katana_crawler import run_katana_crawl, KATANA_PATH
from backend.services.scan_service import validate_target_authorization


def test_katana_binary_exists():
    """Verify that katana.exe binary exists in workspace."""
    assert os.path.exists(KATANA_PATH), f"katana.exe should exist at '{KATANA_PATH}'"


def test_katana_crawler_execution_on_authorized_target():
    """Verify Katana wrapper executes cleanly and returns in-scope discovered endpoints."""
    target_url = "http://127.0.0.1:3000"
    urls = run_katana_crawl(target_url, depth=2, crawl_duration=5)

    assert isinstance(urls, list)
    assert len(urls) > 0
    assert target_url.rstrip("/") in urls or "http://127.0.0.1:3000" in urls


def test_katana_out_of_scope_rejection():
    """Verify Katana scope validator rejects out-of-scope external targets."""
    from scanner.scope import ScopeValidator
    validator = ScopeValidator(target_url="http://localhost:3000")

    assert validator.is_in_scope("http://localhost:3000/api-docs")
    assert not validator.is_in_scope("https://external-malicious-domain.com/evil")
