"""
Unit tests for Mission 12 Part 1 — Grounding Fix Guides in NIST/OWASP Reference Data.
"""

import os
import json
import pytest
from backend.services.nvd_cve_client import fetch_nvd_cve_details, CACHE_FILE
from backend.services.reference_mapper import map_finding_to_references, _OWASP_DATA, _CWE_DATA
from backend.services.remediation_advisor import generate_recommendation
from dashboard.server import render_dashboard_html


def test_owasp_and_cwe_datasets_loaded():
    assert "A01:2021" in _OWASP_DATA
    assert "A03:2021" in _OWASP_DATA
    assert _OWASP_DATA["A03:2021"]["title"] == "Injection"

    assert "CWE-89" in _CWE_DATA
    assert "SQL Injection" in _CWE_DATA["CWE-89"]["name"]
    assert "CWE-79" in _CWE_DATA


def test_reference_mapper_heuristics():
    # Test SQLi
    refs_sqli = map_finding_to_references({"check_name": "SQL Injection vulnerability"})
    assert "A03:2021" in refs_sqli["owasp_category"]
    assert refs_sqli["cwe_info"]["cwe_id"] == "CWE-89"

    # Test Exposed Git
    refs_git = map_finding_to_references({"check_name": "Exposed Git Repository .git"})
    assert "A01:2021" in refs_git["owasp_category"]
    assert refs_git["cwe_info"]["cwe_id"] == "CWE-200"

    # Test Security Header
    refs_hdr = map_finding_to_references({"check_name": "Missing Security Header: Content-Security-Policy"})
    assert "A05:2021" in refs_hdr["owasp_category"]
    assert refs_hdr["cwe_info"]["cwe_id"] == "CWE-16"


def test_nvd_cve_client_and_cache():
    cve_id = "CVE-2021-44228" # Log4Shell
    info = fetch_nvd_cve_details(cve_id)
    assert info["cve_id"] == cve_id
    assert "source" in info
    assert "description" in info

    # Verify disk cache exists
    assert os.path.exists(CACHE_FILE)
    with open(CACHE_FILE, "r", encoding="utf-8") as f:
        cache_data = json.load(f)
    assert cve_id in cache_data


def test_remediation_advisor_reference_enrichment():
    rec = generate_recommendation({"check_name": "SQL Injection in Search Form", "severity": "HIGH"})
    assert "owasp_category" in rec
    assert "A03:2021" in rec["owasp_category"]
    assert rec["cwe_info"]["cwe_id"] == "CWE-89"
    assert "full_fix_guide" in rec
    assert "owasp_category" in rec["full_fix_guide"]


def test_dashboard_rendering_reference_badges():
    html_out = render_dashboard_html()
    assert " OWASP:" in html_out
    assert " MITRE:" in html_out
