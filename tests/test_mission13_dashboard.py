"""
Unit tests for Mission 13 — Enterprise-Grade Dashboard Redesign (Design Tokens, Sidebar Nav, Card-Based Findings Layout).
"""

import os
import pytest
from dashboard.server import render_dashboard_html, load_latest_scan_data, calculate_security_posture


def test_dashboard_design_tokens_and_sidebar():
    html_out = render_dashboard_html()
    assert "--bg-base:" in html_out
    assert "--accent-cyan:" in html_out
    assert "--sev-critical-bg:" in html_out
    assert "app-sidebar" in html_out
    assert "NKAT Threat" in html_out
    assert "Scan History" in html_out


def test_dashboard_card_based_findings_layout():
    html_out = render_dashboard_html()
    assert "finding-card" in html_out or "empty-state-card" in html_out
    assert "metric-card" in html_out
    assert "Target Connection" in html_out
    assert "Security Posture Score" in html_out
    assert "Scanned Endpoints" in html_out
    assert "Discovered Findings" in html_out
    assert "Vulnerability Severity Distribution" in html_out


def test_calculate_security_posture_engine():
    posture = calculate_security_posture([])
    assert posture["score"] == 100
    assert posture["grade"] == "A+"

    sample_findings = [
        {"severity": "CRITICAL"},
        {"severity": "HIGH"},
        {"severity": "MEDIUM"},
    ]
    posture2 = calculate_security_posture(sample_findings)
    assert posture2["score"] < 100
    assert posture2["counts"]["CRITICAL"] == 1


def test_load_latest_scan_data_structure():
    data = load_latest_scan_data()
    assert "target_url" in data
    assert "total_vulnerabilities" in data
    assert "findings" in data
    assert isinstance(data["findings"], list)
