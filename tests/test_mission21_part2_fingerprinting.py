"""
Mission 21 Part 2 Test Suite — API Endpoint Fingerprinting
"""

import pytest
from backend.services.api_fingerprinter import fingerprint_endpoint


def test_fingerprint_json_api_content_type():
    """Verify application/json content type is classified as API Issue."""
    headers = {"Content-Type": "application/json; charset=utf-8"}
    is_api, label = fingerprint_endpoint("http://localhost:3000/rest/user/login", response_headers=headers)
    assert is_api is True
    assert label == "API Issue"


def test_fingerprint_json_body_structure():
    """Verify valid JSON response body is classified as API Issue."""
    body = '{"status": "success", "data": [1, 2, 3]}'
    is_api, label = fingerprint_endpoint("http://localhost:3000/api/v1/scans", response_body=body)
    assert is_api is True
    assert label == "API Issue"


def test_fingerprint_html_web_page():
    """Verify standard HTML page is classified as Web Page Issue."""
    headers = {"Content-Type": "text/html; charset=utf-8"}
    body = "<html><body><h1>Welcome</h1></body></html>"
    is_api, label = fingerprint_endpoint("http://localhost:3000/about", response_headers=headers, response_body=body)
    assert is_api is False
    assert label == "Web Page Issue"
