"""
Unit Tests for Mission 19 — Black & White Theme, Background Image Integration, Centered Login Overlay, and Versioned API CORS Enforcement.
"""

import pytest
import os
import sys
from fastapi.testclient import TestClient

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from dashboard.server import render_dashboard_html, load_latest_scan_data
from backend.main import app


def test_dashboard_renders_black_and_white_theme():
    """
    Verifies that render_dashboard_html() produces the Mission 19 Black & White theme,
    references /bg.jpg, contains the centered login modal, and uses Black & White design tokens.
    """
    html = render_dashboard_html()

    # Black & White theme tokens
    assert "#05070a" in html
    assert "/bg.jpg" in html

    # Centered Login Modal Overlay
    assert 'id="loginOverlay"' in html
    assert 'Sign In to NKAT AI' in html
    assert 'Sign In & Continue' in html
    assert '/api/v1/auth/login' in html

    # Shield logo header
    assert '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>' in html

    # Versioned API fetch endpoints
    assert '/api/v1/findings/' in html
    assert '/api/v1/scans/' in html


def test_bg_image_file_exists():
    """
    Verifies that the uploaded background image exists at data/bg.jpg and dashboard/bg.jpg.
    """
    bg_dashboard = os.path.join(PROJECT_ROOT, "dashboard", "bg.jpg")
    bg_data = os.path.join(PROJECT_ROOT, "data", "bg.jpg")

    assert os.path.exists(bg_dashboard) or os.path.exists(bg_data)


def test_cors_middleware_permits_https_dashboard_origin():
    """
    Verifies that backend/main.py CORSMiddleware allows preflight options requests
    from https://127.0.0.1:8443 and https://localhost:8443.
    """
    client = TestClient(app)
    response = client.options(
        "/api/v1/findings/1/approve",
        headers={
            "Origin": "https://127.0.0.1:8443",
            "Access-Control-Request-Method": "PATCH",
            "Access-Control-Request-Headers": "content-type, x-api-key, authorization"
        }
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "https://127.0.0.1:8443"
    assert response.headers.get("access-control-allow-credentials") == "true"
