"""
Unit tests for POST /api/classify ML inference serving endpoint.
"""

import os
import sys
from fastapi.testclient import TestClient

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.main import app

client = TestClient(app)


def test_classify_sqli_vulnerability():
    payload = {
        "check_name": "SQL Injection in query parameter",
        "evidence": "GET /search?q=1' UNION SELECT 1,username,password FROM users--"
    }
    response = client.post("/api/classify", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["predicted_label"] in (0, 1)
    assert data["label_name"] in ("malicious_vulnerability", "benign_traffic")
    assert 0.0 <= data["confidence_score"] <= 1.0
    assert len(data["features"]) == 10


def test_classify_benign_traffic():
    payload = {
        "check_name": "Informational Banner",
        "evidence": "GET /static/images/logo.png"
    }
    response = client.post("/api/classify", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["predicted_label"] in (0, 1)
    assert 0.0 <= data["confidence_score"] <= 1.0
    assert len(data["features"]) == 10
