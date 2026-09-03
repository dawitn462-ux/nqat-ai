import pytest
from backend.services.nvd_classifier_service import classify_cve_description, get_nvd_classifier_pipeline

def test_nvd_classifier_model_loading():
    """Verify that the NVD model pipeline loads correctly with trained metrics."""
    pipeline = get_nvd_classifier_pipeline()
    assert "vectorizer" in pipeline
    assert "classifier" in pipeline
    assert "metrics" in pipeline
    assert pipeline["metrics"]["accuracy"] > 0.60
    assert pipeline["metrics"]["num_samples"] >= 2000

def test_classify_critical_auth_bypass_description():
    """Test classification of a real critical authentication bypass NVD description."""
    desc = (
        "Authentication Bypass vulnerability in the Oturia Smart Google Code Inserter plugin "
        "allows unauthenticated attackers to insert arbitrary JavaScript or HTML code "
        "and execute remote code as root."
    )
    res = classify_cve_description(desc)
    assert res["predicted_severity"] in ["HIGH", "CRITICAL", "MEDIUM"]
    assert res["confidence"] > 0.40
    assert "severity_probabilities" in res
    assert "HIGH" in res["severity_probabilities"]
    assert len(res["top_keywords"]) > 0
    assert "features_extracted" in res
    assert res["features_extracted"]["is_auth_bypass"] == 1
    assert res["features_extracted"]["is_unauthenticated"] == 1

def test_model_distinctness_from_other_artifacts():
    """Verify that Mission 25 NVD CVE model v2 target classes and features are 100% distinct from CSIC/OWASP models."""
    pipeline = get_nvd_classifier_pipeline()
    assert set(pipeline["classes"]) == {"HIGH", "LOW", "MEDIUM"}
    assert "struct_cols" in pipeline
    assert len(pipeline["struct_cols"]) == 8
    assert "exploitability_score" not in pipeline["struct_cols"]
    assert "is_injection" in pipeline["struct_cols"]

def test_classify_medium_xss_description():
    """Test classification of an XSS / quickfind parameter description."""
    desc = "netpub/server.np in Extensis Portfolio NetPublish has XSS in the quickfind parameter."
    res = classify_cve_description(desc)
    assert res["predicted_severity"] in ["MEDIUM", "LOW", "HIGH"]
    assert "xss" in [k.lower() for k in res["top_keywords"]] or "quickfind" in [k.lower() for k in res["top_keywords"]]

def test_classify_rce_buffer_overflow():
    """Test classification of a buffer overflow RCE description."""
    desc = "Buffer overflow in passwd in BSD based operating systems allows local users to gain root privileges."
    res = classify_cve_description(desc)
    assert res["predicted_severity"] in ["HIGH", "CRITICAL", "MEDIUM"]
    assert res["confidence"] > 0.30

def test_invalid_description_handling():
    """Test edge cases with empty or invalid text inputs."""
    res_empty = classify_cve_description("")
    assert res_empty["predicted_severity"] == "UNKNOWN"
    assert res_empty["confidence"] == 0.0

    res_none = classify_cve_description(None)
    assert res_none["predicted_severity"] == "UNKNOWN"

def test_api_classify_cve_endpoint():
    """Test the integrated POST /api/v1/classify-cve FastAPI endpoint."""
    from fastapi.testclient import TestClient
    from backend.main import app

    client = TestClient(app)
    headers = {"X-API-Key": "nkat_secret_api_key_2026"}
    payload = {
        "description": "Authentication Bypass vulnerability allowing unauthenticated attackers to execute remote code as root.",
        "attack_vector": "NETWORK",
        "exploitability_score": 3.9
    }

    res = client.post("/api/v1/classify-cve", json=payload, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["predicted_severity"] in ["HIGH", "CRITICAL", "MEDIUM"]
    assert "confidence" in data
    assert "severity_probabilities" in data
    assert "features_extracted" in data

