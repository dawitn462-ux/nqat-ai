"""
Unit and Integration Tests for Nuclei Scanner Output Parsing and Service Integration.
"""

import json
import os
import tempfile
import pytest
from backend.services.nuclei_scanner import parse_nuclei_findings, SEVERITY_MAP

# Sample real JSONL output fixture from nuclei
SAMPLE_NUCLEI_JSONL = [
    {
        "template-id": "git-config",
        "info": {
            "name": "Git Config Disclosure",
            "author": ["geeknik"],
            "tags": ["exposure", "git"],
            "reference": ["https://git-scm.com/docs/git-config"],
            "severity": "medium",
            "description": "Git configuration file was disclosed."
        },
        "type": "http",
        "host": "http://localhost:3000",
        "matched-at": "http://localhost:3000/.git/config",
        "timestamp": "2026-08-29T12:00:00.000000Z"
    },
    {
        "template-id": "tech-detect",
        "info": {
            "name": "Wappalyzer Technology Detection",
            "author": ["hakluke"],
            "tags": ["tech"],
            "severity": "info",
            "description": "Discovered technology stack: Node.js, Express"
        },
        "type": "http",
        "host": "http://localhost:3000",
        "matched-at": "http://localhost:3000/",
        "timestamp": "2026-08-29T12:00:01.000000Z"
    },
    {
        "template-id": "cve-2021-22911",
        "info": {
            "name": "Rocket.Chat NoSQL Injection",
            "author": ["princechawla"],
            "tags": ["cve", "nosql"],
            "severity": "critical",
            "description": "Pre-auth NoSQL injection in Rocket.Chat"
        },
        "type": "http",
        "host": "http://localhost:3000",
        "matched-at": "http://localhost:3000/api/v1/method.callAnon",
        "timestamp": "2026-08-29T12:00:02.000000Z"
    }
]


def test_parse_nuclei_findings_with_sample_fixture():
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".jsonl") as tmp:
        for entry in SAMPLE_NUCLEI_JSONL:
            tmp.write(json.dumps(entry) + "\n")
        tmp_path = tmp.name

    try:
        findings = parse_nuclei_findings(tmp_path)
        assert len(findings) == 3

        # Check 1: Git Config Disclosure
        assert findings[0]["check_name"] == "NUCLEI: Git Config Disclosure"
        assert findings[0]["severity"] == "MEDIUM"
        assert "http://localhost:3000/.git/config" in findings[0]["evidence"]

        # Check 2: Tech Detection
        assert findings[1]["check_name"] == "NUCLEI: Wappalyzer Technology Detection"
        assert findings[1]["severity"] == "INFO"
        assert "Node.js, Express" in findings[1]["evidence"]

        # Check 3: Critical CVE
        assert findings[2]["check_name"] == "NUCLEI: Rocket.Chat NoSQL Injection"
        assert findings[2]["severity"] == "CRITICAL"
        assert "http://localhost:3000/api/v1/method.callAnon" in findings[2]["evidence"]
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_parse_nuclei_findings_empty_file():
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".jsonl") as tmp:
        tmp_path = tmp.name

    try:
        findings = parse_nuclei_findings(tmp_path)
        assert findings == []
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_parse_nuclei_findings_missing_file():
    findings = parse_nuclei_findings("non_existent_file_path.jsonl")
    assert findings == []


def test_severity_mapping():
    assert SEVERITY_MAP.get("critical") == "CRITICAL"
    assert SEVERITY_MAP.get("high") == "HIGH"
    assert SEVERITY_MAP.get("medium") == "MEDIUM"
    assert SEVERITY_MAP.get("low") == "LOW"
    assert SEVERITY_MAP.get("info") == "INFO"
    assert SEVERITY_MAP.get("unknown") == "INFO"
