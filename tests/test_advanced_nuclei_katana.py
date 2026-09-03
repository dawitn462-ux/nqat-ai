"""
Test suite for Advanced Katana Crawler & Nuclei Scanner Engine Integration
"""

import os
import sys
import json
import pytest
from unittest.mock import patch, MagicMock

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.services.katana_crawler import run_katana_crawl, KATANA_PATH
from backend.services.nuclei_scanner import run_nuclei_scan, parse_nuclei_findings


def test_katana_crawler_advanced_parameters(tmp_path):
    """Verify Katana crawler handles advanced flags (form fill, known files, custom headers)."""
    target_url = "http://127.0.0.1:3000"
    
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout="http://127.0.0.1:3000/\nhttp://127.0.0.1:3000/api/users\nhttp://127.0.0.1:3000/admin\n",
            stderr="",
            returncode=0
        )
        
        urls = run_katana_crawl(
            target_url=target_url,
            depth=3,
            crawl_duration=15,
            headless=True,
            automatic_form_fill=True,
            known_files="all",
            custom_headers={"X-Scan-Token": "secret123"}
        )

        assert mock_run.called
        cmd_arg = mock_run.call_args[0][0]

        # Verify command flags
        assert "-aff" in cmd_arg
        assert "-kf" in cmd_arg
        assert "all" in cmd_arg
        assert "-system-chrome" in cmd_arg
        assert "-H" in cmd_arg
        assert "X-Scan-Token: secret123" in cmd_arg

        assert "http://127.0.0.1:3000" in urls
        assert "http://127.0.0.1:3000/api/users" in urls


def test_nuclei_scanner_list_targets(tmp_path):
    """Verify Nuclei scanner accepts a list of target URLs and constructs -list command."""
    targets = ["http://127.0.0.1:3000", "http://127.0.0.1:3000/api/v1"]
    out_file = str(tmp_path / "test_nuclei_out.jsonl")

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)

        res_path = run_nuclei_scan(
            targets=targets,
            output_path=out_file,
            tags=["cve", "cisa-kev", "epss"],
            rate_limit=200,
            concurrency=30
        )

        assert mock_run.called
        cmd_arg = mock_run.call_args[0][0]

        assert "-list" in cmd_arg
        assert "nuclei_targets_temp.txt" in cmd_arg[cmd_arg.index("-list") + 1]
        assert "-tags" in cmd_arg
        assert "cve,cisa-kev,epss" in cmd_arg[cmd_arg.index("-tags") + 1]
        assert "-rate-limit" in cmd_arg
        assert "200" in cmd_arg[cmd_arg.index("-rate-limit") + 1]


def test_nuclei_findings_parser_enrichment(tmp_path):
    """Verify Nuclei JSONL parser extracts classification details (CVE, CWE, CVSS score)."""
    mock_jsonl = str(tmp_path / "mock_nuclei_output.jsonl")
    
    finding_data = {
        "template-id": "CVE-2021-44228",
        "info": {
            "name": "Apache Log4j RCE",
            "severity": "critical",
            "classification": {
                "cve-id": ["CVE-2021-44228"],
                "cwe-id": ["CWE-502"],
                "cvss-score": 10.0
            }
        },
        "matched-at": "http://127.0.0.1:3000/api/login",
        "matcher-name": "log4j-jndi"
    }

    with open(mock_jsonl, "w", encoding="utf-8") as f:
        f.write(json.dumps(finding_data) + "\n")

    findings = parse_nuclei_findings(mock_jsonl)

    assert len(findings) == 1
    f = findings[0]
    assert f["check_name"] == "NUCLEI: Apache Log4j RCE"
    assert f["severity"] == "CRITICAL"
    assert f["cve_id"] == "CVE-2021-44228"
    assert f["cwe_id"] == "CWE-502"
    assert f["cvss_score"] == 10.0
    assert "CVE-2021-44228" in f["evidence"]
