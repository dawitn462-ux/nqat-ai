"""
Reference Mapper Service — Maps findings to OWASP Top 10 (2021), MITRE CWE Catalog, and NIST NVD CVE database entries.
Provides deterministic mapping dictionary for all check types and generates authoritative standard citations.
"""

import os
import re
import json
from typing import Dict, Any, Optional

from backend.services.nvd_cve_client import fetch_nvd_cve_details

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OWASP_FILE = os.path.join(PROJECT_ROOT, "data", "reference", "owasp_top10_2021.json")
CWE_FILE = os.path.join(PROJECT_ROOT, "data", "reference", "cwe_catalog.json")


def _load_json_file(filepath: str) -> Dict[str, Any]:
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


_OWASP_DATA = _load_json_file(OWASP_FILE)
_CWE_DATA = _load_json_file(CWE_FILE)


# Deterministic Check Type to Standards Mapping Dictionary (Part 2 & Part 4)
CHECK_TYPE_STANDARDS_MAP = {
    "sql_injection": {
        "check_pattern": "SQL Injection",
        "owasp_category": "A03:2021 - Injection",
        "cwe_id": "CWE-89",
        "cwe_name": "SQL Injection",
    },
    "cross_site_scripting": {
        "check_pattern": "Cross-Site Scripting (XSS)",
        "owasp_category": "A03:2021 - Injection",
        "cwe_id": "CWE-79",
        "cwe_name": "Cross-site Scripting",
    },
    "exposed_git_repository": {
        "check_pattern": "Exposed Git Repository",
        "owasp_category": "A01:2021 - Broken Access Control",
        "cwe_id": "CWE-200",
        "cwe_name": "Exposure of Sensitive Information",
    },
    "missing_security_header": {
        "check_pattern": "Missing Security Header",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "cwe_id": "CWE-16",
        "cwe_name": "Configuration",
    },
    "exposed_swagger_ui": {
        "check_pattern": "Exposed Swagger UI / API Docs",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "cwe_id": "CWE-200",
        "cwe_name": "Exposure of Sensitive Information",
    },
    "exposed_ftp_directory": {
        "check_pattern": "Exposed Anonymous FTP Directory",
        "owasp_category": "A02:2021 - Cryptographic Failures",
        "cwe_id": "CWE-319",
        "cwe_name": "Cleartext Transmission of Sensitive Information",
    },
    "exposed_metrics_endpoint": {
        "check_pattern": "Exposed Telemetry / Metrics Endpoint",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "cwe_id": "CWE-200",
        "cwe_name": "Exposure of Sensitive Information",
    },
    "outdated_software_fingerprint": {
        "check_pattern": "Outdated Software & Version Banners",
        "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
        "cwe_id": "CWE-937",
        "cwe_name": "Using Components with Known Vulnerabilities",
    },
    "ssrf_vulnerability": {
        "check_pattern": "Server-Side Request Forgery",
        "owasp_category": "A10:2021 - Server-Side Request Forgery (SSRF)",
        "cwe_id": "CWE-918",
        "cwe_name": "Server-Side Request Forgery (SSRF)",
    },
    "cve_vulnerability": {
        "check_pattern": "Nuclei CVE Vulnerability Match",
        "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
        "cwe_id": "CWE-937",
        "cwe_name": "Using Components with Known Vulnerabilities",
    },
    "generic_anomaly": {
        "check_pattern": "Generic Security Anomaly / Fallback",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "cwe_id": "CWE-16",
        "cwe_name": "Configuration",
    },
}


def get_standards_mapping(check_name: str) -> Dict[str, str]:
    """
    Returns exact owasp_category and cwe_id for a given check_name via deterministic dictionary lookup.
    """
    check_lower = (check_name or "").lower()
    if "sql injection" in check_lower or "sqli" in check_lower:
        return CHECK_TYPE_STANDARDS_MAP["sql_injection"]
    elif "xss" in check_lower or "cross-site script" in check_lower:
        return CHECK_TYPE_STANDARDS_MAP["cross_site_scripting"]
    elif "git" in check_lower or "version control" in check_lower:
        return CHECK_TYPE_STANDARDS_MAP["exposed_git_repository"]
    elif "header" in check_lower:
        return CHECK_TYPE_STANDARDS_MAP["missing_security_header"]
    elif "swagger" in check_lower or "api doc" in check_lower or "openapi" in check_lower:
        return CHECK_TYPE_STANDARDS_MAP["exposed_swagger_ui"]
    elif "ftp" in check_lower:
        return CHECK_TYPE_STANDARDS_MAP["exposed_ftp_directory"]
    elif "metrics" in check_lower or "prometheus" in check_lower:
        return CHECK_TYPE_STANDARDS_MAP["exposed_metrics_endpoint"]
    elif "outdated" in check_lower or "fingerprint" in check_lower:
        return CHECK_TYPE_STANDARDS_MAP["outdated_software_fingerprint"]
    elif "ssrf" in check_lower:
        return CHECK_TYPE_STANDARDS_MAP["ssrf_vulnerability"]
    elif "cve" in check_lower or "nuclei" in check_lower:
        return CHECK_TYPE_STANDARDS_MAP["cve_vulnerability"]
    else:
        return CHECK_TYPE_STANDARDS_MAP["generic_anomaly"]


def map_finding_to_references(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyzes check_name, evidence, and metadata to return grounded OWASP, CWE, and NIST CVE references.
    """
    check_name = str(finding.get("check_name") or finding.get("title") or "").strip()
    evidence = str(finding.get("evidence") or "")
    metadata = finding.get("metadata") or finding.get("template_info") or {}

    combined_text = f"{check_name} {evidence}".lower()

    # Deterministic mapping lookup
    std_map = get_standards_mapping(check_name)
    cwe_id = std_map["cwe_id"]
    owasp_category = std_map["owasp_category"]
    owasp_key = owasp_category.split(" ")[0]

    # Override cwe_id if explicit CWE pattern is found in evidence/check text
    cwe_match = re.search(r'CWE-(\d+)', combined_text, re.IGNORECASE)
    if cwe_match:
        found_cwe = f"CWE-{cwe_match.group(1)}"
        if found_cwe in _CWE_DATA:
            cwe_id = found_cwe

    cwe_info = _CWE_DATA.get(cwe_id, {})
    if not cwe_info:
        cwe_info = {
            "cwe_id": cwe_id,
            "name": std_map.get("cwe_name", f"Weakness {cwe_id}"),
            "description": f"MITRE Common Weakness Enumeration catalog entry {cwe_id}.",
            "owasp_category": owasp_category,
            "mitigation": "Follow MITRE CWE mitigation guidelines."
        }

    owasp_obj = _OWASP_DATA.get(owasp_key, {
        "id": owasp_key,
        "title": owasp_category.split(" - ")[-1] if " - " in owasp_category else "Security Issue",
        "description": "OWASP Top 10 (2021) standard category."
    })

    # Search for CVE identifier
    cve_id = None
    cve_match = re.search(r'CVE-\d{4}-\d{4,7}', combined_text, re.IGNORECASE)
    if cve_match:
        cve_id = cve_match.group(0).upper()
    elif isinstance(metadata, dict) and metadata.get("cve_id"):
        cve_id = str(metadata["cve_id"]).upper()

    nvd_cve_details = {}
    if cve_id:
        nvd_cve_details = fetch_nvd_cve_details(cve_id)

    # Paraphrased Authoritative Citation (Part 3)
    citation = f"Per OWASP {owasp_category} and MITRE {cwe_id} ({cwe_info.get('name', 'Weakness')}): {cwe_info.get('description', '')}"

    return {
        "owasp_category": owasp_category,
        "cwe_id": cwe_id,
        "owasp_details": owasp_obj,
        "cwe_info": cwe_info,
        "nvd_cve_details": nvd_cve_details,
        "authoritative_citation": citation,
    }
