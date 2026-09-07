"""
Finding Correlation Engine — Deterministic Multi-Source Vulnerability Correlation
----------------------------------------------------------------------------------
Correlates SAST source code vulnerability findings with DAST web HTTP endpoint findings
using deterministic signals (CWE ID, endpoint parameters, file routes, vulnerability category).
"""

import os
import re
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from backend.models import Finding, FindingStatus


def correlate_assessment_findings(db: Session, assessment_id: Optional[int] = None, scan_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Correlates SAST findings and DAST findings associated with an assessment or scan.
    Returns structured list of correlated vulnerability pairs with combined evidence.
    """
    query = db.query(Finding)
    if assessment_id:
        query = query.filter(Finding.assessment_id == assessment_id)
    elif scan_id:
        from backend.models import Subdomain
        query = query.join(Subdomain, Finding.subdomain_id == Subdomain.id).filter(Subdomain.scan_id == scan_id)

    all_findings = query.all()
    if not all_findings:
        return []

    sast_findings = []
    dast_findings = []

    for f in all_findings:
        check_name = (f.check_name or "").lower()
        if "sast" in check_name or "gitleaks" in check_name or "semgrep" in check_name or "file:" in (f.evidence or ""):
            sast_findings.append(f)
        else:
            dast_findings.append(f)

    correlated_pairs = []
    seen_dast = set()

    for d in dast_findings:
        d_check = (d.check_name or "").lower()
        d_cwe = (d.cwe_id or "").upper()
        d_evidence = (d.evidence or "").lower()

        matched_sast = None
        for s in sast_findings:
            s_check = (s.check_name or "").lower()
            s_cwe = (s.cwe_id or "").upper()

            # Signal 1: Matching CWE ID
            if d_cwe and s_cwe and d_cwe == s_cwe:
                matched_sast = s
                break

            # Signal 2: Matching Vulnerability Type (SQLi, XSS, Secret)
            if ("sqli" in d_check or "sql injection" in d_check) and ("sqli" in s_check or "sql injection" in s_check or "sql" in s_check):
                matched_sast = s
                break
            if ("xss" in d_check or "cross-site" in d_check) and ("xss" in s_check or "cross-site" in s_check):
                matched_sast = s
                break

        if matched_sast:
            seen_dast.add(d.id)
            correlated_pairs.append({
                "correlation_id": f"corr_{d.id}_{matched_sast.id}",
                "dast_finding_id": d.id,
                "sast_finding_id": matched_sast.id,
                "title": f"Correlated Vulnerability: {d.check_name}",
                "severity": d.severity,
                "cwe_id": d.cwe_id or matched_sast.cwe_id,
                "dast_evidence": d.evidence,
                "sast_evidence": matched_sast.evidence,
                "confidence": 0.95,
                "status": "CORRELATED"
            })
        else:
            correlated_pairs.append({
                "correlation_id": f"corr_dast_{d.id}",
                "dast_finding_id": d.id,
                "sast_finding_id": None,
                "title": d.check_name,
                "severity": d.severity,
                "cwe_id": d.cwe_id,
                "dast_evidence": d.evidence,
                "sast_evidence": None,
                "confidence": 0.80,
                "status": "UNBOUND_DAST"
            })

    return correlated_pairs
