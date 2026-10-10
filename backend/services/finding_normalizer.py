"""
Canonical Finding Normalizer & Deduplication Service — NQAT AI Security Platform
---------------------------------------------------------------------------------
Normalizes findings from all scanners (DAST Core, Nuclei, Katana, Gitleaks, SAST)
into a canonical platform schema, calculates stable SHA-256 deduplication fingerprints,
and records discrete scanner observation traces in the database.
"""

import hashlib
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from backend.models import Finding, FindingObservation, FindingStatus, Subdomain
from backend.services.remediation_advisor import generate_recommendation
from backend.services.deadline_calculator import calculate_review_deadline

logger = logging.getLogger("nkat.finding_normalizer")


def generate_finding_fingerprint(
    target_host: str,
    check_name: str,
    vulnerability_type: str = "WEB_VULNERABILITY",
    endpoint_or_location: str = "",
    param: str = ""
) -> str:
    """
    Computes a stable, deterministic SHA-256 fingerprint from:
    (target_host, vulnerability_type, check_name, endpoint, parameter).
    """
    raw_str = f"{target_host.lower().strip()}:{vulnerability_type.lower().strip()}:{check_name.lower().strip()}:{endpoint_or_location.lower().strip()}:{param.lower().strip()}"
    return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()


def persist_or_update_canonical_finding(
    db: Session,
    subdomain_id: int,
    scan_id: int,
    check_name: str,
    severity: str,
    evidence: str,
    detection_source: str = "DAST_CORE",
    vulnerability_type: str = "WEB_VULNERABILITY",
    target_url: str = "",
    endpoint: str = "",
    parameter: Optional[str] = None,
    cve_id: Optional[str] = None,
    cwe_id: Optional[str] = None,
    cvss_score: Optional[float] = None,
    cvss_version: Optional[str] = "3.1",
    request_evidence: Optional[str] = None,
    response_evidence: Optional[str] = None,
    code_evidence: Optional[str] = None,
    raw_output: Optional[Dict[str, Any]] = None,
    ml_confidence: Optional[float] = None,
    ml_predicted_label: Optional[int] = None,
    scanner_version: Optional[str] = None,
    confidence_level: str = "MEDIUM"
) -> Finding:
    """
    Canonical Finding Ingestion Pipeline:
    1. Computes deterministic fingerprint.
    2. Deduplicates against existing findings for this subdomain / target.
    3. If existing finding: increments observation_count, updates last_seen_at and evidence.
    4. If new finding: initializes with NEW / OPEN status, first_seen_at = now().
    5. Appends a discrete FindingObservation audit record linking this scan run to the finding.
    """
    subdomain = db.query(Subdomain).filter(Subdomain.id == subdomain_id).first()
    target_host = subdomain.hostname if subdomain else (target_url or "localhost")
    location_str = endpoint or target_url or target_host

    fingerprint = generate_finding_fingerprint(
        target_host=target_host,
        check_name=check_name,
        vulnerability_type=vulnerability_type,
        endpoint_or_location=location_str,
        param=parameter or ""
    )

    now_utc = datetime.now(timezone.utc)

    # Check for existing finding by fingerprint or unique constraint (subdomain_id, check_name, evidence)
    existing_finding = db.query(Finding).filter(
        Finding.subdomain_id == subdomain_id,
        (Finding.fingerprint == fingerprint) | (Finding.check_name == check_name)
    ).first()

    rec_info = generate_recommendation({"check_name": check_name, "severity": severity, "evidence": evidence})
    resolved_cwe = cwe_id or (rec_info.get("cwe_info", {}).get("cwe_id") if isinstance(rec_info.get("cwe_info"), dict) else rec_info.get("cwe_id"))

    if existing_finding:
        # Re-observation of existing finding
        existing_finding.last_seen_at = now_utc
        existing_finding.observation_count = (existing_finding.observation_count or 1) + 1
        existing_finding.fingerprint = fingerprint
        if cvss_score is not None:
            existing_finding.cvss_score = cvss_score
            existing_finding.cvss_version = cvss_version
        if cve_id:
            existing_finding.cve_id = cve_id
        if resolved_cwe:
            existing_finding.cwe_id = resolved_cwe
        if request_evidence:
            existing_finding.request_evidence = request_evidence
        if response_evidence:
            existing_finding.response_evidence = response_evidence
        if raw_output:
            existing_finding.raw_evidence = json.dumps(raw_output)

        # If previously resolved or closed and reopened by new scanner detection:
        if existing_finding.status in (FindingStatus.RESOLVED.value, FindingStatus.CLOSED.value):
            existing_finding.status = FindingStatus.REOPENED.value
            existing_finding.historical_context_note = f"Automatically reopened on {now_utc.isoformat()} due to re-detection in scan #{scan_id}."

        finding_rec = existing_finding
    else:
        # Create new finding record
        deadline = calculate_review_deadline(severity)
        finding_rec = Finding(
            subdomain_id=subdomain_id,
            check_name=check_name,
            severity=str(severity).upper(),
            evidence=evidence,
            recommendation=rec_info.get("recommendation"),
            config_snippet=rec_info.get("config_snippet"),
            status=FindingStatus.OPEN.value,
            fingerprint=fingerprint,
            detection_source=detection_source,
            confidence_level=confidence_level,
            cve_id=cve_id,
            cwe_id=resolved_cwe,
            cvss_score=cvss_score,
            cvss_version=cvss_version if cvss_score is not None else None,
            vulnerability_type=vulnerability_type,
            detection_method="DAST_ACTIVE_PROBE" if "DAST" in detection_source else detection_source,
            first_seen_at=now_utc,
            last_seen_at=now_utc,
            observation_count=1,
            review_deadline=deadline,
            owasp_category=rec_info.get("owasp_category"),
            request_evidence=request_evidence,
            response_evidence=response_evidence,
            code_evidence=code_evidence,
            raw_evidence=json.dumps(raw_output) if raw_output else None,
            ml_confidence=ml_confidence,
            ml_predicted_label=ml_predicted_label
        )
        db.add(finding_rec)

    db.flush()

    # Record discrete FindingObservation trace
    observation = FindingObservation(
        finding_id=finding_rec.id,
        scan_id=scan_id,
        scanner_name=detection_source,
        scanner_version=scanner_version,
        observed_at=now_utc,
        matched_target=location_str,
        raw_output=json.dumps(raw_output) if raw_output else evidence,
        request_evidence=request_evidence,
        response_evidence=response_evidence
    )
    db.add(observation)
    return finding_rec
