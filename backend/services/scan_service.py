"""
Scan Service Core — Target Authorization Validation, Subdomain Discovery Execution,
Background Task Runner, Recommendation Generation, and ML Classification Scoring.
"""

import os
import sys
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from urllib.parse import urlparse
from sqlalchemy.orm import Session

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.database import SessionLocal
from backend.models import Scan, Subdomain, Finding, ScanStatus, FindingStatus
from backend.services.remediation_advisor import generate_recommendation
from backend.services.deadline_calculator import calculate_review_deadline
from scanner.target_parser import TargetParser
from scanner.core import SecurityScanner
from backend.services.nuclei_scanner import run_nuclei_scan, parse_nuclei_findings


import socket

class SubdomainEnumModule:
    def enumerate_subdomains(self, target_url: str) -> List[Dict[str, str]]:
        parsed = urlparse(target_url)
        host = parsed.netloc or parsed.path
        if ":" in host:
            host = host.split(":")[0]

        resolved_ip = "127.0.0.1"
        try:
            resolved_ip = socket.gethostbyname(host)
        except Exception:
            pass

        return [{"hostname": host, "ip_address": resolved_ip}]


def validate_target_authorization(target_url: str, db: Optional[Session] = None, org_id: Optional[int] = None) -> str:
    """
    Validates target against docs/AUTHORIZED_TARGETS.md policy AND user's verified DomainTargets in DB.
    Raises ValueError if target ownership has not been verified or is not listed in authorization policy.
    """
    target_clean = (target_url or "").strip().rstrip("/")

    # 1. Check against static policy file (built-in authorized targets)
    try:
        auth_targets = TargetParser.get_authorized_targets()
        for auth in auth_targets:
            if auth.rstrip("/") == target_clean or target_clean in auth:
                return target_clean or auth
    except Exception:
        pass

    # 2. Check against DB verified domain targets for organization
    if db is not None:
        from backend.models import DomainTarget, DomainVerificationStatus
        from backend.services.domain_verification_service import normalize_domain, is_domain_verified_and_active, log_domain_audit

        domain_name, _ = normalize_domain(target_clean)
        query = db.query(DomainTarget).filter(
            DomainTarget.domain == domain_name
        )
        if org_id is not None:
            query = query.filter(DomainTarget.organization_id == org_id)

        matched_domain = query.first()
        if matched_domain:
            if matched_domain.status == DomainVerificationStatus.VERIFIED.value:
                if not is_domain_verified_and_active(matched_domain):
                    matched_domain.status = DomainVerificationStatus.EXPIRED.value
                    matched_domain.last_error = "Domain verification expired (>30 days). Re-verification required."
                    log_domain_audit(
                        db=db,
                        user_id=None,
                        domain=matched_domain.domain,
                        method=matched_domain.verification_method,
                        result="EXPIRED",
                        details="Domain verification expired (older than 30 days). Re-verification required."
                    )
                    db.commit()
                    raise ValueError(
                        f"Target '{target_url}' verification has EXPIRED (>30 days). Mandatory re-verification is required prior to scanning."
                    )
                return target_clean

    raise ValueError(
        f"Target '{target_url}' is NOT authorized for scanning. Mandatory ownership verification (DNS TXT or File check) is required prior to scanning."
    )




def score_finding_with_ml(check_name: str, evidence: str = None, severity: str = "LOW") -> tuple:
    """
    Scores finding check_name/evidence text using champion finding-level model loaded once at startup.
    Returns (ml_predicted_label, ml_confidence).
    """
    try:
        from backend.routers.classification import CHAMPION_MODEL
        from scripts.prepare_finding_dataset import extract_finding_features_v2

        if CHAMPION_MODEL is not None:
            feats = extract_finding_features_v2(check_name, severity, evidence or "")
            probs = CHAMPION_MODEL.predict_proba([feats])[0]
            label = int(CHAMPION_MODEL.predict([feats])[0])
            conf = float(probs[label])
            return label, round(conf, 4)
    except Exception as exc:
        sys.stderr.write(f"[!] Warning ML scoring finding: {exc}\n")

    return None, None


def run_scan_pipeline_background(scan_id: int, target_url: str):
    """
    Background Task Runner:
    1. Updates Scan status to RUNNING.
    2. Runs subdomain enumeration.
    3. Runs SecurityScanner core custom checks.
    4. Persists findings with automated recommendations and ML classification confidence.
    5. Runs Nuclei vulnerability scanner and merges findings with automated recommendations & ML scoring.
    6. Updates Scan status to COMPLETED.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(_execute_scan_async(scan_id, target_url))
    loop.close()


async def _execute_scan_async(scan_id: int, target_url: str, db: Optional[Session] = None):
    should_close_db = False
    if db is None:
        db = SessionLocal()
        should_close_db = True
    try:
        db_scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not db_scan:
            return

        db_scan.status = ScanStatus.RUNNING.value
        db.commit()

        # Step 1: Subdomain enumeration
        subdomain_enum = SubdomainEnumModule()
        subdomain_data = subdomain_enum.enumerate_subdomains(target_url)

        created_subdomains = []

        for sub_info in subdomain_data:
            existing = db.query(Subdomain).filter(
                Subdomain.scan_id == scan_id, Subdomain.hostname == sub_info["hostname"]
            ).first()
            if not existing:
                sub_rec = Subdomain(
                    scan_id=scan_id,
                    hostname=sub_info["hostname"],
                    ip_address=sub_info.get("ip_address", "127.0.0.1")
                )
                db.add(sub_rec)
                created_subdomains.append(sub_rec)
            else:
                created_subdomains.append(existing)

        db.commit()
        for s in created_subdomains:
            db.refresh(s)

        primary_subdomain = created_subdomains[0] if created_subdomains else None

        # Step 1.5: Deep Crawl with Katana binary & API Fingerprinting
        from backend.services.katana_crawler import run_katana_crawl
        from backend.services.api_fingerprinter import fingerprint_endpoint

        katana_urls = run_katana_crawl(target_url, depth=2, crawl_duration=5)

        # Store discovered Katana endpoints in database under this scan with API fingerprinting
        for k_url in katana_urls:
            parsed_k = urlparse(k_url)
            k_host = parsed_k.netloc or parsed_k.path
            if ":" in k_host:
                k_host = k_host.split(":")[0]
            
            # Store route path as hostname or endpoint parameter
            route_host = f"{k_host}{parsed_k.path}" if parsed_k.path and parsed_k.path != "/" else k_host
            is_api, _ = fingerprint_endpoint(k_url)

            existing_k = db.query(Subdomain).filter(
                Subdomain.scan_id == scan_id, Subdomain.hostname == route_host
            ).first()
            if not existing_k:
                db_sub = Subdomain(
                    scan_id=scan_id,
                    hostname=route_host,
                    ip_address=primary_subdomain.ip_address if primary_subdomain else "127.0.0.1",
                    is_api_endpoint=is_api
                )
                db.add(db_sub)
        db.commit()

        # Step 1.8: Cross-reference all discovered subdomains & assets against URLhaus and ThreatFox feeds (Mission 28 Part 3)
        from backend.services.threat_feed_client import check_asset_against_malicious_feeds
        
        all_subdomains = db.query(Subdomain).filter(Subdomain.scan_id == scan_id).all()
        for sub in all_subdomains:
            for target_asset in set([sub.hostname, sub.ip_address]):
                if not target_asset or target_asset in ["127.0.0.1", "localhost"]:
                    continue
                intel_match = check_asset_against_malicious_feeds(target_asset)
                if intel_match.get("is_malicious"):
                    feed_name = intel_match.get("feed_name")
                    details = intel_match.get("details")
                    existing_finding = db.query(Finding).filter(
                        Finding.subdomain_id == sub.id,
                        Finding.check_name == "Associated with Known Malicious Infrastructure"
                    ).first()

                    if not existing_finding:
                        mal_finding = Finding(
                            subdomain_id=sub.id,
                            check_name="Associated with Known Malicious Infrastructure",
                            severity="CRITICAL",
                            evidence=f"Discovered asset '{target_asset}' was matched in real-time threat feed '{feed_name}'. {details}",
                            recommendation="IMMEDIATE ISOLATION REQUIRED: Discovered hostname/IP matches active C2/malware infrastructure in real-time threat intelligence feeds. Revoke DNS records and isolate host immediately.",
                            config_snippet=f"# Threat Intel Match: {feed_name}\n# Asset: {target_asset}\n# Details: {details}",
                            status=FindingStatus.OPEN.value,
                            review_deadline=calculate_review_deadline("CRITICAL"),
                            owasp_category="A06:2021-Vulnerable and Outdated Components / Infrastructure",
                            cwe_id="CWE-912",
                            is_api_endpoint=sub.is_api_endpoint
                        )
                        db.add(mal_finding)
        db.commit()

        # Step 2: Execute scanner core audit
        scanner = SecurityScanner(policy_path="docs/AUTHORIZED_TARGETS.md", target_url=target_url)
        report = await scanner.execute_scan()

        # Step 3: Persist custom-check findings in DB with automated recommendations & ML classification
        seen_checks = set()
        if primary_subdomain and report.findings:
            for f in report.findings:
                check_key = f.title.strip().lower()
                if check_key in seen_checks:
                    continue
                seen_checks.add(check_key)

                sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                is_api_flag, _ = fingerprint_endpoint(target_url)

                f_dict = {"check_name": f.title, "severity": sev_val, "evidence": f.evidence}
                rec_info = generate_recommendation(f_dict)
                ml_label, ml_conf = score_finding_with_ml(f.title, f.evidence, severity=sev_val)

                db_finding = Finding(
                    subdomain_id=primary_subdomain.id,
                    check_name=f.title,
                    severity=sev_val,
                    evidence=f.evidence,
                    recommendation=rec_info.get("recommendation"),
                    config_snippet=rec_info.get("config_snippet"),
                    status=FindingStatus.OPEN.value,
                    ml_predicted_label=ml_label,
                    ml_confidence=ml_conf,
                    review_deadline=calculate_review_deadline(sev_val),
                    owasp_category=rec_info.get("owasp_category"),
                    cwe_id=rec_info.get("cwe_info", {}).get("cwe_id") if isinstance(rec_info.get("cwe_info"), dict) else rec_info.get("cwe_id"),
                    is_api_endpoint=is_api_flag
                )
                existing = db.query(Finding).filter(
                    Finding.subdomain_id == primary_subdomain.id,
                    Finding.check_name == f.title
                ).first()
                if not existing:
                    db.add(db_finding)
            db.commit()

        # Step 3.5: Run Wordlist-Based Content Discovery (Mission 27 SecLists Gobuster Technique)
        from backend.services.content_discovery import run_content_discovery_async
        cd_findings = await run_content_discovery_async(target_url, max_words=300)

        if primary_subdomain and cd_findings:
            for cd in cd_findings:
                check_key = cd["check_name"].strip().lower()
                if check_key in seen_checks:
                    continue
                seen_checks.add(check_key)

                rec_info = generate_recommendation(cd)
                ml_label, ml_conf = score_finding_with_ml(cd["check_name"], cd["evidence"], severity=cd.get("severity", "MEDIUM"))
                is_api_cd, _ = fingerprint_endpoint(cd.get("endpoint", target_url))

                db_finding = Finding(
                    subdomain_id=primary_subdomain.id,
                    check_name=cd["check_name"],
                    severity=cd["severity"],
                    evidence=cd["evidence"],
                    recommendation=rec_info.get("recommendation"),
                    config_snippet=rec_info.get("config_snippet"),
                    status=FindingStatus.OPEN.value,
                    ml_predicted_label=ml_label,
                    ml_confidence=ml_conf,
                    review_deadline=calculate_review_deadline(cd.get("severity", "MEDIUM")),
                    owasp_category=rec_info.get("owasp_category"),
                    cwe_id=cd.get("cwe_id"),
                    is_api_endpoint=is_api_cd
                )
                existing = db.query(Finding).filter(
                    Finding.subdomain_id == primary_subdomain.id,
                    Finding.check_name == cd["check_name"]
                ).first()
                if not existing:
                    db.add(db_finding)
            db.commit()

        # Step 4: Run nuclei across all Katana-crawled endpoints with dynamic threat tags & merge findings
        scan_targets = list(dict.fromkeys(katana_urls + [target_url]))
        nuclei_output_path = run_nuclei_scan(
            targets=scan_targets,
            tags=["cve", "misconfiguration", "exposure", "cisa-kev", "epss"],
            rate_limit=150,
            concurrency=25,
        )
        nuclei_findings = parse_nuclei_findings(nuclei_output_path)

        if primary_subdomain and nuclei_findings:
            for nf in nuclei_findings:
                check_key = nf["check_name"].strip().lower()
                if check_key in seen_checks:
                    continue
                seen_checks.add(check_key)

                rec_info = generate_recommendation(nf)
                ml_label, ml_conf = score_finding_with_ml(nf["check_name"], nf["evidence"], severity=nf.get("severity", "LOW"))
                is_api_nf, _ = fingerprint_endpoint(nf.get("matched_at") or nf.get("evidence", target_url))

                cwe_val = nf.get("cwe_id") or rec_info.get("cwe_info", {}).get("cwe_id") if isinstance(rec_info.get("cwe_info"), dict) else rec_info.get("cwe_id")

                db_finding = Finding(
                    subdomain_id=primary_subdomain.id,
                    check_name=nf["check_name"],
                    severity=nf["severity"],
                    evidence=nf["evidence"],
                    recommendation=rec_info.get("recommendation"),
                    config_snippet=rec_info.get("config_snippet"),
                    status=FindingStatus.OPEN.value,
                    ml_predicted_label=ml_label,
                    ml_confidence=ml_conf,
                    review_deadline=calculate_review_deadline(nf.get("severity", "LOW")),
                    owasp_category=rec_info.get("owasp_category"),
                    cwe_id=cwe_val,
                    is_api_endpoint=is_api_nf
                )
                existing = db.query(Finding).filter(
                    Finding.subdomain_id == primary_subdomain.id,
                    Finding.check_name == nf["check_name"]
                ).first()
                if not existing:
                    db.add(db_finding)
            db.commit()

        # Step 5: Cross-reference threat intelligence (CISA KEV + EPSS) and compute Prioritization Index for all scan findings
        from backend.services.threat_feed_client import enrich_finding_with_threat_intel
        from backend.services.prioritization import enrich_finding_prioritization

        scan_findings = (
            db.query(Finding)
            .join(Subdomain, Finding.subdomain_id == Subdomain.id)
            .filter(Subdomain.scan_id == scan_id)
            .all()
        )
        for sf in scan_findings:
            enrich_finding_with_threat_intel(db, sf)
            enrich_finding_prioritization(db, sf)

        db_scan.status = ScanStatus.COMPLETED.value
        db.commit()
    except Exception as exc:
        db.rollback()
        db_scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if db_scan:
            db_scan.status = ScanStatus.FAILED.value
            db.commit()
        sys.stderr.write(f"[!] Error executing background scan task for scan_id={scan_id}: {exc}\n")
    finally:
        if should_close_db:
            db.close()