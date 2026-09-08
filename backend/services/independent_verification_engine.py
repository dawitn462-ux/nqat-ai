"""
Independent Verification Engine — Decoupled Vulnerability Patch Verification Module.
Executes independent DAST/HTTP probes against live target applications post-remediation.
Compares BEFORE and AFTER evidence snapshots to determine if a vulnerability has been verified resolved.
"""

import json
import httpx
from datetime import datetime, timezone
from typing import Tuple, Dict, Any, Optional
from sqlalchemy.orm import Session

from backend.models import Finding, FindingStatus, AuditLog, Scan


class IndependentVerificationEngine:
    """
    Decoupled verification module that tests live target endpoints independently of patch generation.
    """

    def verify_finding(self, db: Session, finding_id: int) -> Tuple[bool, str, Dict[str, Any]]:
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            return False, f"Finding #{finding_id} not found.", {}

        subdomain = finding.subdomain
        target_url = subdomain.hostname if subdomain and subdomain.hostname else "http://127.0.0.1:8888"
        if not target_url.startswith(("http://", "https://")):
            target_url = f"http://{target_url}"

        # Parse request evidence if available to re-run exact HTTP probe
        req_data = {}
        if finding.request_evidence:
            try:
                req_data = json.loads(finding.request_evidence)
            except Exception:
                pass

        method = req_data.get("method", "GET").upper()
        probe_url = req_data.get("url") or finding.subdomain.hostname or target_url
        if not probe_url.startswith(("http://", "https://")):
            probe_url = f"http://{probe_url}"

        headers = {"User-Agent": "NKAT-Independent-Verification-Agent/1.0"}
        params = req_data.get("params") or {}
        payload = req_data.get("payload")

        # Create unique verification scan record
        v_scan = Scan(
            organization_id=finding.subdomain.scan.organization_id if finding.subdomain and finding.subdomain.scan else 1,
            target=probe_url,
            status="COMPLETED"
        )
        db.add(v_scan)
        db.commit()
        db.refresh(v_scan)

        # Store BEFORE evidence if not set
        if not finding.before_evidence:
            finding.before_evidence = finding.response_evidence or json.dumps({"evidence": finding.evidence})

        # Execute independent HTTP request against live target
        after_evidence_dict = {}
        vuln_still_present = False
        reason = ""

        try:
            with httpx.Client(timeout=8.0, verify=False, follow_redirects=True, headers=headers) as client:
                if method == "POST":
                    resp = client.post(probe_url, json={finding.parameter or "q": payload or "' OR '1'='1"})
                else:
                    resp = client.get(probe_url, params=params)

                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                after_evidence_dict = {
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "body_snippet": resp.text[:500],
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }

                # Evaluate detection rule based on check_name and vulnerability_type
                check_name_lower = finding.check_name.lower()
                vtype = finding.vulnerability_type or ""

                known_headers = ["content-security-policy", "x-frame-options", "x-content-type-options", "strict-transport-security", "referrer-policy", "x-powered-by"]
                if any(h in check_name_lower for h in known_headers) or "header" in check_name_lower or "missing" in check_name_lower or "missing" in vtype.lower():
                    # Identify missing header name
                    for h_name in ["content-security-policy", "x-frame-options", "x-content-type-options", "strict-transport-security", "referrer-policy"]:
                        if h_name in check_name_lower:
                            if h_name not in resp_headers:
                                vuln_still_present = True
                                reason = f"Header '{h_name}' is STILL MISSING from HTTP response headers."
                            else:
                                reason = f"Header '{h_name}' is now PRESENT ({resp_headers[h_name]})."
                            break
                    if "x-powered-by" in check_name_lower:
                        if "x-powered-by" in resp_headers:
                            vuln_still_present = True
                            reason = f"Header 'X-Powered-By' is STILL DISCLOSED ({resp_headers['x-powered-by']})."
                        else:
                            reason = "Header 'X-Powered-By' is now ABSENT."

                elif "sql injection" in check_name_lower or "sqli" in vtype.lower():
                    body_lower = resp.text.lower()
                    if any(err in body_lower for err in ["sqlite_error", "sqlite3", "sequelizedatabaseerror", "syntax error"]):
                        vuln_still_present = True
                        reason = "Live target STILL returns SQL database error messages."
                    else:
                        reason = "No database error signatures detected in live response."

                elif "xss" in check_name_lower or "reflected_xss" in vtype.lower():
                    if finding.payload and finding.payload in resp.text:
                        vuln_still_present = True
                        reason = f"Canary payload '{finding.payload}' is STILL reflected unescaped in response."
                    else:
                        reason = "Canary payload is no longer reflected unescaped."
                else:
                    # Generic check: if response status code is 200 and evidence matches
                    if finding.evidence and finding.evidence in resp.text:
                        vuln_still_present = True
                        reason = "Finding evidence string STILL PRESENT in live response."

        except Exception as exc:
            vuln_still_present = True
            reason = f"HTTP request to target failed during verification: {exc}"
            after_evidence_dict = {"error": str(exc)}

        finding.after_evidence = json.dumps(after_evidence_dict)
        finding.verification_scan_id = v_scan.id
        finding.reverified_at = datetime.now(timezone.utc)

        if not vuln_still_present:
            finding.status = FindingStatus.RESOLVED.value
            audit_action = "INDEPENDENT_VERIFICATION_PASSED"
            log_msg = f"Independent verification scan #{v_scan.id} PASSED. {reason}"
            success = True
        else:
            finding.status = FindingStatus.REOPENED.value
            audit_action = "INDEPENDENT_VERIFICATION_FAILED"
            log_msg = f"Independent verification scan #{v_scan.id} FAILED. {reason}"
            success = False

        audit_entry = AuditLog(
            finding_id=finding.id,
            scan_id=v_scan.id,
            action=audit_action,
            actor="independent_verification_engine",
            actor_name="Independent_Verification_Engine"
        )
        db.add(audit_entry)
        db.commit()
        db.refresh(finding)

        return success, log_msg, after_evidence_dict
