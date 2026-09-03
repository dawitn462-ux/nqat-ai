"""
HTTPS Dashboard Web Application Server — NKAT Threat Sentinel Enterprise Console (Mission 19)
Serves the NKAT AI Cybersecurity Operations Console over TLS/SSL encryption (HTTPS:8443).

Design System & Features (Mission 19 Black & White / Monochromatic Glassmorphism):
- Monochromatic Pure Black / Dark Charcoal base (#05070a), high-contrast white typography (#ffffff), silver accents (#a1a1aa).
- Uploaded Cyber Security Network Image background overlay (/bg.jpg) with radial vignette and backdrop-filter blur glassmorphism.
- Custom Black & White Shield Logo in sidebar header.
- Black badges with high-contrast legibility borders for severity scale.
- Centered Black & White Sign In Overlay (Mission 16 Local JWT Auth) with smooth transition into console.
- Surfaced PDF Executive Export button (Mission 18) and AI Agent Triage Panel (Mission 15) prominently.
- Card-Based Finding Stream with AI threat confidence pills, CISA KEV / EPSS badges, deadline countdowns, multi-server fix guides, and human approval action buttons.
- Fully integrated versioned API endpoints (/api/v1/...) with CORS credentials support.
"""

import http.server
import ssl
import os
import sys
import json
import html
from urllib.parse import urlparse, parse_qs

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from engine.cert_generator import generate_self_signed_cert
from backend.services.remediation_advisor import generate_recommendation


def load_latest_scan_data(selected_scan_id=None):
    """
    Loads findings dynamically from database if present, with fallback to data/ files.
    Only loads findings for the specified or most recent scan and deduplicates findings per check.
    """
    findings = []
    target_url = "http://localhost:3000"
    endpoints_scanned = 4
    timestamp = "2026-08-30 00:00:00"
    scans_history = [
        {"id": 35, "target": "http://localhost:3000", "status": "COMPLETED"},
        {"id": 34, "target": "http://localhost:8080", "status": "COMPLETED"}
    ]

    try:
        from backend.database import SessionLocal
        from backend.models import Scan, Subdomain, Finding, AuditLog

        db = SessionLocal()
        
        # Load Scan History for persistent sidebar
        all_scans = db.query(Scan).order_by(Scan.id.desc()).limit(10).all()
        if all_scans:
            scans_history = [
                {
                    "id": s.id,
                    "target": s.target,
                    "status": s.status,
                    "created_at": str(s.created_at)[:19] if s.created_at else ""
                }
                for s in all_scans
            ]

        if selected_scan_id:
            db_scan = db.query(Scan).filter(Scan.id == selected_scan_id).first()
        else:
            db_scan = db.query(Scan).order_by(Scan.id.desc()).first()

        if db_scan:
            target_url = db_scan.target
            timestamp = str(db_scan.created_at)

            # Query findings associated ONLY with the selected scan
            db_findings = (
                db.query(Finding)
                .join(Subdomain, Finding.subdomain_id == Subdomain.id)
                .filter(Subdomain.scan_id == db_scan.id)
                .order_by(Finding.id.asc())
                .all()
            )

            # Fallback to recent scan with findings if current has none
            if not db_findings:
                latest_scan_with_findings = (
                    db.query(Scan)
                    .join(Subdomain, Subdomain.scan_id == Scan.id)
                    .join(Finding, Finding.subdomain_id == Subdomain.id)
                    .order_by(Scan.id.desc())
                    .first()
                )
                if latest_scan_with_findings:
                    db_scan = latest_scan_with_findings
                    target_url = db_scan.target
                    timestamp = str(db_scan.created_at)
                    db_findings = (
                        db.query(Finding)
                        .join(Subdomain, Finding.subdomain_id == Subdomain.id)
                        .filter(Subdomain.scan_id == db_scan.id)
                        .order_by(Finding.id.asc())
                        .all()
                    )

            if db_findings:
                seen_checks = set()
                for f in db_findings:
                    check_key = (f.check_name or "").strip().lower()
                    if check_key in seen_checks:
                        continue
                    seen_checks.add(check_key)

                    sub = db.query(Subdomain).filter(Subdomain.id == f.subdomain_id).first()
                    host = sub.hostname if sub else target_url

                    rec_text = f.recommendation
                    snip_text = f.config_snippet
                    advice = generate_recommendation({"check_name": f.check_name, "severity": f.severity, "evidence": f.evidence})
                    if not rec_text:
                        rec_text = advice.get("recommendation")
                        snip_text = advice.get("config_snippet")

                    findings.append({
                        "id": f.id,
                        "title": f.check_name,
                        "severity": f.severity,
                        "evidence": f.evidence or "N/A",
                        "endpoint": host,
                        "recommendation": rec_text,
                        "config_snippet": snip_text,
                        "status": f.status,
                        "ml_confidence": f.ml_confidence,
                        "ml_predicted_label": f.ml_predicted_label,
                        "review_deadline": str(f.review_deadline) if f.review_deadline else None,
                        "previous_state": f.previous_state,
                        "approved_at": str(f.approved_at) if f.approved_at else None,
                        "approved_by": f.approved_by,
                        "full_fix_guide": advice.get("full_fix_guide"),
                        "is_in_cisa_kev": getattr(f, "is_in_cisa_kev", False),
                        "epss_score": getattr(f, "epss_score", None),
                        "epss_percentile": getattr(f, "epss_percentile", None),
                    })
                agent_logs = (
                    db.query(AuditLog)
                    .filter(AuditLog.actor == "agent")
                    .order_by(AuditLog.id.desc())
                    .limit(10)
                    .all()
                )
                agent_triage_actions = [
                    {
                        "id": log.id,
                        "action": log.action,
                        "finding_id": log.finding_id,
                        "actor_name": log.actor_name,
                        "timestamp": str(log.timestamp)[:19] if log.timestamp else None,
                    }
                    for log in agent_logs
                ]
                # Compute Attack Path Graph & Threat Vector Score
                from backend.services.threat_correlation import compute_attack_path_graph
                threat_graph_data = compute_attack_path_graph(db, db_scan.id)

                scan_id_val = db_scan.id
                db.close()
                return {
                    "scan_id": scan_id_val,
                    "target_url": target_url,
                    "endpoints_scanned": endpoints_scanned,
                    "total_vulnerabilities": len(findings),
                    "findings": findings,
                    "timestamp": timestamp,
                    "agent_triage_actions": agent_triage_actions,
                    "threat_graph_data": threat_graph_data,
                    "scans_history": scans_history,
                }
            db.close()
    except Exception as err:
        sys.stderr.write(f"[!] Warning reading DB findings in dashboard: {err}\n")

    # Fallback to local report files
    latest_report_path = os.path.join(PROJECT_ROOT, "data", "scan_report_latest.json")
    if os.path.exists(latest_report_path):
        try:
            with open(latest_report_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                target_url = data.get("target_url", target_url)
                timestamp = data.get("timestamp")
                summary = data.get("summary", {})
                endpoints_scanned = summary.get("total_endpoints_scanned", 1)

                raw_findings = data.get("findings", [])
                seen_checks = set()
                for idx, item in enumerate(raw_findings, start=1):
                    t = item.get("title", item.get("check_name", "Security Issue"))
                    check_key = t.strip().lower()
                    if check_key in seen_checks:
                        continue
                    seen_checks.add(check_key)

                    sev = item.get("severity", "MEDIUM")
                    ev = item.get("evidence", "N/A")
                    advice = generate_recommendation({"check_name": t, "severity": sev, "evidence": ev})
                    findings.append({
                        "id": item.get("id", idx),
                        "title": t,
                        "severity": sev,
                        "evidence": ev,
                        "endpoint": item.get("endpoint", target_url),
                        "recommendation": advice.get("recommendation"),
                        "config_snippet": advice.get("config_snippet"),
                        "status": item.get("status", "OPEN"),
                        "ml_confidence": item.get("ml_confidence", 0.95),
                        "ml_predicted_label": item.get("ml_predicted_label", 1),
                        "review_deadline": item.get("review_deadline"),
                        "previous_state": item.get("previous_state"),
                        "approved_at": item.get("approved_at"),
                        "approved_by": item.get("approved_by"),
                        "full_fix_guide": advice.get("full_fix_guide"),
                        "is_in_cisa_kev": False,
                        "epss_score": None,
                        "epss_percentile": None,
                    })

                return {
                    "scan_id": 1,
                    "target_url": target_url,
                    "endpoints_scanned": endpoints_scanned,
                    "total_vulnerabilities": len(findings),
                    "findings": findings,
                    "timestamp": timestamp,
                    "agent_triage_actions": [],
                    "threat_graph_data": {},
                    "scans_history": scans_history,
                }
        except Exception as err:
            sys.stderr.write(f"[!] Error parsing scan_report_latest.json: {err}\n")

    return {
        "scan_id": 1,
        "target_url": target_url,
        "endpoints_scanned": endpoints_scanned,
        "total_vulnerabilities": len(findings),
        "findings": findings,
        "timestamp": timestamp,
        "agent_triage_actions": [],
        "threat_graph_data": {},
        "scans_history": scans_history,
    }


def calculate_security_posture(findings):
    """
    Computes Security Posture Score (0-100), Letter Grade, and Severity Distribution %
    """
    if not findings:
        return {
            "score": 100,
            "grade": "A+",
            "level": "OPTIMAL",
            "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "pcts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        }

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = str(f.get("severity", "LOW")).upper()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["LOW"] += 1

    total = len(findings)
    deductions = (counts["CRITICAL"] * 25) + (counts["HIGH"] * 15) + (counts["MEDIUM"] * 8) + (counts["LOW"] * 3) + (counts["INFO"] * 1)
    score = max(0, min(100, 100 - deductions))

    if score >= 90:
        grade, level = "A+", "OPTIMAL"
    elif score >= 80:
        grade, level = "A-", "GOOD"
    elif score >= 70:
        grade, level = "B", "MODERATE"
    elif score >= 55:
        grade, level = "C", "ELEVATED THREAT"
    elif score >= 40:
        grade, level = "D", "HIGH RISK"
    else:
        grade, level = "F", "CRITICAL RISK"

    pcts = {k: round((v / total) * 100, 1) if total > 0 else 0 for k, v in counts.items()}

    return {
        "score": score,
        "grade": grade,
        "level": level,
        "counts": counts,
        "pcts": pcts
    }


def render_dashboard_html(selected_scan_id=None) -> str:
    scan_data = load_latest_scan_data(selected_scan_id=selected_scan_id)
    findings = scan_data["findings"]
    target_url = scan_data["target_url"]
    endpoints_scanned = scan_data["endpoints_scanned"]
    total_vulns = scan_data["total_vulnerabilities"]
    scans_history = scan_data.get("scans_history", [])

    posture = calculate_security_posture(findings)
    posture_score = posture["score"]
    posture_grade = posture["grade"]
    posture_level = posture["level"]
    counts = posture["counts"]
    pcts = posture["pcts"]

    scan_id_val = scan_data.get("scan_id", 1)
    agent_triage_actions = scan_data.get("agent_triage_actions", [])

    crit_cnt = counts.get("CRITICAL", 0)
    high_cnt = counts.get("HIGH", 0)
    agent_summary_text = (
        f"Scan #{scan_id_val} Risk Evaluation: Total {total_vulns} findings discovered. "
        f"Requires immediate human attention for {crit_cnt} Critical and {high_cnt} High risk vulnerabilities. "
        f"Zero findings auto-approved (Human Approval Policy Enforced)."
    )

    threat_graph_data = scan_data.get("threat_graph_data") or {}
    threat_vector_score = threat_graph_data.get("composite_threat_score", 0.0)
    threat_chains = threat_graph_data.get("attack_chains", [])

    if not threat_chains:
        threat_chains_html = '<div style="color: var(--text-muted); font-size: 0.8rem; font-style: italic;">No compound attack paths detected in target infrastructure.</div>'
    else:
        chain_items = []
        for ch in threat_chains:
            ch_name = html.escape(str(ch.get("chain_name")))
            ch_imp = html.escape(str(ch.get("impact")))
            ch_desc = html.escape(str(ch.get("description")))
            chain_items.append(
                f'<div style="background: rgba(0, 0, 0, 0.7); border: 1px solid #ff4d4d; border-radius: 8px; padding: 10px 14px; margin-bottom: 8px;">'
                f'<div style="font-weight: 700; color: #ff4d4d; font-size: 0.9rem; display: flex; justify-content: space-between;"><span> Compound Chain: {ch_name}</span> <span style="background: rgba(255, 77, 77, 0.2); color: #ff8080; padding: 2px 8px; border-radius: 12px; font-size: 0.72rem; border: 1px solid #ff4d4d;">CRITICAL BLAST RADIUS</span></div>'
                f'<div style="color: #e4e4e7; font-size: 0.84rem; margin-top: 4px;"><strong>Target Impact:</strong> {ch_imp}</div>'
                f'<div style="color: #a1a1aa; font-size: 0.8rem; margin-top: 2px;">{ch_desc}</div>'
                f'</div>'
            )
        threat_chains_html = "".join(chain_items)

    if not agent_triage_actions:
        agent_actions_html = '<div style="color: var(--text-muted); font-size: 0.8rem; font-style: italic;">No agent triage actions recorded for this scan yet. Click " Trigger AI Agent Triage" above to run the 4-tool reasoning loop.</div>'
    else:
        log_items = []
        for log in agent_triage_actions:
            act_name = html.escape(str(log.get("action")))
            actor_display = html.escape(str(log.get("actor_name") or "NKAT_Agent"))
            f_id_ref = log.get("finding_id")
            ts_str = html.escape(str(log.get("timestamp") or ""))
            f_ref_str = f"Finding #{f_id_ref}" if f_id_ref else "Target Infrastructure"
            log_items.append(
                f'<div style="background: rgba(0, 0, 0, 0.8); border: 1px solid rgba(255, 255, 255, 0.2); border-radius: 6px; padding: 6px 10px; font-size: 0.78rem; display: flex; justify-content: space-between; align-items: center;">'
                f'<div><strong style="color: #ffffff;"> [{actor_display}]</strong> executed <code style="background: rgba(255,255,255,0.1); padding: 2px 6px; border-radius: 4px; color: #ffffff; border: 1px solid rgba(255,255,255,0.2);">{act_name}</code> on <span>{f_ref_str}</span></div>'
                f'<div style="color: #a1a1aa; font-size: 0.72rem;">{ts_str}</div>'
                f'</div>'
            )
        agent_actions_html = "".join(log_items)

    cards = []
    if not findings:
        cards.append("""
        <div class="empty-state-card">
          <div style="font-size: 2.5rem; margin-bottom: 0.5rem;"></div>
          <h3 style="color: #fff; font-size: 1.1rem; margin-bottom: 0.25rem;">Target Infrastructure Clean</h3>
          <p style="color: var(--text-secondary); font-size: 0.85rem;">Zero active vulnerabilities detected on this endpoint.</p>
        </div>
        """)
    else:
        for item in findings:
            f_id = item["id"]
            title = html.escape(str(item["title"]))
            sev = str(item["severity"]).upper()
            ev = html.escape(str(item.get("evidence", "N/A")))
            endpoint = html.escape(str(item.get("endpoint", target_url)))
            rec = html.escape(str(item.get("recommendation", "Review server configuration.")))
            snip = item.get("config_snippet")
            status_str = str(item.get("status", "OPEN")).upper()

            sev_class = f"sev-{sev.lower()}"

            status_badge_class = "status-open"
            status_display_text = "OPEN"
            if status_str == "AUTO_APPROVED":
                status_badge_class = "status-approved"
                status_display_text = " AUTO-APPROVED (TIMEOUT)"
            elif status_str == "APPROVED":
                status_badge_class = "status-approved"
                status_display_text = "APPROVED"
            elif status_str in ("REJECTED", "FALSE_POSITIVE"):
                status_badge_class = "status-rejected"
                status_display_text = "REJECTED"
            elif status_str == "RESOLVED":
                status_badge_class = "status-approved"
                status_display_text = "RESOLVED"

            approval_info = ""
            if item.get("approved_by"):
                app_by = html.escape(str(item["approved_by"]))
                approval_info = f'<span style="font-size: 0.72rem; color: var(--text-muted); margin-left: 6px;">by {app_by}</span>'

            deadline_info = ""
            if item.get("review_deadline"):
                dl_str = html.escape(str(item["review_deadline"])[:19])
                deadline_info = f'<span style="font-size: 0.73rem; color: #ffffff; background: rgba(0, 0, 0, 0.8); padding: 2px 8px; border-radius: 10px; border: 1px solid rgba(255, 255, 255, 0.3);"> Deadline: {dl_str}</span>'

            # Threat Intel Badges (CISA KEV + EPSS)
            cisa_kev_badge = ""
            if item.get("is_in_cisa_kev"):
                cisa_kev_badge = '<span style="font-size: 0.72rem; color: #ff4d4d; background: rgba(0, 0, 0, 0.85); border: 1px solid #ff4d4d; padding: 2px 8px; border-radius: 10px; font-weight: 700;"> CISA KEV Exploited</span>'

            epss_val = item.get("epss_score")
            epss_badge = ""
            if epss_val is not None:
                epss_badge = f'<span style="font-size: 0.72rem; color: #ffffff; background: rgba(0, 0, 0, 0.85); border: 1px solid rgba(255, 255, 255, 0.4); padding: 2px 8px; border-radius: 10px; font-weight: 600;"> EPSS: {epss_val}</span>'

            snip_html = ""
            if snip:
                esc_snip = html.escape(str(snip))
                snip_html = f"""
                <details style="margin-top: 10px;">
                  <summary style="font-size: 0.8rem; color: #ffffff; cursor: pointer; font-weight: 600;">View Raw Fix Snippet</summary>
                  <pre style="background: rgba(0, 0, 0, 0.9); padding: 10px 12px; border-radius: 8px; font-family: 'Consolas', monospace; font-size: 0.78rem; color: #ffffff; margin-top: 6px; white-space: pre-wrap; border: 1px solid var(--border-card);">{esc_snip}</pre>
                </details>"""

            guide_html = ""
            guide = item.get("full_fix_guide") or generate_recommendation({"check_name": item["title"], "severity": item["severity"], "evidence": item.get("evidence")}).get("full_fix_guide")
            if guide:
                meaning_text = html.escape(str(guide.get("plain_language_meaning", "")))
                risk_text = html.escape(str(guide.get("why_it_is_risky", "")))
                fix_steps = guide.get("fix_steps", {})
                nginx_step = html.escape(str(fix_steps.get("nginx", "")))
                apache_step = html.escape(str(fix_steps.get("apache", "")))
                express_step = html.escape(str(fix_steps.get("express_node", "")))
                verification_text = html.escape(str(guide.get("verification_steps", "")))
                rollback_text = html.escape(str(guide.get("rollback_note", "")))

                owasp_cat = html.escape(str(guide.get("owasp_category") or "A05:2021 - Security Misconfiguration"))
                cwe_obj = guide.get("cwe_info", {})
                cwe_badge = f"{html.escape(str(cwe_obj.get('cwe_id', 'CWE-16')))}: {html.escape(str(cwe_obj.get('name', 'Configuration')))}" if isinstance(cwe_obj, dict) and cwe_obj.get("cwe_id") else "CWE-16: Configuration"

                cve_obj = guide.get("nvd_cve_details", {})
                cve_html = ""
                if isinstance(cve_obj, dict) and cve_obj.get("cve_id"):
                    cve_id_str = html.escape(str(cve_obj["cve_id"]))
                    cvss_val = html.escape(str(cve_obj.get("cvss_score") or "N/A"))
                    cve_html = f'<div style="margin-top: 6px; background: rgba(0, 0, 0, 0.85); border: 1px solid #ff4d4d; padding: 6px 10px; border-radius: 6px; color: #ffffff;"><strong style="color: #ff4d4d;"> NIST NVD Reference ({cve_id_str}):</strong> CVSS v3 Base Score: <strong>{cvss_val}</strong> | Source: {html.escape(str(cve_obj.get("source", "NIST NVD")))}</div>'

                ref_badges_html = f"""
                <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 8px;">
                  <span style="background: rgba(0, 0, 0, 0.85); border: 1px solid #ffffff; color: #ffffff; font-weight: 600; padding: 2px 8px; border-radius: 10px; font-size: 0.72rem;"> OWASP: {owasp_cat}</span>
                  <span style="background: rgba(0, 0, 0, 0.85); border: 1px solid #a1a1aa; color: #e4e4e7; font-weight: 600; padding: 2px 8px; border-radius: 10px; font-size: 0.72rem;"> MITRE: {cwe_badge}</span>
                </div>"""

                citation_text = html.escape(str(guide.get("authoritative_citation") or f"Per OWASP {owasp_cat} and MITRE {cwe_badge}"))
                citation_html = f'<div style="margin-bottom: 8px; background: rgba(0, 0, 0, 0.85); border-left: 4px solid #ffffff; border: 1px solid rgba(255, 255, 255, 0.2); padding: 6px 10px; border-radius: 4px; font-size: 0.76rem; color: #e4e4e7;"><strong style="color: #ffffff;"> Standard Citation:</strong> {citation_text}</div>'

                guide_html = f"""
                <details class="fix-guide-details" style="margin-top: 12px; width: 100%; border-radius: var(--radius-md); background: var(--bg-card); border: 1px solid var(--border-card); box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4); overflow: hidden; transition: all 0.25s ease;">
                  <summary style="padding: 0.85rem 1.1rem; background: rgba(0, 0, 0, 0.85); border-bottom: 1px solid var(--border-card); color: #ffffff; font-weight: 700; font-size: 0.88rem; cursor: pointer; display: flex; align-items: center; justify-content: space-between; user-select: none;">
                    <span style="display: flex; align-items: center; gap: 8px;"> HOW TO FIX — Technical Remediation & Standards Guide</span>
                    <span style="font-size: 0.74rem; background: rgba(255, 255, 255, 0.15); padding: 3px 8px; border-radius: 12px; color: #ffffff; border: 1px solid rgba(255, 255, 255, 0.3);">Click to Expand Guide </span>
                  </summary>
                  <div style="padding: 1.25rem; font-size: 0.82rem; color: #e2e8f0; line-height: 1.5; display: flex; flex-direction: column; gap: 0.85rem;">
                    
                    {ref_badges_html}
                    {cve_html}
                    {citation_html}
                    
                    <!-- Problem Definition & Risk Cards -->
                    <div style="display: grid; grid-template-columns: 1fr; gap: 0.85rem;">
                      <div class="fix-card" style="background: var(--bg-elevated); padding: 1rem; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); border-left: 4px solid #ffffff;">
                        <strong style="color: #ffffff; font-size: 0.86rem; display: flex; align-items: center; gap: 6px;"> What the Problem Is:</strong>
                        <p style="margin-top: 6px; margin-bottom: 0; color: #d4d4d8; font-size: 0.84rem;">{meaning_text}</p>
                      </div>
                      <div class="fix-card" style="background: var(--bg-elevated); padding: 1rem; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); border-left: 4px solid #ff4d4d;">
                        <strong style="color: #ff4d4d; font-size: 0.86rem; display: flex; align-items: center; gap: 6px;"> Security Risk & Impact:</strong>
                        <p style="margin-top: 6px; margin-bottom: 0; color: #d4d4d8; font-size: 0.84rem;">{risk_text}</p>
                      </div>
                    </div>
                    
                    <div style="font-weight: 700; color: #ffffff; font-size: 0.88rem; margin-top: 0.5rem; display: flex; align-items: center; gap: 6px;">
                      <span> Multi-Server Configuration & Remediation Engine:</span>
                    </div>
                    
                    <!-- Server Fix Cards -->
                    <div style="display: flex; flex-direction: column; gap: 0.75rem;">
                      <div class="fix-card" style="background: var(--bg-elevated); padding: 0.85rem 1rem; border-radius: var(--radius-sm); border: 1px solid rgba(255, 255, 255, 0.2);">
                        <div style="color: #ffffff; font-weight: 700; margin-bottom: 6px; font-size: 0.82rem; display: flex; align-items: center; gap: 6px;"> 1. Nginx Web Server Configuration:</div>
                        <pre style="background: rgba(0, 0, 0, 0.9); padding: 10px 12px; border-radius: var(--radius-sm); font-family: 'Consolas', 'Fira Code', monospace; font-size: 0.78rem; color: #ffffff; white-space: pre-wrap; margin: 0; border: 1px solid rgba(255, 255, 255, 0.2);">{nginx_step}</pre>
                      </div>
                      <div class="fix-card" style="background: var(--bg-elevated); padding: 0.85rem 1rem; border-radius: var(--radius-sm); border: 1px solid rgba(255, 255, 255, 0.2);">
                        <div style="color: #e4e4e7; font-weight: 700; margin-bottom: 6px; font-size: 0.82rem; display: flex; align-items: center; gap: 6px;"> 2. Apache HTTP Server Configuration (.htaccess / VHost):</div>
                        <pre style="background: rgba(0, 0, 0, 0.9); padding: 10px 12px; border-radius: var(--radius-sm); font-family: 'Consolas', 'Fira Code', monospace; font-size: 0.78rem; color: #e4e4e7; white-space: pre-wrap; margin: 0; border: 1px solid rgba(255, 255, 255, 0.2);">{apache_step}</pre>
                      </div>
                      <div class="fix-card" style="background: var(--bg-elevated); padding: 0.85rem 1rem; border-radius: var(--radius-sm); border: 1px solid rgba(255, 255, 255, 0.2);">
                        <div style="color: #a1a1aa; font-weight: 700; margin-bottom: 6px; font-size: 0.82rem; display: flex; align-items: center; gap: 6px;"> 3. Express / Node.js Application Code Fix:</div>
                        <pre style="background: rgba(0, 0, 0, 0.9); padding: 10px 12px; border-radius: var(--radius-sm); font-family: 'Consolas', 'Fira Code', monospace; font-size: 0.78rem; color: #a1a1aa; white-space: pre-wrap; margin: 0; border: 1px solid rgba(255, 255, 255, 0.2);">{express_step}</pre>
                      </div>
                    </div>

                    <!-- Verification & Rollback Procedure Cards -->
                    <div style="display: grid; grid-template-columns: 1fr; gap: 0.75rem;">
                      <div class="fix-card" style="background: rgba(0, 0, 0, 0.7); border: 1px solid rgba(255, 255, 255, 0.3); padding: 0.85rem 1rem; border-radius: var(--radius-sm); color: #ffffff;">
                        <strong style="color: #ffffff; font-size: 0.84rem;"> Verification Procedure:</strong>
                        <p style="margin-top: 4px; margin-bottom: 0; color: #e4e4e7; font-size: 0.82rem;">{verification_text}</p>
                      </div>
                      <div class="fix-card" style="background: rgba(0, 0, 0, 0.7); border: 1px solid #ff4d4d; padding: 0.85rem 1rem; border-radius: var(--radius-sm); color: #ff8080;">
                        <strong style="color: #ff4d4d; font-size: 0.84rem;">↩ Safe Rollback Procedure:</strong>
                        <p style="margin-top: 4px; margin-bottom: 0; color: #ff8080; font-size: 0.82rem;">{rollback_text}</p>
                      </div>
                    </div>

                  </div>
                </details>"""

            ml_conf = item.get("ml_confidence")
            ml_lbl = item.get("ml_predicted_label")

            ml_badge_html = ""
            if ml_conf is not None:
                conf_pct = round(ml_conf * 100, 1)
                if ml_lbl == 1:
                    lbl_text = "Malicious"
                    lbl_color = "var(--sev-critical-text)"
                    lbl_border = "var(--sev-critical-border)"
                else:
                    lbl_text = "Benign"
                    lbl_color = "var(--sev-low-text)"
                    lbl_border = "var(--sev-low-border)"

                ml_badge_html = f"""
                <span class="ai-badge" style="background: rgba(0, 0, 0, 0.85); border: 1px solid {lbl_border}; color: {lbl_color};">
                  <span> AI Threat: {lbl_text}</span>
                  <span style="opacity: 0.85; font-size: 0.7rem;">({conf_pct}% Conf)</span>
                </span>"""

            restore_btn = ""
            if status_str in ("AUTO_APPROVED", "RESOLVED"):
                restore_btn = f'<button class="btn-action btn-restore" onclick="restoreFinding({f_id})">Restore State</button>'

            cards.append(f"""
            <div class="finding-card" id="finding-row-{f_id}">
              <div class="card-header-bar">
                <div class="meta-left">
                  <span class="severity-pill {sev_class}">{sev}</span>
                  {ml_badge_html}
                  {cisa_kev_badge}
                  {epss_badge}
                  {deadline_info}
                </div>
                <div class="meta-right">
                  <span class="status-badge {status_badge_class}">{status_display_text}</span>
                  {approval_info}
                </div>
              </div>

              <div class="card-title-block">
                <span class="finding-id-tag">#{f_id}</span>
                <h3 class="finding-title-text">{title}</h3>
                <span class="endpoint-chip"> {endpoint}</span>
              </div>

              <div class="card-recommendation-box">
                <div style="font-weight: 600; color: #ffffff; margin-bottom: 4px; font-size: 0.84rem;"> Actionable Fix Recommendation:</div>
                <div style="color: var(--text-primary); font-size: 0.86rem; line-height: 1.4;">{rec}</div>
                {snip_html}
                {guide_html}
              </div>

              <div class="card-actions-bar">
                <div style="font-size: 0.76rem; color: var(--text-muted);">Evidence: <span style="color: #cbd5e1;">{ev[:80]}...</span></div>
                <div class="action-btn-group">
                  <button class="btn-action btn-approve" onclick="approveFinding({f_id})">Approve Fix</button>
                  <button class="btn-action btn-reject" onclick="rejectFinding({f_id})">Reject / False Positive</button>
                  {restore_btn}
                </div>
              </div>
            </div>
            """)

        findings_cards_html = "".join(cards)

    # Sidebar Scan Select Dropdown Options HTML
    select_options = []
    for sc in scans_history:
        s_id = sc.get("id")
        s_tg = html.escape(str(sc.get("target") or ""))
        selected_attr = "selected" if s_id == scan_id_val else ""
        select_options.append(f'<option value="{s_id}" {selected_attr}>Scan #{s_id}: {s_tg}</option>')
    sidebar_scan_select_options = "".join(select_options)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NKAT Threat Sentinel — Enterprise Cybersecurity Console</title>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg-base: #05070a;
      --bg-sidebar: rgba(10, 12, 18, 0.92);
      --bg-card: rgba(18, 22, 30, 0.86);
      --bg-elevated: rgba(24, 30, 42, 0.92);

      --accent-white: #ffffff;
      --accent-silver: #e4e4e7;
      --accent-muted: #a1a1aa;
      --accent-cyan: #ffffff;

      --text-primary: #ffffff;
      --text-secondary: #d4d4d8;
      --text-muted: #94949e;

      --border-subtle: rgba(255, 255, 255, 0.14);
      --border-card: rgba(255, 255, 255, 0.22);
      --border-highlight: rgba(255, 255, 255, 0.45);

      /* Monochromatic Legible Severity Scale */
      --sev-critical-bg: rgba(0, 0, 0, 0.88);
      --sev-critical-text: #ff4d4d;
      --sev-critical-border: #ff4d4d;

      --sev-high-bg: rgba(0, 0, 0, 0.88);
      --sev-high-text: #ff944d;
      --sev-high-border: #ff944d;

      --sev-medium-bg: rgba(0, 0, 0, 0.88);
      --sev-medium-text: #ffcc00;
      --sev-medium-border: #ffcc00;

      --sev-low-bg: rgba(0, 0, 0, 0.88);
      --sev-low-text: #a1a1aa;
      --sev-low-border: #71717a;

      --radius-sm: 6px;
      --radius-md: 10px;
      --radius-lg: 14px;
    }}

    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: 'Outfit', sans-serif; }}

    body {{
      background: #05070a url('/bg.jpg') no-repeat center center fixed;
      background-size: cover;
      color: var(--text-primary);
      min-height: 100vh;
      display: flex;
      position: relative;
    }}

    /* Full-Screen Dark Overlay for Background Image */
    body::before {{
      content: '';
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: radial-gradient(circle at center, rgba(5, 7, 10, 0.75) 0%, rgba(5, 7, 10, 0.94) 100%);
      pointer-events: none;
      z-index: 0;
    }}

    /* Persistent Product Sidebar Navigation */
    .app-sidebar {{
      width: 270px;
      background: var(--bg-sidebar);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border-right: 1px solid var(--border-subtle);
      display: flex;
      flex-direction: column;
      position: fixed;
      top: 0;
      bottom: 0;
      left: 0;
      z-index: 100;
      overflow-y: auto;
    }}

    .sidebar-brand {{
      padding: 1.5rem 1.25rem;
      display: flex;
      align-items: center;
      gap: 0.75rem;
      border-bottom: 1px solid var(--border-subtle);
    }}

    .brand-logo {{
      width: 40px;
      height: 40px;
      background: #ffffff;
      color: #000000;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      box-shadow: 0 0 16px rgba(255, 255, 255, 0.3);
    }}

    .brand-info {{
      display: flex;
      flex-direction: column;
    }}

    .brand-name {{
      font-size: 1.1rem;
      font-weight: 700;
      color: #ffffff;
    }}

    .brand-tag {{
      font-size: 0.72rem;
      color: var(--accent-silver);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      font-weight: 600;
    }}

    .sidebar-section-title {{
      padding: 1rem 1.25rem 0.4rem;
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--text-muted);
      font-weight: 700;
    }}

    .sidebar-nav {{
      padding: 0.5rem 0.75rem;
      display: flex;
      flex-direction: column;
      gap: 0.35rem;
    }}

    .nav-item {{
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 0.65rem 0.85rem;
      border-radius: var(--radius-sm);
      color: var(--text-secondary);
      text-decoration: none;
      font-size: 0.86rem;
      font-weight: 500;
      transition: all 0.25s ease;
    }}

    .nav-item:hover, .nav-item.active {{
      background: rgba(255, 255, 255, 0.12);
      color: #ffffff;
      font-weight: 600;
      border: 1px solid rgba(255, 255, 255, 0.2);
    }}

    .auth-input {{
      width: 100%;
      padding: 6px 10px;
      margin-top: 6px;
      background: rgba(0, 0, 0, 0.9);
      border: 1px solid rgba(255, 255, 255, 0.2);
      border-radius: 4px;
      color: #fff;
      font-size: 0.78rem;
    }}

    .auth-input:focus {{
      outline: none;
      border-color: #ffffff;
    }}

    .sidebar-footer {{
      padding: 1.25rem;
      border-top: 1px solid var(--border-subtle);
      margin-top: auto;
    }}

    .tls-badge {{
      display: flex;
      align-items: center;
      gap: 0.5rem;
      background: rgba(0, 0, 0, 0.8);
      border: 1px solid rgba(255, 255, 255, 0.3);
      color: #ffffff;
      padding: 0.4rem 0.75rem;
      border-radius: 20px;
      font-size: 0.75rem;
      font-weight: 600;
    }}

    .status-dot {{
      width: 6px;
      height: 6px;
      background: #ffffff;
      border-radius: 50%;
      box-shadow: 0 0 8px #ffffff;
    }}

    /* Main Area Container */
    .main-area {{
      margin-left: 270px;
      flex: 1;
      padding: 2rem;
      max-width: 1380px;
      width: calc(100% - 270px);
      position: relative;
      z-index: 1;
    }}

    .header-bar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1.75rem;
    }}

    .page-title {{
      font-size: 1.5rem;
      font-weight: 700;
      color: #fff;
    }}

    .page-sub {{
      font-size: 0.84rem;
      color: var(--text-secondary);
      margin-top: 0.25rem;
    }}

    /* Prominent Top Action Buttons */
    .top-action-group {{
      display: flex;
      gap: 0.75rem;
      align-items: center;
    }}

    .btn-export-pdf {{
      background: #ffffff;
      border: 1px solid #ffffff;
      color: #000000;
      font-weight: 700;
      padding: 0.6rem 1.1rem;
      border-radius: 8px;
      font-size: 0.86rem;
      cursor: pointer;
      box-shadow: 0 4px 14px rgba(255, 255, 255, 0.2);
      transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    }}

    .btn-export-pdf:hover {{
      transform: translateY(-2px);
      background: #e4e4e7;
      box-shadow: 0 6px 20px rgba(255, 255, 255, 0.35);
    }}

    /* Number-First Metrics & Posture Card */
    .grid-metrics {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1.25rem;
      margin-bottom: 1.5rem;
    }}

    .metric-card {{
      background: var(--bg-card);
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
      border: 1px solid var(--border-card);
      border-radius: var(--radius-md);
      padding: 1.25rem;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.5);
      transition: transform 0.25s cubic-bezier(0.4, 0, 0.2, 1), border-color 0.25s ease;
    }}

    .metric-card:hover {{
      transform: translateY(-2px);
      border-color: var(--border-highlight);
    }}

    .metric-title {{
      font-size: 0.76rem;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.8px;
      font-weight: 600;
      margin-bottom: 0.4rem;
    }}

    .metric-value {{
      font-size: 1.6rem;
      font-weight: 700;
      color: #fff;
      word-break: break-all;
    }}

    .metric-sub {{
      font-size: 0.78rem;
      color: var(--accent-silver);
      margin-top: 0.4rem;
    }}

    /* Security Posture Breakdown Card */
    .posture-card {{
      background: var(--bg-card);
      backdrop-filter: blur(10px);
      border: 1px solid var(--border-card);
      border-radius: var(--radius-md);
      padding: 1.5rem;
      margin-bottom: 1.5rem;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
    }}

    .posture-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
    }}

    .posture-score-badge {{
      display: flex;
      align-items: center;
      gap: 0.75rem;
      background: rgba(0, 0, 0, 0.8);
      border: 1px solid var(--border-highlight);
      padding: 0.5rem 1rem;
      border-radius: 30px;
    }}

    .grade-circle {{
      width: 32px;
      height: 32px;
      border-radius: 50%;
      background: #ffffff;
      color: #000000;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-size: 0.95rem;
    }}

    .distribution-bar {{
      height: 12px;
      background: rgba(255, 255, 255, 0.08);
      border-radius: 6px;
      display: flex;
      overflow: hidden;
      margin-top: 0.75rem;
    }}

    .bar-seg {{
      height: 100%;
      transition: width 0.4s ease;
    }}

    .bar-critical {{ background: #ff4d4d; }}
    .bar-high {{ background: #ff944d; }}
    .bar-medium {{ background: #ffcc00; }}
    .bar-low {{ background: #a1a1aa; }}

    .dist-legend {{
      display: flex;
      gap: 1.25rem;
      margin-top: 0.85rem;
      flex-wrap: wrap;
    }}

    .legend-item {{
      display: flex;
      align-items: center;
      gap: 0.4rem;
      font-size: 0.78rem;
      color: var(--text-secondary);
    }}

    .legend-dot {{
      width: 8px;
      height: 8px;
      border-radius: 50%;
    }}

    /* Card-Based Finding Stream */
    .section-card {{
      background: var(--bg-card);
      backdrop-filter: blur(10px);
      border: 1px solid var(--border-card);
      border-radius: var(--radius-md);
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }}

    .section-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1.25rem;
      color: #fff;
      font-size: 1.1rem;
      font-weight: 700;
    }}

    .finding-card {{
      background: var(--bg-elevated);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      padding: 1.25rem;
      margin-bottom: 1rem;
      transition: transform 0.25s cubic-bezier(0.4, 0, 0.2, 1), border-color 0.25s ease, box-shadow 0.25s ease;
    }}

    .finding-card:hover {{
      transform: translateY(-2px);
      border-color: var(--border-highlight);
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.6);
    }}

    .card-header-bar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.75rem;
      flex-wrap: wrap;
      gap: 0.5rem;
    }}

    .meta-left {{
      display: flex;
      align-items: center;
      gap: 0.6rem;
      flex-wrap: wrap;
    }}

    .severity-pill {{
      padding: 0.2rem 0.65rem;
      border-radius: 12px;
      font-weight: 700;
      font-size: 0.75rem;
      letter-spacing: 0.5px;
    }}

    .sev-critical {{ background: var(--sev-critical-bg); color: var(--sev-critical-text); border: 1px solid var(--sev-critical-border); }}
    .sev-high {{ background: var(--sev-high-bg); color: var(--sev-high-text); border: 1px solid var(--sev-high-border); }}
    .sev-medium {{ background: var(--sev-medium-bg); color: var(--sev-medium-text); border: 1px solid var(--sev-medium-border); }}
    .sev-low {{ background: var(--sev-low-bg); color: var(--sev-low-text); border: 1px solid var(--sev-low-border); }}

    .ai-badge {{
      display: flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.2rem 0.6rem;
      border-radius: 12px;
      font-size: 0.73rem;
      font-weight: 600;
    }}

    .status-badge {{
      padding: 0.25rem 0.75rem;
      border-radius: 20px;
      font-size: 0.75rem;
      font-weight: 700;
    }}

    .status-open {{ background: rgba(0, 0, 0, 0.85); color: #ffcc00; border: 1px solid #ffcc00; }}
    .status-approved {{ background: rgba(0, 0, 0, 0.85); color: #ffffff; border: 1px solid #ffffff; }}
    .status-rejected {{ background: rgba(0, 0, 0, 0.85); color: #ff4d4d; border: 1px solid #ff4d4d; }}

    .card-title-block {{
      margin-bottom: 0.75rem;
    }}

    .finding-id-tag {{
      font-size: 0.75rem;
      color: var(--text-muted);
      font-weight: 600;
    }}

    .finding-title-text {{
      font-size: 1.05rem;
      font-weight: 700;
      color: #fff;
      margin: 0.2rem 0 0.4rem;
    }}

    .endpoint-chip {{
      display: inline-block;
      font-size: 0.78rem;
      color: #ffffff;
      background: rgba(0, 0, 0, 0.7);
      padding: 0.2rem 0.6rem;
      border-radius: 4px;
      border: 1px solid rgba(255, 255, 255, 0.2);
    }}

    .card-recommendation-box {{
      background: rgba(0, 0, 0, 0.6);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      padding: 0.85rem 1rem;
      margin-bottom: 1rem;
    }}

    .card-actions-bar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-top: 1px solid var(--border-subtle);
      padding-top: 0.85rem;
      flex-wrap: wrap;
      gap: 0.5rem;
    }}

    .action-btn-group {{
      display: flex;
      gap: 0.5rem;
    }}

    .btn-action {{
      padding: 0.4rem 0.85rem;
      border-radius: 6px;
      font-size: 0.78rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      border: none;
    }}

    .btn-approve {{ background: rgba(0, 0, 0, 0.85); color: #ffffff; border: 1px solid #ffffff; }}
    .btn-approve:hover {{ background: #ffffff; color: #000000; }}

    .btn-reject {{ background: rgba(0, 0, 0, 0.85); color: #ff4d4d; border: 1px solid #ff4d4d; }}
    .btn-reject:hover {{ background: #ff4d4d; color: #000000; }}

    .btn-restore {{ background: rgba(0, 0, 0, 0.85); color: #e4e4e7; border: 1px solid #e4e4e7; }}
    .btn-restore:hover {{ background: #e4e4e7; color: #000000; }}

    /* Centered Black & White Sign In Overlay */
    .login-modal-overlay {{
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(5, 7, 10, 0.88);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      z-index: 1000;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: opacity 0.3s ease;
    }}

    .login-modal-box {{
      width: 380px;
      background: rgba(18, 22, 30, 0.95);
      border: 1px solid rgba(255, 255, 255, 0.25);
      border-radius: var(--radius-lg);
      padding: 2rem;
      box-shadow: 0 10px 40px rgba(0, 0, 0, 0.8);
      text-align: center;
    }}

    .skeleton-loader {{
      display: none;
      padding: 1.5rem;
      background: rgba(0, 0, 0, 0.9);
      border: 1px solid #ffffff;
      border-radius: 10px;
      text-align: center;
      margin-bottom: 1.5rem;
      color: #ffffff;
      font-weight: 700;
    }}

    .empty-state-card {{
      text-align: center;
      padding: 3rem 1rem;
      background: var(--bg-elevated);
      border-radius: var(--radius-md);
      border: 1px dashed var(--border-subtle);
    }}
  </style>
</head>
<body>

  <!-- Centered Black & White Sign In Overlay Modal -->
  <div id="loginOverlay" class="login-modal-overlay" style="display: none;">
    <div class="login-modal-box">
      <div style="width: 48px; height: 48px; background: #ffffff; color: #000; border-radius: 12px; margin: 0 auto 1.25rem; display: flex; align-items: center; justify-content: center; box-shadow: 0 0 20px rgba(255, 255, 255, 0.3);">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="m9 12 2 2 4-4"/>
        </svg>
      </div>
      <h2 style="color: #ffffff; font-size: 1.4rem; font-weight: 700; margin-bottom: 1.5rem; letter-spacing: -0.3px;">Sign In to NKAT AI</h2>

      <div style="text-align: left; margin-bottom: 1rem;">
        <label style="font-size: 0.78rem; color: #a1a1aa; font-weight: 600; text-transform: uppercase;">Username</label>
        <input type="text" id="modalUser" class="auth-input" value="admin" style="padding: 10px 14px; margin-top: 4px; font-size: 0.88rem; border-radius: 8px;">
      </div>

      <div style="text-align: left; margin-bottom: 1.5rem;">
        <label style="font-size: 0.78rem; color: #a1a1aa; font-weight: 600; text-transform: uppercase;">Password</label>
        <input type="password" id="modalPass" class="auth-input" value="admin_secret_2026" style="padding: 10px 14px; margin-top: 4px; font-size: 0.88rem; border-radius: 8px;">
      </div>

      <button onclick="performModalLogin()" style="width: 100%; padding: 0.75rem; background: #ffffff; color: #000000; border: none; font-weight: 700; border-radius: 8px; cursor: pointer; font-size: 0.92rem; box-shadow: 0 4px 16px rgba(255,255,255,0.25);">Sign In & Continue</button>

      <button onclick="closeLoginModal()" style="margin-top: 1rem; background: transparent; border: none; color: #a1a1aa; font-size: 0.8rem; cursor: pointer; text-decoration: underline;">Enter Console in Viewer Mode</button>
    </div>
  </div>

  <!-- Persistent Left Product Sidebar Navigation -->
  <aside class="app-sidebar">
    <div class="sidebar-brand">
      <div class="brand-logo" style="width: 44px; height: 44px; overflow: hidden; border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.3);">
        <img src="/logo.jpg" alt="NKAT AI Emblem" style="width: 100%; height: 100%; object-fit: cover;">
      </div>
      <div class="brand-info">
        <span class="brand-name">NKAT AI</span>
        <span class="brand-tag">Sentinel Console</span>
      </div>
    </div>

    <div class="sidebar-section-title">Navigation</div>
    <nav class="sidebar-nav">
      <a href="#console-top" class="nav-item active" onclick="navigateToSection('console-top', this); return false;">
        <span class="nav-icon"></span>
        <span>Operations Console</span>
      </a>
      <a href="#attack-path-section" class="nav-item" onclick="navigateToSection('attack-path-section', this); return false;">
        <span class="nav-icon"></span>
        <span>Attack Path Graph</span>
      </a>
      <a href="#ai-triage-section" class="nav-item" onclick="navigateToSection('ai-triage-section', this); return false;">
        <span class="nav-icon"></span>
        <span>AI Agent Triage</span>
      </a>
    </nav>

    <div class="sidebar-section-title">Scan History</div>
    <div style="padding: 0 0.85rem;">
      <select onchange="switchScanTarget(this.value)" style="width: 100%; background: rgba(0, 0, 0, 0.85); color: #ffffff; border: 1px solid rgba(255, 255, 255, 0.22); border-radius: 8px; padding: 8px 10px; font-size: 0.82rem; font-weight: 500; cursor: pointer; outline: none;">
        {sidebar_scan_select_options}
      </select>
    </div>

    <div class="sidebar-footer">
      <div class="tls-badge">
        <span class="status-dot"></span>
        <span>TLS 1.3 Encrypted (HTTPS:8443)</span>
      </div>
    </div>
  </aside>

  <!-- Main Workspace Area -->
  <main class="main-area">
    
    <div id="console-top" class="header-bar">
      <div>
        <h1 class="page-title">Cybersecurity Operations & Threat Triage Console</h1>
        <p class="page-sub">Local-First Autonomous Scanner & AI Multi-Vector Correlation Engine</p>
      </div>

      <!-- Surface PDF Export & AI Triage Prominently -->
      <div class="top-action-group">
        <button class="btn-export-pdf" onclick="downloadPdfReport({scan_id_val})"> Export Executive PDF</button>
        <button onclick="openLoginModal()" style="background: rgba(0,0,0,0.8); border: 1px solid #ffffff; color: #ffffff; font-weight: 700; padding: 0.6rem 1.1rem; border-radius: 8px; font-size: 0.86rem; cursor: pointer;"> Sign In</button>
      </div>
    </div>

    <!-- Loading Skeleton State -->
    <div id="skeletonLoader" class="skeleton-loader">
      Executing AI Threat Analysis & Audit Loop... Please Wait.
    </div>

    <!-- Number-First Metric Cards -->
    <div class="grid-metrics">
      <div class="metric-card">
        <div class="metric-title">Target Connection</div>
        <div class="metric-value" style="font-size: 1.1rem; color: #ffffff;">{target_url}</div>
        <div class="metric-sub">Scan #{scan_id_val} | Local Scope Authorized</div>
      </div>

      <div class="metric-card">
        <div class="metric-title">Security Posture Score</div>
        <div class="metric-value">{posture_score} <span style="font-size: 1.1rem; color: #ff4d4d;">/ 100</span></div>
        <div class="metric-sub" style="color: #ff4d4d; font-weight: 700;">Grade: {posture_grade} ({posture_level})</div>
      </div>

      <div class="metric-card">
        <div class="metric-title">Scanned Endpoints</div>
        <div class="metric-value">{endpoints_scanned}</div>
        <div class="metric-sub">Active Host Targets</div>
      </div>

      <div class="metric-card">
        <div class="metric-title">Discovered Findings</div>
        <div class="metric-value">{total_vulns}</div>
        <div class="metric-sub">0 Auto-Approved</div>
      </div>
    </div>

    <!-- Security Posture Distribution Card -->
    <div class="posture-card">
      <div class="posture-header">
        <div>
          <h2 style="color: #fff; font-size: 1.15rem; font-weight: 700;">Vulnerability Severity Distribution</h2>
          <p style="color: var(--text-secondary); font-size: 0.82rem; margin-top: 2px;">Restrained enterprise severity weighting breakdown</p>
        </div>
        <div class="posture-score-badge">
          <div class="grade-circle">{posture_grade}</div>
          <div style="display: flex; flex-direction: column;">
            <span style="font-size: 0.72rem; color: var(--text-muted); text-transform: uppercase;">Status</span>
            <span style="font-size: 0.85rem; color: #fff; font-weight: 700;">{posture_level}</span>
          </div>
        </div>
      </div>

      <div class="distribution-bar">
        <div class="bar-seg bar-critical" style="width: {pcts['CRITICAL']}%;"></div>
        <div class="bar-seg bar-high" style="width: {pcts['HIGH']}%;"></div>
        <div class="bar-seg bar-medium" style="width: {pcts['MEDIUM']}%;"></div>
        <div class="bar-seg bar-low" style="width: {pcts['LOW']}%;"></div>
      </div>

      <div class="dist-legend">
        <div class="legend-item"><span class="legend-dot" style="background: #ff4d4d;"></span> <strong>Critical:</strong> {counts['CRITICAL']} ({pcts['CRITICAL']}%)</div>
        <div class="legend-item"><span class="legend-dot" style="background: #ff944d;"></span> <strong>High:</strong> {counts['HIGH']} ({pcts['HIGH']}%)</div>
        <div class="legend-item"><span class="legend-dot" style="background: #ffcc00;"></span> <strong>Medium:</strong> {counts['MEDIUM']} ({pcts['MEDIUM']}%)</div>
        <div class="legend-item"><span class="legend-dot" style="background: #a1a1aa;"></span> <strong>Low / Info:</strong> {counts['LOW']} ({pcts['LOW']}%)</div>
      </div>
    </div>

    <!-- Advanced Attack Path & Threat Chain Graph Visualizer Panel -->
    <div id="attack-path-section" class="section-card" style="border: 1px solid rgba(255, 77, 77, 0.4); background: rgba(18, 22, 30, 0.88);">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
        <span style="color: #ff4d4d; font-weight: 700; font-size: 1rem; display: flex; align-items: center; gap: 8px;"> Attack Path & Threat Chain Graph Visualizer</span>
        <span style="background: rgba(0, 0, 0, 0.85); border: 1px solid #ff4d4d; color: #ff4d4d; padding: 4px 10px; border-radius: 12px; font-weight: 700; font-size: 0.8rem;">
          Composite Vector Score: {threat_vector_score} / 100
        </span>
      </div>

      <div>
        <div style="font-weight: 600; color: #a1a1aa; font-size: 0.8rem; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px;"> Correlated Attack Chain Chains & Exploitation Paths:</div>
        {threat_chains_html}
      </div>
    </div>

    <!-- AI Agent Triage & Stated Reasoning Trajectory Panel -->
    <div id="ai-triage-section" class="section-card" style="border: 1px solid rgba(255, 255, 255, 0.3); background: rgba(18, 22, 30, 0.88);">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
        <span style="color: #ffffff; font-weight: 700; font-size: 1rem; display: flex; align-items: center; gap: 8px;"> AI Agent Triage & Stated Reasoning Panel</span>
        <button class="btn-action btn-approve" style="background: rgba(0, 0, 0, 0.85); border: 1px solid #ffffff; color: #ffffff;" onclick="triggerAgentTriage({scan_id_val})"> Trigger AI Agent Triage</button>
      </div>

      <div style="margin-top: 10px; font-size: 0.85rem; color: #cbd5e1; line-height: 1.5;">
        <div style="background: rgba(0, 0, 0, 0.8); padding: 10px 14px; border-radius: 8px; border-left: 4px solid #ffffff; margin-bottom: 12px;">
          <strong style="color: #ffffff;"> Executive Risk Summary (summarize_risk):</strong>
          <p style="margin-top: 4px; color: #e4e4e7;">{agent_summary_text}</p>
        </div>

        <div style="font-weight: 600; color: #a1a1aa; font-size: 0.8rem; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px;"> Agent Tool Invocations & Stated Reasoning Log (Audit Log Transparency):</div>
        <div style="display: flex; flex-direction: column; gap: 6px;">
          {agent_actions_html}
        </div>
      </div>
    </div>

    <!-- Findings Stream Cards -->
    <div class="section-card">
      <div class="section-header">
        <span>Vulnerability Stream & Multi-Server Remediation Guides</span>
        <span style="font-size: 0.8rem; color: var(--text-secondary); font-weight: 500;">Card View Layout</span>
      </div>

      <div id="findingsContainer">
{findings_cards_html}
      </div>
    </div>
  </main>

  <script>
    const API_KEY = 'nkat_secret_api_key_2026';
    let jwtToken = '';

    function navigateToSection(sectionId, element) {{
      document.querySelectorAll('.sidebar-nav .nav-item').forEach(el => el.classList.remove('active'));
      if (element) {{
        element.classList.add('active');
      }}
      const target = document.getElementById(sectionId);
      if (target) {{
        target.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
      }}
    }}

    function showLoading() {{
      document.getElementById('skeletonLoader').style.display = 'block';
    }}

    function openLoginModal() {{
      document.getElementById('loginOverlay').style.display = 'flex';
    }}

    function closeLoginModal() {{
      document.getElementById('loginOverlay').style.display = 'none';
    }}

    function downloadPdfReport(scanId) {{
      window.open('/api/v1/scans/' + scanId + '/report/pdf', '_blank');
    }}

    function switchScanTarget(scanId) {{
      location.href = '?scan_id=' + scanId;
    }}

    function safeSetHtml(id, val) {{
      const el = document.getElementById(id);
      if (el) el.innerHTML = val;
    }}

    async function performModalLogin() {{
      const uEl = document.getElementById('modalUser');
      const pEl = document.getElementById('modalPass');
      if (!uEl || !pEl) return;
      const u = uEl.value;
      const p = pEl.value;
      try {{
        const res = await fetch('/api/v1/auth/login', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ username: u, password: p }})
        }});
        if (res.ok) {{
          const data = await res.json();
          jwtToken = data.access_token;
          safeSetHtml('jwtStatusPill', '<span style="color:#ffffff; font-weight:700;">Token: Active (HS256)</span>');
          closeLoginModal();
        }} else {{
          alert('Invalid login credentials.');
        }}
      }} catch (err) {{
        alert('Authentication Connection Error: ' + err);
      }}
    }}

    async function performLocalLogin() {{
      const uEl = document.getElementById('loginUser');
      const pEl = document.getElementById('loginPass');
      if (!uEl || !pEl) return;
      const u = uEl.value;
      const p = pEl.value;
      try {{
        const res = await fetch('/api/v1/auth/login', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ username: u, password: p }})
        }});
        if (res.ok) {{
          const data = await res.json();
          jwtToken = data.access_token;
          safeSetHtml('jwtStatusPill', '<span style="color:#ffffff; font-weight:700;">Token: Active (HS256)</span>');
        }} else {{
          safeSetHtml('jwtStatusPill', '<span style="color:#ff4d4d; font-weight:700;">Token: Invalid Credentials</span>');
        }}
      }} catch (err) {{
        safeSetHtml('jwtStatusPill', '<span style="color:#ff4d4d;">Auth Connection Error</span>');
      }}
    }}

    async function approveFinding(findingId) {{
      try {{
        showLoading();
        const headers = {{ 'Content-Type': 'application/json', 'X-API-Key': API_KEY }};
        if (jwtToken) headers['Authorization'] = 'Bearer ' + jwtToken;

        const res = await fetch('/api/v1/findings/' + findingId + '/approve', {{
          method: 'PATCH',
          headers: headers,
          body: JSON.stringify({{ approved_by: 'admin_dashboard' }})
        }});
        if (res.ok) {{
          location.reload();
        }} else {{
          alert('Failed to approve finding #' + findingId);
        }}
      }} catch (err) {{
        alert('Error communicating with backend API: ' + err);
      }}
    }}

    async function rejectFinding(findingId) {{
      try {{
        showLoading();
        const headers = {{ 'Content-Type': 'application/json', 'X-API-Key': API_KEY }};
        if (jwtToken) headers['Authorization'] = 'Bearer ' + jwtToken;

        const res = await fetch('/api/v1/findings/' + findingId + '/reject', {{
          method: 'PATCH',
          headers: headers,
          body: JSON.stringify({{ approved_by: 'admin_dashboard' }})
        }});
        if (res.ok) {{
          location.reload();
        }} else {{
          alert('Failed to reject finding #' + findingId);
        }}
      }} catch (err) {{
        alert('Error communicating with backend API: ' + err);
      }}
    }}

    async function restoreFinding(findingId) {{
      try {{
        showLoading();
        const headers = {{ 'Content-Type': 'application/json', 'X-API-Key': API_KEY }};
        if (jwtToken) headers['Authorization'] = 'Bearer ' + jwtToken;

        const res = await fetch('/api/v1/findings/' + findingId + '/rollback', {{
          method: 'PATCH',
          headers: headers,
          body: JSON.stringify({{ approved_by: 'admin_dashboard' }})
        }});
        if (res.ok) {{
          location.reload();
        }} else {{
          alert('Failed to restore finding #' + findingId);
        }}
      }} catch (err) {{
        alert('Error communicating with backend API: ' + err);
      }}
    }}

    async function triggerAgentTriage(scanId) {{
      try {{
        showLoading();
        const headers = {{ 'Content-Type': 'application/json', 'X-API-Key': API_KEY }};
        if (jwtToken) headers['Authorization'] = 'Bearer ' + jwtToken;

        const res = await fetch('/api/v1/scans/' + scanId + '/agent-triage', {{
          method: 'POST',
          headers: headers
        }});
        if (res.ok) {{
          location.reload();
        }} else {{
          alert('Failed to trigger AI agent triage for scan #' + scanId);
        }}
      }} catch (err) {{
        alert('Error triggering AI agent triage: ' + err);
      }}
    }}
  </script>
</body>
</html>
"""


class SecureDashboardHandler(http.server.BaseHTTPRequestHandler):
    """
    HTTP Request Handler serving dashboard content with mandatory security headers.
    """

    def _proxy_api_request(self):
        """
        Proxies /api/ requests from https://localhost:8443 directly to http://127.0.0.1:8000 backend.
        Eliminates browser Mixed Content and CORS errors completely.
        """
        import urllib.request
        import urllib.error

        try:
            backend_url = f"http://127.0.0.1:8000{self.path}"
            content_length = int(self.headers.get("Content-Length", 0))
            body_bytes = self.rfile.read(content_length) if content_length > 0 else None

            headers = {}
            for h in ("Content-Type", "X-API-Key", "Authorization", "Accept"):
                val = self.headers.get(h)
                if val:
                    headers[h] = val

            req = urllib.request.Request(
                backend_url,
                data=body_bytes,
                headers=headers,
                method=self.command
            )
            with urllib.request.urlopen(req) as resp:
                resp_data = resp.read()
                self.send_response(resp.status)
                for key, val in resp.headers.items():
                    if key.lower() not in ("content-length", "transfer-encoding", "server"):
                        self.send_header(key, val)
                self.send_header("Content-Length", str(len(resp_data)))
                self.end_headers()
                self.wfile.write(resp_data)
        except urllib.error.HTTPError as http_err:
            err_data = http_err.read()
            self.send_response(http_err.code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(err_data)))
            self.end_headers()
            self.wfile.write(err_data)
        except Exception as exc:
            err_msg = json.dumps({"error": "DashboardProxyError", "detail": str(exc)}).encode("utf-8")
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(err_msg)))
            self.end_headers()
            self.wfile.write(err_msg)

    def do_GET(self):
        try:
            parsed = urlparse(self.path)

            # Proxy API GET requests (e.g. PDF report download)
            if parsed.path.startswith("/api/"):
                self._proxy_api_request()
                return

            # Serve uploaded media files (images & videos from /uploads/ directory)
            if parsed.path.startswith("/uploads/"):
                rel_upload = parsed.path.lstrip("/").replace("/", os.sep)
                upload_file = os.path.join(PROJECT_ROOT, rel_upload)
                print(f"[+] [Media Server] Request Path: {self.path} | Resolved File: {upload_file} | Exists: {os.path.exists(upload_file)}")
                if os.path.exists(upload_file) and os.path.isfile(upload_file):
                    ext = os.path.splitext(upload_file)[1].lower()
                    content_types = {
                        ".png": "image/png",
                        ".jpg": "image/jpeg",
                        ".jpeg": "image/jpeg",
                        ".gif": "image/gif",
                        ".webp": "image/webp",
                        ".svg": "image/svg+xml",
                        ".mp4": "video/mp4",
                        ".webm": "video/webm",
                        ".mov": "video/quicktime",
                        ".m4v": "video/mp4"
                    }
                    content_type = content_types.get(ext, "application/octet-stream")
                    with open(upload_file, "rb") as f:
                        data = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Cache-Control", "public, max-age=86400")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(data)
                    return

            # Serve Mission 20 React SPA compiled assets (frontend/dist/assets/...)
            dist_dir = os.path.join(PROJECT_ROOT, "frontend", "dist")
            if parsed.path.startswith("/assets/"):
                rel_asset = parsed.path.lstrip("/").replace("/", os.sep)
                asset_file = os.path.join(dist_dir, rel_asset)
                if os.path.exists(asset_file) and os.path.isfile(asset_file):
                    content_type = "application/javascript" if asset_file.endswith(".js") else "text/css" if asset_file.endswith(".css") else "application/octet-stream"
                    with open(asset_file, "rb") as f:
                        data = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Cache-Control", "public, max-age=86400")
                    self.end_headers()
                    self.wfile.write(data)
                    return

            # Serve news image assets (from frontend/dist/news/ or frontend/public/news/)
            if parsed.path.startswith("/news/"):
                rel_news = parsed.path.lstrip("/").replace("/", os.sep)
                news_file = os.path.join(dist_dir, rel_news)
                if not os.path.exists(news_file):
                    news_file = os.path.join(PROJECT_ROOT, "frontend", "public", rel_news)
                if os.path.exists(news_file) and os.path.isfile(news_file):
                    ext = os.path.splitext(news_file)[1].lower()
                    content_type = "image/png" if ext == ".png" else "image/jpeg"
                    with open(news_file, "rb") as f:
                        data = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Cache-Control", "public, max-age=86400")
                    self.end_headers()
                    self.wfile.write(data)
                    return

            # Serve logo image static route
            if parsed.path in ("/logo.jpg", "/assets/logo.jpg"):
                logo_path = os.path.join(PROJECT_ROOT, "dashboard", "logo.jpg")
                if not os.path.exists(logo_path):
                    logo_path = os.path.join(PROJECT_ROOT, "data", "logo.jpg")
                if os.path.exists(logo_path):
                    with open(logo_path, "rb") as img_file:
                        img_data = img_file.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "image/jpeg")
                    self.send_header("Content-Length", str(len(img_data)))
                    self.send_header("Cache-Control", "public, max-age=86400")
                    self.end_headers()
                    self.wfile.write(img_data)
                    return

            # Serve background image static route
            if parsed.path in ("/bg.jpg", "/assets/bg.jpg"):
                bg_path = os.path.join(PROJECT_ROOT, "dashboard", "bg.jpg")
                if not os.path.exists(bg_path):
                    bg_path = os.path.join(PROJECT_ROOT, "data", "bg.jpg")
                if os.path.exists(bg_path):
                    with open(bg_path, "rb") as img_file:
                        img_data = img_file.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "image/jpeg")
                    self.send_header("Content-Length", str(len(img_data)))
                    self.send_header("Cache-Control", "public, max-age=86400")
                    self.end_headers()
                    self.wfile.write(img_data)
                    return

            query = parse_qs(parsed.query)

            # Serve Mission 20 React Frontend SPA (frontend/dist/index.html)
            react_index = os.path.join(dist_dir, "index.html")
            if os.path.exists(react_index) and "legacy" not in query:
                with open(react_index, "rb") as f:
                    html_bytes = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html_bytes)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("X-XSS-Protection", "1; mode=block")
                self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
                self.end_headers()
                self.wfile.write(html_bytes)
                return

            scan_id_val = None
            if "scan_id" in query and query["scan_id"]:
                try:
                    scan_id_val = int(query["scan_id"][0])
                except ValueError:
                    pass

            html_content = render_dashboard_html(selected_scan_id=scan_id_val)

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html_content.encode("utf-8"))))

            # Mandatory Security Headers
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-XSS-Protection", "1; mode=block")
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self' https:; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:;"
            )
            self.end_headers()

            self.wfile.write(html_content.encode("utf-8"))
        except Exception as exc:
            sys.stderr.write(f"[!] Error handling dashboard request: {exc}\n")
            self.send_error(500, f"Internal Dashboard Server Error: {exc}")

    def do_POST(self):
        if self.path.startswith("/api/"):
            self._proxy_api_request()
        else:
            self.send_error(404, "Not Found")

    def do_PATCH(self):
        if self.path.startswith("/api/"):
            self._proxy_api_request()
        else:
            self.send_error(404, "Not Found")

    def do_DELETE(self):
        if self.path.startswith("/api/"):
            self._proxy_api_request()
        else:
            self.send_error(404, "Not Found")

    def do_OPTIONS(self):
        if self.path.startswith("/api/"):
            self._proxy_api_request()
        else:
            self.send_response(200)
            self.end_headers()

    def log_message(self, format, *args):
        """Suppress noisy HTTP server access log outputs."""
        pass


def run_dashboard_server(port: int = 8443, cert_file: str = "certs/cert.pem", key_file: str = "certs/key.pem"):
    """
    Starts the TLS/SSL encrypted HTTPS Dashboard Web Application Server on localhost:8443.
    """
    if not (os.path.exists(cert_file) and os.path.exists(key_file)):
        sys.stdout.write("[*] Generating self-signed SSL/TLS certificate pair...\n")
        generate_self_signed_cert(cert_file, key_file)

    server_address = ("127.0.0.1", port)
    httpd = http.server.HTTPServer(server_address, SecureDashboardHandler)

    # Wrap socket with TLS 1.3/1.2 SSLContext
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    sys.stdout.write(f"\n[+] NKAT Enterprise Threat Sentinel Console running at: https://127.0.0.1:{port}/\n")
    sys.stdout.write("[+] Security Enforcement: TLS 1.3 Active | HSTS Enabled | CSP Active\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.stdout.write("\n[*] Dashboard server shutting down cleanly.\n")
        httpd.server_close()


if __name__ == "__main__":
    run_dashboard_server()
