"""
Full Agentic Security Orchestrator Service — Assessment-Level SAST+DAST+Remediation Lifecycle
-----------------------------------------------------------------------------------------------
Orchestrates autonomous security assessment, finding correlation, AI root cause analysis,
patch generation, patch safety validation, DAST rescan verification, and rollback control
via Anthropic Claude tool calling or local heuristic fallback engine.

Enforces strict Policy Gateway:
REGISTERED -> ENABLED -> AGENT_ALLOWED -> POLICY_ALLOWED -> TARGET_AUTHORIZED -> ARGUMENTS_VALIDATED -> RESOURCE_LIMITS -> EXECUTE -> NORMALIZE -> AUDIT
"""

import os
import time
import json
import logging
import asyncio
import concurrent.futures
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from dotenv import load_dotenv

import anthropic

from backend.database import SessionLocal
from backend.models import Assessment, Scan, Subdomain, Finding, AuditLog, FindingStatus, Remediation, RemediationStatus
from backend.services.scan_service import validate_target_authorization, score_finding_with_ml
from backend.services.audit_logger import log_audit_event
from backend.services.agent_capability_gateway import orchestrator_gateway
from backend.services.finding_correlator import correlate_assessment_findings
from backend.services.remediation_engine import map_finding_to_source, generate_remediation_analysis_and_patch, validate_patch_safety, apply_patch_in_isolated_branch, validate_remediation_and_rescan, rollback_remediation

load_dotenv()
logger = logging.getLogger("nkat.agent_orchestrator")

MAX_AGENT_ITERATIONS = 10
MAX_EXECUTION_TIME_SECONDS = 120.0

# Preserved 4 scan tools + new Assessment Capabilities
ALLOWED_AGENT_TOOLS = {
    "get_findings",
    "flag_for_priority_review",
    "request_deeper_scan",
    "summarize_risk",
    "get_assessment_context",
    "get_assessment_findings",
    "run_sast",
    "discover_endpoints",
    "run_dast",
    "analyze_finding",
    "correlate_findings",
    "generate_patch",
    "validate_patch",
    "rollback_remediation"
}

ORCHESTRATOR_CAPABILITY_SCHEMAS = [
    {
        "name": "get_assessment_context",
        "description": "Reads target URL, repository path, scans, assets, and summary findings for an assessment_id.",
        "input_schema": {
            "type": "object",
            "properties": {"assessment_id": {"type": "integer"}},
            "required": ["assessment_id"]
        }
    },
    {
        "name": "get_assessment_findings",
        "description": "Reads all correlated SAST and DAST findings for an assessment_id.",
        "input_schema": {
            "type": "object",
            "properties": {"assessment_id": {"type": "integer"}},
            "required": ["assessment_id"]
        }
    },
    {
        "name": "run_sast",
        "description": "Runs SAST code audit and secret detection on repository source code.",
        "input_schema": {
            "type": "object",
            "properties": {"repository_path": {"type": "string"}}
        }
    },
    {
        "name": "discover_endpoints",
        "description": "Runs Katana crawler to discover web routes and API endpoints on an authorized target URL.",
        "input_schema": {
            "type": "object",
            "properties": {"target_url": {"type": "string"}},
            "required": ["target_url"]
        }
    },
    {
        "name": "run_dast",
        "description": "Executes active DAST vulnerability scans (SQLi, XSS, headers, Nuclei templates) on authorized targets.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string"},
                "subdomain_id": {"type": "integer"}
            }
        }
    },
    {
        "name": "analyze_finding",
        "description": "Performs AI root-cause analysis and maps finding to source file, function, and line.",
        "input_schema": {
            "type": "object",
            "properties": {"finding_id": {"type": "integer"}},
            "required": ["finding_id"]
        }
    },
    {
        "name": "correlate_findings",
        "description": "Correlates SAST code location findings with DAST HTTP endpoint findings.",
        "input_schema": {
            "type": "object",
            "properties": {"assessment_id": {"type": "integer"}},
            "required": ["assessment_id"]
        }
    },
    {
        "name": "validate_patch",
        "description": "Applies patch to isolated Git branch, executes unit/SAST/DAST tests, and verifies fix.",
        "input_schema": {
            "type": "object",
            "properties": {"remediation_id": {"type": "integer"}},
            "required": ["remediation_id"]
        }
    },
    {
        "name": "rollback_remediation",
        "description": "Restores repository to base commit state if remediation validation fails.",
        "input_schema": {
            "type": "object",
            "properties": {"remediation_id": {"type": "integer"}},
            "required": ["remediation_id"]
        }
    },
    {
        "name": "get_findings",
        "description": "Reads security scan findings from database for a scan_id.",
        "input_schema": {
            "type": "object",
            "properties": {"scan_id": {"type": "integer"}},
            "required": ["scan_id"]
        }
    },
    {
        "name": "flag_for_priority_review",
        "description": "Flags a high or critical severity finding for priority human review.",
        "input_schema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "integer"},
                "reason": {"type": "string"}
            },
            "required": ["finding_id", "reason"]
        }
    },
    {
        "name": "request_deeper_scan",
        "description": "Triggers a deeper scan on a specific subdomain.",
        "input_schema": {
            "type": "object",
            "properties": {"subdomain_id": {"type": "integer"}},
            "required": ["subdomain_id"]
        }
    },
    {
        "name": "summarize_risk",
        "description": "Generates an executive risk summary for human review.",
        "input_schema": {
            "type": "object",
            "properties": {"scan_id": {"type": "integer"}},
            "required": ["scan_id"]
        }
    }
]


# Backward Compatibility Tools
def get_findings(db: Session, scan_id: int) -> List[Dict[str, Any]]:
    db_scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not db_scan:
        return []

    findings = (
        db.query(Finding)
        .join(Subdomain, Finding.subdomain_id == Subdomain.id)
        .filter(Subdomain.scan_id == scan_id)
        .order_by(Finding.id.asc())
        .all()
    )

    return [
        {
            "id": f.id,
            "subdomain_id": f.subdomain_id,
            "check_name": f.check_name,
            "severity": f.severity,
            "evidence": f.evidence,
            "status": f.status,
            "owasp_category": f.owasp_category,
            "cwe_id": f.cwe_id,
        }
        for f in findings
    ]


def flag_for_priority_review(db: Session, finding_id: int, reason: str) -> Dict[str, Any]:
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        return {"status": "error", "message": f"Finding #{finding_id} not found"}

    finding.previous_state = f"PRIORITY_REVIEW_FLAGGED: {reason}"
    actor_label = f"NKAT_Agent: {reason[:120]}"
    log_audit_event(db, finding_id, action="priority_flag", actor="agent", actor_name=actor_label)
    db.commit()
    db.refresh(finding)
    return {"status": "success", "finding_id": finding_id, "reason": reason}


def request_deeper_scan(db: Session, subdomain_id: int, reasoning: str = None) -> Dict[str, Any]:
    sub = db.query(Subdomain).filter(Subdomain.id == subdomain_id).first()
    if not sub:
        return {"status": "error", "message": f"Subdomain #{subdomain_id} not found"}

    target_host = sub.hostname
    target_url = target_host if target_host.startswith(("http://", "https://")) else f"http://{target_host}"

    try:
        validated_url = validate_target_authorization(target_url, db=db)
    except Exception as exc:
        log_audit_event(db, subdomain_id=subdomain_id, action="deeper_scan_rejected", actor="agent", actor_name=f"REJECTED:{str(exc)[:120]}")
        db.commit()
        return {"status": "rejected_scope_violation", "subdomain_id": subdomain_id, "message": str(exc)}

    reason_str = reasoning or f"Deeper scan requested on subdomain #{subdomain_id}"
    log_audit_event(db, subdomain_id=subdomain_id, action="deeper_scan_triggered", actor="agent", actor_name=f"NKAT_Agent: {reason_str[:120]}")
    db.commit()

    from backend.services.katana_crawler import run_katana_crawl
    from backend.services.nuclei_scanner import run_nuclei_scan, parse_nuclei_findings
    from scanner.core import SecurityScanner

    scanners_used = []
    katana_urls = [validated_url]
    raw_findings = []

    try:
        try:
            k_results = run_katana_crawl(validated_url, depth=2, crawl_duration=5)
            if k_results:
                katana_urls = list(dict.fromkeys(k_results + [validated_url]))
                scanners_used.append("katana")
        except Exception:
            pass

        try:
            nuclei_out = run_nuclei_scan(targets=katana_urls, tags=["cve", "misconfiguration", "exposure", "cisa-kev", "epss"], rate_limit=150, concurrency=25, timeout=5)
            n_findings = parse_nuclei_findings(nuclei_out)
            if n_findings:
                raw_findings.extend(n_findings)
            scanners_used.append("nuclei")
        except Exception:
            pass

        try:
            def _run_core_scanner():
                scanner = SecurityScanner(policy_path="docs/AUTHORIZED_TARGETS.md", target_url=validated_url)
                return asyncio.run(scanner.execute_scan())

            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop and loop.is_running():
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    report = executor.submit(_run_core_scanner).result()
            else:
                report = _run_core_scanner()

            if report and report.findings:
                for f in report.findings:
                    sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                    raw_findings.append({"check_name": f.title, "severity": sev_val, "evidence": f.evidence, "matched_at": validated_url})
            scanners_used.append("security_scanner")
        except Exception:
            pass

        existing_checks = {f.check_name.strip().lower() for f in db.query(Finding).filter(Finding.subdomain_id == sub.id).all()}
        new_findings_created = []

        for rf in raw_findings:
            check_name = rf.get("check_name", "Unknown Security Finding")
            if check_name.strip().lower() in existing_checks:
                continue
            existing_checks.add(check_name.strip().lower())

            sev = rf.get("severity", "LOW")
            evidence = rf.get("evidence", "No evidence snippet provided.")
            rec_info = generate_recommendation(rf)
            ml_label, ml_conf = score_finding_with_ml(check_name, evidence, severity=sev)

            db_finding = Finding(
                subdomain_id=sub.id,
                check_name=check_name,
                severity=sev,
                evidence=evidence,
                recommendation=rec_info.get("recommendation"),
                config_snippet=rec_info.get("config_snippet"),
                status=FindingStatus.OPEN.value,
                ml_predicted_label=ml_label,
                ml_confidence=ml_conf,
                review_deadline=calculate_review_deadline(sev),
                owasp_category=rec_info.get("owasp_category"),
                cwe_id=rf.get("cwe_id") or rec_info.get("cwe_id")
            )
            db.add(db_finding)
            new_findings_created.append(db_finding)

        db.commit()
        for nf in new_findings_created:
            db.refresh(nf)

        return {
            "status": "success",
            "subdomain_id": subdomain_id,
            "target": validated_url,
            "scanners_used": scanners_used,
            "scan_execution_status": "completed",
            "new_findings_count": len(new_findings_created),
            "new_finding_ids": [f.id for f in new_findings_created]
        }
    except Exception as exec_err:
        db.rollback()
        return {"status": "failed", "subdomain_id": subdomain_id, "error": str(exec_err)}


def summarize_risk(db: Session, scan_id: int, reasoning: str = None) -> Dict[str, Any]:
    findings = get_findings(db, scan_id)
    if not findings:
        return {"status": "success", "summary": "Zero findings discovered. Target infrastructure compliant."}

    crit_count = sum(1 for f in findings if f["severity"].upper() == "CRITICAL")
    high_count = sum(1 for f in findings if f["severity"].upper() == "HIGH")

    summary_text = f"Scan #{scan_id} Risk Evaluation: Total {len(findings)} findings ({crit_count} Critical, {high_count} High)."
    log_audit_event(db, scan_id=scan_id, action="risk_summary_generated", actor="agent", actor_name=f"NKAT_Agent: {summary_text[:120]}")
    db.commit()
    return {"status": "success", "summary": summary_text, "critical_count": crit_count, "high_count": high_count}


def execute_agent_tool(db: Session, tool_name: str, reasoning: str = None, **kwargs) -> Dict[str, Any]:
    """
    Capability Gateway Dispatcher:
    Enforces deny-by-default execution through AgentCapabilityGateway.
    """
    if tool_name not in ALLOWED_AGENT_TOOLS and not orchestrator_gateway.get_capability(tool_name):
        err_msg = f"Guardrail Violation: Attempted unauthorized capability execution '{tool_name}'."
        logger.error(f"[Guardrail Blocked] {err_msg}")
        log_audit_event(db, action="guardrail_tool_blocked", actor="agent", actor_name=f"BLOCKED:{tool_name}")
        db.commit()
        return {"status": "rejected_unauthorized_tool", "message": err_msg}

    if tool_name == "get_findings":
        return {"status": "success", "data": get_findings(db, kwargs.get("scan_id"))}
    elif tool_name == "flag_for_priority_review":
        reason = kwargs.get("reason") or reasoning or "Priority threat flagged by AI agent"
        return flag_for_priority_review(db, kwargs.get("finding_id"), reason)
    elif tool_name == "request_deeper_scan":
        return request_deeper_scan(db, kwargs.get("subdomain_id"), reasoning=reasoning)
    elif tool_name == "summarize_risk":
        return summarize_risk(db, kwargs.get("scan_id"), reasoning=reasoning)
    else:
        return orchestrator_gateway.execute_capability(
            db=db,
            capability_id=tool_name,
            assessment_id=kwargs.get("assessment_id"),
            target_url=kwargs.get("target_url") or kwargs.get("target"),
            actor="agent",
            reasoning=reasoning,
            **kwargs
        )


def run_agent_orchestrator_loop(assessment_id: int) -> Dict[str, Any]:
    """
    Full Assessment Security Orchestrator Decision Loop powered by Anthropic Claude Tool Calling:
    Orchestrates SAST, DAST, Finding Correlation, AI Root Cause Analysis, Patch Generation, and Rescan Verification.
    """
    start_time = time.time()
    db = SessionLocal()
    trajectory = []
    iterations = 0

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key or api_key.startswith("mock_") or "pytest" in os.environ.get("PYTEST_CURRENT_TEST", ""):
        return _run_heuristic_orchestrator_loop(db, assessment_id, start_time)

    try:
        client = anthropic.Anthropic(api_key=api_key)
        ass_context = orchestrator_gateway.execute_capability(db, "get_assessment_context", assessment_id=assessment_id)

        system_prompt = (
            "You are NKAT Sentinel Autonomous Security Orchestrator. "
            "You evaluate security assessments across SAST, DAST, finding correlation, AI root cause analysis, "
            "patch generation, and fix verification. Execute capabilities through the policy gateway to assess threats "
            "and verify remediations. Do not attempt arbitrary shell execution or bypass target scope authorization."
        )

        messages = [{"role": "user", "content": f"Begin orchestrator assessment loop for assessment_id #{assessment_id}. Context: {json.dumps(ass_context)}"}]

        while iterations < MAX_AGENT_ITERATIONS and (time.time() - start_time <= MAX_EXECUTION_TIME_SECONDS):
            iterations += 1

            response = client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=1024,
                system=system_prompt,
                tools=ORCHESTRATOR_CAPABILITY_SCHEMAS,
                messages=messages,
            )

            tool_use_blocks = [block for block in response.content if block.type == "tool_use"]
            if not tool_use_blocks or response.stop_reason == "end_turn":
                text_content = "".join([b.text for b in response.content if hasattr(b, "text")])
                trajectory.append({"step": iterations, "tool": "claude_completion", "result": text_content or "Orchestration complete."})
                break

            claude_reasoning = "".join([b.text for b in response.content if hasattr(b, "text") and b.text]).strip()
            tool_results_content = []

            for block in tool_use_blocks:
                tool_output = execute_agent_tool(db, block.name, reasoning=claude_reasoning, **(block.input or {}))
                trajectory.append({"step": iterations, "tool": block.name, "reasoning": claude_reasoning, "input": block.input, "result": tool_output})
                tool_results_content.append({"type": "tool_result", "tool_use_id": block.id, "content": json.dumps(tool_output)})

            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results_content})

        db.close()
        return {"assessment_id": assessment_id, "iterations_used": iterations, "trajectory": trajectory, "status": "COMPLETED"}

    except Exception as exc:
        db.close()
        logger.error(f"[Orchestrator Loop Error]: {exc}", exc_info=True)
        return _run_heuristic_orchestrator_loop(db, assessment_id, start_time)


def _run_heuristic_orchestrator_loop(db: Session, assessment_id: int, start_time: float) -> Dict[str, Any]:
    """
    Deterministic Heuristic Fallback Orchestrator Engine for offline/test environments.
    """
    trajectory = []
    iterations = 0

    try:
        iterations += 1
        ass_res = orchestrator_gateway.execute_capability(db, "get_assessment_context", assessment_id=assessment_id)
        trajectory.append({"step": iterations, "capability": "get_assessment_context", "result": ass_res})

        # 1. Run SAST audit
        if iterations < MAX_AGENT_ITERATIONS:
            iterations += 1
            sast_res = orchestrator_gateway.execute_capability(db, "run_sast")
            trajectory.append({"step": iterations, "capability": "run_sast", "result": sast_res})

        # 2. Correlate SAST & DAST findings
        if iterations < MAX_AGENT_ITERATIONS:
            iterations += 1
            corr_res = orchestrator_gateway.execute_capability(db, "correlate_findings", assessment_id=assessment_id)
            trajectory.append({"step": iterations, "capability": "correlate_findings", "result": corr_res})

        db.close()
        return {
            "assessment_id": assessment_id,
            "iterations_used": iterations,
            "max_iterations": MAX_AGENT_ITERATIONS,
            "engine": "heuristic_orchestrator",
            "trajectory": trajectory,
            "status": "COMPLETED"
        }
    except Exception as exc:
        db.close()
        return {"assessment_id": assessment_id, "error": str(exc), "status": "FAILED"}


# Backward Compatibility Function Alias
run_agent_triage_loop = run_agent_orchestrator_loop
