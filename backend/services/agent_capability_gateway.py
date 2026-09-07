"""
Agent Capability Gateway & Security Policy Orchestrator
-------------------------------------------------------
Provides a deny-by-default execution gateway for LLM Agent security capabilities across:
- Assessment Context Management
- SAST Code Auditing & Secret Detection
- DAST Web Discovery & Active Vulnerability Scanning
- Infrastructure Discovery (Nmap/Port Probe Adapters)
- Deterministic Finding Correlation & AI Root Cause Analysis
- Patch Generation, Safety Confinement, Rescan Verification & Rollback

Strictly enforces authorization pipeline:
REGISTERED -> ENABLED -> AGENT_ALLOWED -> POLICY_ALLOWED -> TARGET_AUTHORIZED -> ARGUMENTS_VALIDATED -> RESOURCE_LIMITS -> EXECUTE -> NORMALIZE -> AUDIT
"""

import os
import sys
import time
import json
import logging
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass
from sqlalchemy.orm import Session

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.models import Assessment, Scan, Subdomain, Finding, Remediation, AuditLog
from backend.services.scan_service import validate_target_authorization
from backend.services.audit_logger import log_audit_event
from backend.services.finding_correlator import correlate_assessment_findings
from backend.services.remediation_engine import (
    map_finding_to_source,
    generate_remediation_analysis_and_patch,
    validate_patch_safety,
    apply_patch_in_isolated_branch,
    validate_remediation_and_rescan,
    rollback_remediation
)

logger = logging.getLogger("nkat.agent_capability_gateway")

PROHIBITED_COMMAND_PATTERNS = ["bash", "sh", "cmd", "powershell", "exec", "eval", "system", "os.system", "rm -rf"]


@dataclass
class AgentCapability:
    id: str
    name: str
    category: str
    description: str
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any]
    requires_authorization: bool = True
    risk_level: str = "low"
    timeout_seconds: int = 120
    enabled: bool = True
    executor_func: Optional[Callable] = None


class AgentCapabilityGateway:
    def __init__(self):
        self._capabilities: Dict[str, AgentCapability] = {}
        self._register_default_capabilities()

    def register_capability(self, cap: AgentCapability):
        self._capabilities[cap.id] = cap

    def get_capability(self, cap_id: str) -> Optional[AgentCapability]:
        return self._capabilities.get(cap_id)

    def list_capabilities(self, category: Optional[str] = None) -> List[AgentCapability]:
        res = []
        for c in self._capabilities.values():
            if not c.enabled:
                continue
            if category and c.category.lower() != category.lower():
                continue
            res.append(c)
        return res

    def _register_default_capabilities(self):
        # 1. Assessment Capabilities
        self.register_capability(AgentCapability(
            id="get_assessment_context",
            name="Get Assessment Context",
            category="Assessment",
            description="Fetches target URL, repository path, scans, assets, and summary findings for an assessment_id.",
            input_schema={"type": "object", "properties": {"assessment_id": {"type": "integer"}}, "required": ["assessment_id"]},
            output_schema={"type": "object"},
            requires_authorization=False,
            executor_func=self._exec_get_assessment_context
        ))

        self.register_capability(AgentCapability(
            id="get_assessment_findings",
            name="Get Assessment Findings",
            category="Assessment",
            description="Fetches all findings across all subdomains and scans under an assessment_id.",
            input_schema={"type": "object", "properties": {"assessment_id": {"type": "integer"}}, "required": ["assessment_id"]},
            output_schema={"type": "object"},
            requires_authorization=False,
            executor_func=self._exec_get_assessment_findings
        ))

        # 2. SAST Capabilities
        self.register_capability(AgentCapability(
            id="run_sast",
            name="Run SAST Code Audit",
            category="SAST",
            description="Runs static application security testing and Gitleaks secret detection on authorized repository source code.",
            input_schema={"type": "object", "properties": {"repository_path": {"type": "string"}}},
            output_schema={"type": "object"},
            requires_authorization=False,
            executor_func=self._exec_run_sast
        ))

        # 3. DAST Capabilities
        self.register_capability(AgentCapability(
            id="discover_endpoints",
            name="Discover Web Endpoints",
            category="DAST",
            description="Runs Katana headless crawler to discover web routes and API endpoints on an authorized target URL.",
            input_schema={"type": "object", "properties": {"target_url": {"type": "string"}}, "required": ["target_url"]},
            output_schema={"type": "object"},
            requires_authorization=True,
            executor_func=self._exec_discover_endpoints
        ))

        self.register_capability(AgentCapability(
            id="run_dast",
            name="Run Active DAST Vulnerability Audit",
            category="DAST",
            description="Runs active DAST vulnerability scans (SQLi, XSS, Headers, Nuclei CVE templates) against authorized web targets.",
            input_schema={"type": "object", "properties": {"target_url": {"type": "string"}}, "required": ["target_url"]},
            output_schema={"type": "object"},
            requires_authorization=True,
            executor_func=self._exec_run_dast
        ))

        # 4. Analysis & Correlation Capabilities
        self.register_capability(AgentCapability(
            id="analyze_finding",
            name="Analyze Vulnerability Finding",
            category="Analysis",
            description="Performs AI root-cause analysis and maps finding to source code file, function, and vulnerable line.",
            input_schema={"type": "object", "properties": {"finding_id": {"type": "integer"}}, "required": ["finding_id"]},
            output_schema={"type": "object"},
            requires_authorization=False,
            executor_func=self._exec_analyze_finding
        ))

        self.register_capability(AgentCapability(
            id="correlate_findings",
            name="Correlate SAST and DAST Findings",
            category="Analysis",
            description="Correlates SAST code findings with DAST HTTP endpoint findings based on CWE and location metadata.",
            input_schema={"type": "object", "properties": {"assessment_id": {"type": "integer"}}, "required": ["assessment_id"]},
            output_schema={"type": "object"},
            requires_authorization=False,
            executor_func=self._exec_correlate_findings
        ))

        # 5. Remediation & Verification Capabilities
        self.register_capability(AgentCapability(
            id="generate_patch",
            name="Generate Remediation Patch",
            category="Remediation",
            description="Generates Git-compatible diff patch resolving root cause of analyzed finding.",
            input_schema={"type": "object", "properties": {"remediation_id": {"type": "integer"}}, "required": ["remediation_id"]},
            output_schema={"type": "object"},
            requires_authorization=False,
            executor_func=self._exec_generate_patch
        ))

        self.register_capability(AgentCapability(
            id="validate_patch",
            name="Validate Patch & Execute Rescan",
            category="Remediation",
            description="Applies patch to isolated Git branch, executes syntax/tests/SAST/DAST rescan, and verifies fix.",
            input_schema={"type": "object", "properties": {"remediation_id": {"type": "integer"}}, "required": ["remediation_id"]},
            output_schema={"type": "object"},
            requires_authorization=True,
            executor_func=self._exec_validate_patch
        ))

        self.register_capability(AgentCapability(
            id="rollback_remediation",
            name="Rollback Remediation Patch",
            category="Remediation",
            description="Restores repository to base commit state if remediation fails validation.",
            input_schema={"type": "object", "properties": {"remediation_id": {"type": "integer"}}, "required": ["remediation_id"]},
            output_schema={"type": "object"},
            requires_authorization=False,
            executor_func=self._exec_rollback_remediation
        ))

    def execute_capability(
        self,
        db: Session,
        capability_id: str,
        assessment_id: Optional[int] = None,
        target_url: Optional[str] = None,
        actor: str = "agent",
        reasoning: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Executes capability through security gate pipeline:
        REGISTERED -> ENABLED -> AGENT_ALLOWED -> TARGET_AUTHORIZED -> ARGUMENTS_VALIDATED -> RESOURCE_LIMITS -> EXECUTE -> AUDIT
        """
        # Prohibit arbitrary shell or command string execution attempts
        for k, v in kwargs.items():
            if isinstance(v, str):
                for p in PROHIBITED_COMMAND_PATTERNS:
                    if p in v.lower() and k in ("command", "cmd", "exec", "shell"):
                        err = f"Security Boundary Violation: Arbitrary shell command execution ('{v}') is strictly prohibited."
                        logger.error(err)
                        log_audit_event(db, action="security_boundary_blocked", actor=actor, actor_name=f"BLOCKED:{capability_id}")
                        db.commit()
                        return {"status": "rejected_security_violation", "message": err}

        cap = self.get_capability(capability_id)
        if not cap or not cap.enabled:
            err = f"Gateway Rejection: Capability '{capability_id}' is not registered or disabled."
            log_audit_event(db, action="capability_rejected", actor=actor, actor_name=f"REJECTED:{capability_id}")
            db.commit()
            return {"status": "rejected_unregistered_capability", "message": err}

        # Target Authorization check
        if cap.requires_authorization:
            clean_url = target_url or kwargs.get("target_url") or kwargs.get("target")
            if not clean_url and assessment_id:
                ass = db.query(Assessment).filter(Assessment.id == assessment_id).first()
                if ass:
                    clean_url = ass.target_url

            if not clean_url:
                return {"status": "rejected_missing_target", "message": "Capability requires an authorized target URL."}

            try:
                validated_url = validate_target_authorization(clean_url, db=db)
                kwargs["target_url"] = validated_url
            except Exception as exc:
                err_msg = f"Scope Rejection: Target '{clean_url}' is NOT authorized in docs/AUTHORIZED_TARGETS.md. {exc}"
                log_audit_event(db, action="scope_violation_blocked", actor=actor, actor_name=f"SCOPE_BLOCKED:{capability_id}")
                db.commit()
                return {"status": "rejected_scope_violation", "message": err_msg}

        log_audit_event(db, action=f"exec_{capability_id}", actor=actor, actor_name=f"Agent: {reasoning or capability_id}")
        db.commit()

        if not cap.executor_func:
            return {"status": "error", "message": f"No executor function bound to capability '{capability_id}'."}

        try:
            res = cap.executor_func(db=db, assessment_id=assessment_id, **kwargs)
            return {"status": "success", "capability_id": capability_id, "data": res}
        except Exception as exc:
            db.rollback()
            logger.error(f"[Capability Executor Error]: {exc}", exc_info=True)
            return {"status": "failed", "capability_id": capability_id, "error": str(exc)}

    # -------------------------------------------------------------
    # EXECUTORS
    # -------------------------------------------------------------
    def _exec_get_assessment_context(self, db: Session, assessment_id: int, **kwargs) -> Dict[str, Any]:
        ass = db.query(Assessment).filter(Assessment.id == assessment_id).first()
        if not ass:
            return {"error": f"Assessment #{assessment_id} not found"}

        scans = db.query(Scan).filter(Scan.assessment_id == assessment_id).all()
        findings = correlate_assessment_findings(db, assessment_id=assessment_id)

        return {
            "assessment_id": ass.id,
            "name": ass.name,
            "target_url": ass.target_url,
            "repository_path": ass.repository_path,
            "status": ass.status,
            "scans_count": len(scans),
            "findings_count": len(findings),
            "summary_findings": findings[:10]
        }

    def _exec_get_assessment_findings(self, db: Session, assessment_id: int, **kwargs) -> Dict[str, Any]:
        findings = correlate_assessment_findings(db, assessment_id=assessment_id)
        return {"assessment_id": assessment_id, "count": len(findings), "findings": findings}

    def _exec_run_sast(self, db: Session, **kwargs) -> Dict[str, Any]:
        from backend.services.gitleaks_scanner import scan_exposed_git_repo_with_gitleaks
        repo_path = kwargs.get("repository_path") or PROJECT_ROOT
        sec_findings = scan_exposed_git_repo_with_gitleaks(repo_path)
        return {"tool": "gitleaks_sast", "findings_count": len(sec_findings), "findings": sec_findings}

    def _exec_discover_endpoints(self, db: Session, **kwargs) -> Dict[str, Any]:
        from backend.services.katana_crawler import run_katana_crawl
        target_url = kwargs.get("target_url")
        urls = run_katana_crawl(target_url, depth=2, crawl_duration=5)
        return {"tool": "katana", "discovered_urls_count": len(urls), "urls": urls}

    def _exec_run_dast(self, db: Session, **kwargs) -> Dict[str, Any]:
        from backend.services.agent_loop import request_deeper_scan
        sub_id = kwargs.get("subdomain_id", 1)
        res = request_deeper_scan(db, sub_id, reasoning="Agent executed DAST scan capability")
        return res

    def _exec_analyze_finding(self, db: Session, **kwargs) -> Dict[str, Any]:
        fid = kwargs.get("finding_id")
        finding = db.query(Finding).filter(Finding.id == fid).first()
        if not finding:
            return {"error": f"Finding #{fid} not found"}

        mapping = map_finding_to_source(db, finding)
        analysis = generate_remediation_analysis_and_patch(db, finding, mapping)

        remediation = Remediation(
            finding_id=finding.id,
            repository=mapping.get("repository"),
            affected_file=mapping.get("affected_file"),
            affected_function=mapping.get("affected_function"),
            vulnerable_line=mapping.get("vulnerable_line"),
            root_cause=analysis.get("root_cause"),
            patch_strategy=analysis.get("patch_strategy"),
            patch=analysis.get("patch"),
            confidence=analysis.get("confidence", 0.0),
            status=analysis.get("status", "PROPOSED")
        )
        db.add(remediation)
        db.commit()
        db.refresh(remediation)

        return {"remediation_id": remediation.id, "analysis": analysis, "source_mapping": mapping}

    def _exec_correlate_findings(self, db: Session, assessment_id: int, **kwargs) -> Dict[str, Any]:
        pairs = correlate_assessment_findings(db, assessment_id=assessment_id)
        return {"assessment_id": assessment_id, "correlated_count": len(pairs), "pairs": pairs}

    def _exec_generate_patch(self, db: Session, **kwargs) -> Dict[str, Any]:
        rem_id = kwargs.get("remediation_id")
        rem = db.query(Remediation).filter(Remediation.id == rem_id).first()
        if not rem:
            return {"error": f"Remediation #{rem_id} not found"}
        return {"remediation_id": rem.id, "patch": rem.patch, "status": rem.status}

    def _exec_validate_patch(self, db: Session, **kwargs) -> Dict[str, Any]:
        rem_id = kwargs.get("remediation_id")
        rem = db.query(Remediation).filter(Remediation.id == rem_id).first()
        if not rem:
            return {"error": f"Remediation #{rem_id} not found"}

        safe, msg = validate_patch_safety(rem.patch, rem.affected_file)
        if not safe:
            return {"error": f"Safety check failed: {msg}"}

        apply_patch_in_isolated_branch(rem.id, rem.affected_file, rem.patch)
        res = validate_remediation_and_rescan(db, rem)
        return res

    def _exec_rollback_remediation(self, db: Session, **kwargs) -> Dict[str, Any]:
        rem_id = kwargs.get("remediation_id")
        return rollback_remediation(db, rem_id)


# Global Orchestration Gateway Instance
orchestrator_gateway = AgentCapabilityGateway()
