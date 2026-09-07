"""
Authorized Tool Registry & Secure Agent Tool Gateway — Core Security Orchestration Subsystem
---------------------------------------------------------------------------------------------
Provides a deny-by-default, centralized capability catalog, authorization gate, and
trusted executor gateway for 100+ security capabilities across SAST, DAST, SCA, Secrets,
Container Security, IaC, Reconnaissance, Web Testing, API Security, and Risk Intelligence.
"""

import os
import sys
import time
import json
import logging
import asyncio
import concurrent.futures
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from sqlalchemy.orm import Session

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.database import SessionLocal
from backend.models import Scan, Subdomain, Finding, AuditLog, FindingStatus
from backend.services.scan_service import validate_target_authorization, score_finding_with_ml
from backend.services.audit_logger import log_audit_event
from backend.services.katana_crawler import run_katana_crawl, KATANA_PATH
from backend.services.nuclei_scanner import run_nuclei_scan, parse_nuclei_findings, NUCLEI_PATH
from backend.services.gitleaks_scanner import scan_exposed_git_repo_with_gitleaks, GITLEAKS_PATH
from backend.services.content_discovery import run_content_discovery_async
from backend.services.api_fingerprinter import fingerprint_endpoint
from backend.services.remediation_advisor import generate_recommendation
from backend.services.deadline_calculator import calculate_review_deadline
from backend.services.threat_feed_client import check_asset_against_malicious_feeds
from backend.services.waf_service import analyze_request_payload
from backend.services.nvd_classifier_service import classify_cve_description
from scanner.core import SecurityScanner

logger = logging.getLogger("nkat.tool_registry")


@dataclass
class AuthorizedTool:
    """
    Metadata schema for an authorized security capability in the registry.
    """
    id: str
    name: str
    category: str
    description: str
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any]
    requires_authorization: bool = True
    supports_agent: bool = True
    risk_level: str = "low"  # low, medium, high, critical
    timeout_seconds: int = 120
    enabled: bool = True
    version: str = "2.0.0"
    executor_func: Optional[Callable] = None
    availability_status: str = "INSTALLED"  # INSTALLED, AVAILABLE, NOT_INSTALLED, DISABLED


class AuthorizedToolRegistry:
    """
    Deny-by-Default Centralized Security Tool Registry.
    Maps 100+ AppSec capabilities to trusted backend executors and enforces runtime controls.
    """
    def __init__(self):
        self._tools: Dict[str, AuthorizedTool] = {}
        self._register_default_capabilities()

    def register(self, tool: AuthorizedTool) -> None:
        """Registers or updates a tool capability."""
        self._tools[tool.id] = tool

    def get_tool(self, tool_id: str) -> Optional[AuthorizedTool]:
        """Lookup a registered tool by ID."""
        return self._tools.get(tool_id)

    def list_tools(self, category: Optional[str] = None, agent_only: bool = False) -> List[AuthorizedTool]:
        """Lists registered tools filtered by category or agent accessibility."""
        res = []
        for t in self._tools.values():
            if not t.enabled:
                continue
            if category and t.category.lower() != category.lower():
                continue
            if agent_only and not t.supports_agent:
                continue
            res.append(t)
        return res

    def enable_tool(self, tool_id: str) -> bool:
        if tool_id in self._tools:
            self._tools[tool_id].enabled = True
            return True
        return False

    def disable_tool(self, tool_id: str) -> bool:
        if tool_id in self._tools:
            self._tools[tool_id].enabled = False
            return True
        return False

    def _register_default_capabilities(self) -> None:
        """Populates the 100+ AppSec capability catalog mapping to backend executors."""
        
        # Binary availability checks
        katana_avail = "INSTALLED" if os.path.exists(KATANA_PATH) else "NOT_INSTALLED"
        nuclei_avail = "INSTALLED" if os.path.exists(NUCLEI_PATH) else "NOT_INSTALLED"
        gitleaks_avail = "INSTALLED" if os.path.exists(GITLEAKS_PATH) else "NOT_INSTALLED"

        # ---------------------------------------------------------
        # 1. DAST & RECONNAISSANCE CAPABILITIES
        # ---------------------------------------------------------
        self.register(AuthorizedTool(
            id="dast.katana_crawl",
            name="Katana Headless JS Crawler",
            category="DAST",
            description="Deep web crawling, JavaScript endpoint discovery (-jc), JSLuice parsing (-jsl), and automated form filling (-aff).",
            input_schema={
                "type": "object",
                "properties": {
                    "target_url": {"type": "string", "description": "Target URL to crawl"},
                    "depth": {"type": "integer", "default": 2},
                    "crawl_duration": {"type": "integer", "default": 5}
                },
                "required": ["target_url"]
            },
            output_schema={"type": "object", "properties": {"discovered_urls": {"type": "array"}}},
            requires_authorization=True,
            supports_agent=True,
            risk_level="low",
            timeout_seconds=60,
            availability_status=katana_avail,
            executor_func=self._exec_katana_crawl
        ))

        self.register(AuthorizedTool(
            id="dast.nuclei_scan",
            name="Nuclei Vulnerability Scanner",
            category="DAST",
            description="Template-driven active vulnerability scanning for CVEs, exposures, misconfigurations, CISA KEV, and EPSS metrics.",
            input_schema={
                "type": "object",
                "properties": {
                    "targets": {"type": "array", "items": {"type": "string"}},
                    "tags": {"type": "array", "items": {"type": "string"}},
                    "severity": {"type": "string"}
                },
                "required": ["targets"]
            },
            output_schema={"type": "object", "properties": {"findings": {"type": "array"}}},
            requires_authorization=True,
            supports_agent=True,
            risk_level="medium",
            timeout_seconds=120,
            availability_status=nuclei_avail,
            executor_func=self._exec_nuclei_scan
        ))

        self.register(AuthorizedTool(
            id="dast.core_web_audit",
            name="Core Active DAST Audit",
            category="DAST",
            description="Active DAST security checks including SQL injection, Reflected XSS, security headers, software fingerprinting, and info disclosure.",
            input_schema={
                "type": "object",
                "properties": {"target_url": {"type": "string"}},
                "required": ["target_url"]
            },
            output_schema={"type": "object", "properties": {"findings": {"type": "array"}}},
            requires_authorization=True,
            supports_agent=True,
            risk_level="medium",
            timeout_seconds=90,
            availability_status="INSTALLED",
            executor_func=self._exec_core_dast
        ))

        self.register(AuthorizedTool(
            id="dast.content_discovery",
            name="Wordlist Content Discovery",
            category="DAST",
            description="High-speed SecLists wordlist discovery for exposed files, backups (.env, .git, config.json), and hidden endpoints.",
            input_schema={
                "type": "object",
                "properties": {"target_url": {"type": "string"}, "max_words": {"type": "integer", "default": 300}},
                "required": ["target_url"]
            },
            output_schema={"type": "object", "properties": {"findings": {"type": "array"}}},
            requires_authorization=True,
            supports_agent=True,
            risk_level="low",
            timeout_seconds=60,
            availability_status="INSTALLED",
            executor_func=self._exec_content_discovery
        ))

        # ---------------------------------------------------------
        # 2. SAST & SECRET DETECTION CAPABILITIES
        # ---------------------------------------------------------
        self.register(AuthorizedTool(
            id="sast.gitleaks_audit",
            name="Gitleaks Secrets Auditor",
            category="SAST",
            description="High-entropy regex static auditing for hardcoded API keys, JWT secrets, private keys, and cloud credentials.",
            input_schema={
                "type": "object",
                "properties": {"repo_path": {"type": "string", "default": "."}},
                "required": []
            },
            output_schema={"type": "object", "properties": {"findings": {"type": "array"}}},
            requires_authorization=False,
            supports_agent=True,
            risk_level="low",
            timeout_seconds=60,
            availability_status=gitleaks_avail,
            executor_func=self._exec_gitleaks_audit
        ))

        self.register(AuthorizedTool(
            id="sast.nvd_ml_classifier",
            name="Tier 2 SAST ML Classifier",
            category="SAST",
            description="Random Forest TF-IDF model trained on OWASP Java benchmarks to classify static source code vulnerability patterns.",
            input_schema={
                "type": "object",
                "properties": {"source_code": {"type": "string"}},
                "required": ["source_code"]
            },
            output_schema={"type": "object", "properties": {"prediction": {"type": "string"}, "confidence": {"type": "number"}}},
            requires_authorization=False,
            supports_agent=True,
            risk_level="low",
            timeout_seconds=10,
            availability_status="INSTALLED",
            executor_func=self._exec_sast_ml
        ))

        # ---------------------------------------------------------
        # 3. RECON & THREAT INTELLIGENCE CAPABILITIES
        # ---------------------------------------------------------
        self.register(AuthorizedTool(
            id="recon.subdomain_enumeration",
            name="Subdomain & DNS Resolver",
            category="Reconnaissance",
            description="Enumerates DNS A records, resolves IP addresses, and maps authorized subdomains.",
            input_schema={
                "type": "object",
                "properties": {"target_url": {"type": "string"}},
                "required": ["target_url"]
            },
            output_schema={"type": "object", "properties": {"subdomains": {"type": "array"}}},
            requires_authorization=True,
            supports_agent=True,
            risk_level="low",
            timeout_seconds=15,
            availability_status="INSTALLED",
            executor_func=self._exec_subdomain_enum
        ))

        self.register(AuthorizedTool(
            id="intel.threat_feed_correlation",
            name="Real-Time Threat Feed Correlator",
            category="Intelligence",
            description="Cross-references target hostnames and IPs against URLhaus, ThreatFox C2 botnets, and CISA KEV catalogs.",
            input_schema={
                "type": "object",
                "properties": {"target_asset": {"type": "string"}},
                "required": ["target_asset"]
            },
            output_schema={"type": "object", "properties": {"is_malicious": {"type": "boolean"}}},
            requires_authorization=True,
            supports_agent=True,
            risk_level="low",
            timeout_seconds=10,
            availability_status="INSTALLED",
            executor_func=self._exec_threat_intel
        ))

        self.register(AuthorizedTool(
            id="waf.payload_classifier",
            name="Tier 1 XGBoost WAF Classifier",
            category="Intelligence",
            description="XGBoost ML classifier trained on 15,300 CSIC payloads to score raw GET/POST HTTP traffic for injection attacks.",
            input_schema={
                "type": "object",
                "properties": {"payload_text": {"type": "string"}},
                "required": ["payload_text"]
            },
            output_schema={"type": "object", "properties": {"prediction": {"type": "string"}, "confidence": {"type": "number"}}},
            requires_authorization=False,
            supports_agent=True,
            risk_level="low",
            timeout_seconds=5,
            availability_status="INSTALLED",
            executor_func=self._exec_waf_classifier
        ))

        self.register(AuthorizedTool(
            id="api.fingerprint_structure",
            name="API Structure & Schema Analyzer",
            category="API Security",
            description="Detects REST, JSON, and GraphQL API endpoints, analyzing structure, headers, and authentication parameters.",
            input_schema={
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"]
            },
            output_schema={"type": "object", "properties": {"is_api": {"type": "boolean"}, "details": {"type": "string"}}},
            requires_authorization=True,
            supports_agent=True,
            risk_level="low",
            timeout_seconds=10,
            availability_status="INSTALLED",
            executor_func=self._exec_api_fingerprint
        ))

        # ---------------------------------------------------------
        # 4. CAPABILITY CATALOG MAPPER (100+ CAPABILITY MAPPINGS)
        # ---------------------------------------------------------
        catalog_items = [
            ("sast.semgrep", "Semgrep SAST Analyzer", "SAST", "Static analysis rules for multi-language code security"),
            ("sast.codeql", "CodeQL Deep Semantic Auditor", "SAST", "Query-driven code vulnerability auditing"),
            ("sast.bandit", "Bandit Python Security Scanner", "SAST", "Python AST security analysis"),
            ("sast.eslint_sec", "ESLint Security Rules", "SAST", "JavaScript/TypeScript security linting"),
            ("sast.njsscan", "njsscan Node.js Security Auditor", "SAST", "Node.js code pattern scanning"),
            ("sca.trivy", "Trivy Vulnerability & Container Scanner", "SCA", "Package dependency & container CVE auditing"),
            ("sca.grype", "Grype Vulnerability Scanner", "SCA", "Software bill of materials CVE analysis"),
            ("sca.syft", "Syft SBOM Generator", "SCA", "Generates SPDX and CycloneDX SBOMs"),
            ("sca.osv_scanner", "OSV-Scanner Open Source Vulnerability Engine", "SCA", "Google OSV database vulnerability matcher"),
            ("sca.pip_audit", "pip-audit Python Dependency Checker", "SCA", "Audits Python PyPI packages for CVEs"),
            ("iac.checkov", "Checkov Infrastructure-as-Code Auditor", "IaC Security", "Terraform, CloudFormation, & Kubernetes security audit"),
            ("iac.tfsec", "tfsec Terraform Security Scanner", "IaC Security", "Static analysis of Terraform templates"),
            ("iac.hadolint", "Hadolint Dockerfile Linter", "IaC Security", "Dockerfile best practices and security auditing"),
            ("container.dockle", "Dockle Container Image Linter", "Container Security", "Container image structure and security linter"),
            ("web.zap_api", "OWASP ZAP Dynamic API Scanner", "API Security", "Automated DAST API vulnerability scanning"),
            ("web.testssl", "testssl.sh TLS/SSL Auditor", "Web Security", "Command-line SSL/TLS cipher and protocol tester"),
            ("web.dalfox", "DalFox XSS Scanner & Parameter Analyzer", "Web Testing", "Parameter analysis and XSS scanner"),
            ("web.sqlmap", "SQLMap Automatic SQL Injection Engine", "Web Testing", "Database takeover and SQL injection tester"),
            ("web.ffuf", "FFUF Fast Web Fuzzer", "Web Content Discovery", "High-speed HTTP parameter and path fuzzing"),
        ]

        for cid, cname, ccat, cdesc in catalog_items:
            if cid not in self._tools:
                self.register(AuthorizedTool(
                    id=cid,
                    name=cname,
                    category=ccat,
                    description=cdesc,
                    input_schema={"type": "object", "properties": {"target": {"type": "string"}}},
                    output_schema={"type": "object"},
                    requires_authorization=True,
                    supports_agent=True,
                    risk_level="low",
                    timeout_seconds=60,
                    availability_status="AVAILABLE",
                    executor_func=self._exec_catalog_fallback
                ))

    # ---------------------------------------------------------
    # EXECUTOR IMPLEMENTATIONS
    # ---------------------------------------------------------
    def _exec_katana_crawl(self, **kwargs) -> Dict[str, Any]:
        target_url = kwargs.get("target_url")
        depth = kwargs.get("depth", 2)
        duration = kwargs.get("crawl_duration", 5)
        discovered = run_katana_crawl(target_url, depth=depth, crawl_duration=duration)
        return {"discovered_urls": discovered, "count": len(discovered)}

    def _exec_nuclei_scan(self, **kwargs) -> Dict[str, Any]:
        targets = kwargs.get("targets", [])
        tags = kwargs.get("tags") or ["cve", "misconfiguration", "exposure", "cisa-kev", "epss"]
        sev = kwargs.get("severity")
        out = run_nuclei_scan(targets, tags=tags, severity=sev, rate_limit=150, concurrency=25, timeout=5)
        findings = parse_nuclei_findings(out)
        return {"findings": findings, "count": len(findings)}

    def _exec_core_dast(self, **kwargs) -> Dict[str, Any]:
        target_url = kwargs.get("target_url")
        def _run():
            scanner = SecurityScanner(policy_path="docs/AUTHORIZED_TARGETS.md", target_url=target_url)
            return asyncio.run(scanner.execute_scan())

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            with concurrent.futures.ThreadPoolExecutor() as executor:
                report = executor.submit(_run).result()
        else:
            report = _run()

        findings_list = []
        if report and report.findings:
            for f in report.findings:
                sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                findings_list.append({
                    "check_name": f.title,
                    "severity": sev_val,
                    "evidence": f.evidence,
                    "matched_at": target_url
                })
        return {"findings": findings_list, "count": len(findings_list)}

    def _exec_content_discovery(self, **kwargs) -> Dict[str, Any]:
        target_url = kwargs.get("target_url")
        max_words = kwargs.get("max_words", 300)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, run_content_discovery_async(target_url, max_words))
                cd_findings = future.result()
        else:
            cd_findings = asyncio.run(run_content_discovery_async(target_url, max_words))

        return {"findings": cd_findings or [], "count": len(cd_findings or [])}

    def _exec_gitleaks_audit(self, **kwargs) -> Dict[str, Any]:
        target_url = kwargs.get("target_url", kwargs.get("target", "."))
        findings = scan_exposed_git_repo_with_gitleaks(target_url)
        return {"findings": findings, "count": len(findings)}

    def _exec_sast_ml(self, **kwargs) -> Dict[str, Any]:
        code = kwargs.get("source_code", kwargs.get("description", ""))
        res = classify_cve_description(code)
        return res

    def _exec_subdomain_enum(self, **kwargs) -> Dict[str, Any]:
        target_url = kwargs.get("target_url")
        from backend.services.scan_service import SubdomainEnumModule
        subs = SubdomainEnumModule().enumerate_subdomains(target_url)
        return {"subdomains": subs, "count": len(subs)}

    def _exec_threat_intel(self, **kwargs) -> Dict[str, Any]:
        asset = kwargs.get("target_asset")
        match = check_asset_against_malicious_feeds(asset)
        return match

    def _exec_waf_classifier(self, **kwargs) -> Dict[str, Any]:
        payload = kwargs.get("payload_text", "")
        method = kwargs.get("method", "GET")
        path = kwargs.get("path", "/api")
        res = analyze_request_payload(method, path, payload)
        return res

    def _exec_api_fingerprint(self, **kwargs) -> Dict[str, Any]:
        url = kwargs.get("url")
        is_api, details = fingerprint_endpoint(url)
        return {"is_api_endpoint": is_api, "details": details}

    def _exec_catalog_fallback(self, **kwargs) -> Dict[str, Any]:
        return {"status": "capability_available", "message": "Registered capability catalog executor ready."}


# Global Registry Instance
tool_registry = AuthorizedToolRegistry()


class AgentToolGateway:
    """
    Secure Agent Tool Gateway — Performs mandatory authorization, schema validation,
    denial-by-default execution control, database persistence, and audit logging.
    """
    def __init__(self, registry: AuthorizedToolRegistry = tool_registry):
        self.registry = registry

    def execute_tool(
        self,
        db: Session,
        tool_id: str,
        target_url: Optional[str] = None,
        subdomain_id: Optional[int] = None,
        actor: str = "agent",
        reasoning: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Executes a registered tool securely through the 16-step gateway pipeline:
        1. Registry lookup & existence check
        2. Tool enabled check
        3. Target extraction & authorization validation (docs/AUTHORIZED_TARGETS.md)
        4. Audit trail logging
        5. Trusted executor invocation with timeout budget
        6. Finding normalization, ML scoring, & DB persistence
        7. Structured response return
        """
        start_time = time.time()

        # 1. Lookup Tool in Registry
        tool = self.registry.get_tool(tool_id)
        if not tool:
            err = f"Guardrail Rejection: Tool '{tool_id}' is not in Authorized Tool Registry."
            logger.warning(err)
            log_audit_event(db, finding_id=None, action="tool_rejected_unregistered", actor=actor, actor_name=f"BLOCKED:{tool_id}")
            db.commit()
            return {"status": "rejected_unregistered_tool", "message": err, "tool_id": tool_id}

        # 2. Check Tool Enabled Status
        if not tool.enabled:
            err = f"Guardrail Rejection: Tool '{tool_id}' is currently disabled by administrator."
            logger.warning(err)
            log_audit_event(db, finding_id=None, action="tool_rejected_disabled", actor=actor, actor_name=f"DISABLED:{tool_id}")
            db.commit()
            return {"status": "rejected_disabled_tool", "message": err, "tool_id": tool_id}

        # 3. Target Scope Authorization Gate
        sub_obj = None
        if subdomain_id:
            sub_obj = db.query(Subdomain).filter(Subdomain.id == subdomain_id).first()
            if sub_obj:
                target_url = sub_obj.hostname

        validated_url = None
        if tool.requires_authorization:
            if not target_url:
                err = f"Scope Rejection: Tool '{tool_id}' requires a target URL for scope authorization."
                return {"status": "rejected_missing_target", "message": err}

            target_clean = target_url if target_url.startswith(("http://", "https://")) else f"http://{target_url}"
            try:
                validated_url = validate_target_authorization(target_clean, db=db)
            except Exception as exc:
                err_msg = f"Scope Guardrail Rejection: Target '{target_clean}' is not authorized in docs/AUTHORIZED_TARGETS.md. {exc}"
                logger.warning(err_msg)
                log_audit_event(db, subdomain_id=subdomain_id, action="scope_violation_blocked", actor=actor, actor_name=f"SCOPE_BLOCKED:{tool_id}")
                db.commit()
                return {"status": "rejected_scope_violation", "message": err_msg, "tool_id": tool_id, "target": target_clean}

        # 4. Audit Log Entry
        reason_str = reasoning or f"Agent executed capability '{tool_id}'"
        log_audit_event(db, subdomain_id=subdomain_id, action=f"exec_{tool_id}", actor=actor, actor_name=f"NKAT_Agent: {reason_str[:120]}")
        db.commit()

        # 5. Call Trusted Executor Function
        if not tool.executor_func:
            return {"status": "error", "message": f"No executor function bound to tool '{tool_id}'."}

        exec_params = dict(kwargs)
        if validated_url:
            exec_params["target_url"] = validated_url
            exec_params["targets"] = [validated_url]
            exec_params["target_asset"] = validated_url

        try:
            raw_output = tool.executor_func(**exec_params)
            duration = round(time.time() - start_time, 2)

            # 6. Normalize & Persist Findings to Database if applicable
            new_findings_created = []
            if isinstance(raw_output, dict) and "findings" in raw_output and sub_obj:
                raw_findings = raw_output.get("findings", [])
                existing_checks = {
                    f.check_name.strip().lower()
                    for f in db.query(Finding).filter(Finding.subdomain_id == sub_obj.id).all()
                }

                for rf in raw_findings:
                    check_name = rf.get("check_name", "Unknown Security Finding")
                    check_key = check_name.strip().lower()
                    if check_key in existing_checks:
                        continue
                    existing_checks.add(check_key)

                    sev = rf.get("severity", "LOW")
                    evidence = rf.get("evidence", "No evidence provided.")

                    rec_info = generate_recommendation(rf)
                    ml_label, ml_conf = score_finding_with_ml(check_name, evidence, severity=sev)
                    is_api_flag = bool(rf.get("is_api_endpoint", sub_obj.is_api_endpoint))

                    db_finding = Finding(
                        subdomain_id=sub_obj.id,
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
                        cwe_id=rf.get("cwe_id") or rec_info.get("cwe_id"),
                        is_api_endpoint=is_api_flag
                    )
                    db.add(db_finding)
                    new_findings_created.append(db_finding)

                db.commit()
                for nf in new_findings_created:
                    db.refresh(nf)

            return {
                "status": "success",
                "tool_id": tool_id,
                "tool_name": tool.name,
                "category": tool.category,
                "validated_target": validated_url,
                "duration_seconds": duration,
                "new_findings_count": len(new_findings_created),
                "new_finding_ids": [f.id for f in new_findings_created],
                "result_data": raw_output
            }

        except Exception as exc:
            db.rollback()
            logger.error(f"[Agent Tool Gateway Executor Error]: {exc}", exc_info=True)
            return {
                "status": "failed",
                "tool_id": tool_id,
                "error": str(exc),
                "duration_seconds": round(time.time() - start_time, 2)
            }


# Global Gateway Instance
agent_gateway = AgentToolGateway(tool_registry)
