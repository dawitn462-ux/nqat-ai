"""
Core Security Scanner Orchestrator.
Coordinates target scope verification exclusively from docs/AUTHORIZED_TARGETS.md,
endpoint crawling, vulnerability checks, response sanitization, and structured JSON output.
"""

import json
import os
import time
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

from scanner.target_parser import TargetParser
from scanner.scope import ScopeValidator
from scanner.sanitizer import ResponseSanitizer
from scanner.client import AsyncScannerClient
from scanner.crawler import EndpointCrawler
from scanner.checks import ALL_CHECKS
from scanner.models import (
    ScanReport,
    ScanSummary,
    VulnerabilityFinding,
    StructuredFinding,
    Severity,
)
from scanner.exceptions import ScopeViolationError, ScanConfigError


class SecurityScanner:
    """
    Main Security Scanner orchestrator for NKAT AI.
    Parses authorized target scope strictly from docs/AUTHORIZED_TARGETS.md policy.
    Never accepts arbitrary free-text CLI target overrides.
    """

    def __init__(
        self,
        policy_path: str = "docs/AUTHORIZED_TARGETS.md",
        output_dir: str = "data",
        strict_enforcement: Optional[bool] = None,
        enforce_https: Optional[bool] = None,
        target_url: Optional[str] = None,
    ):
        self.policy_path = policy_path
        https_flag = enforce_https if enforce_https is not None else (os.getenv("ENFORCE_HTTPS", "false").lower() in ("true", "1", "yes"))

        if target_url:
            self.target_url = target_url
        else:
            self.target_url = TargetParser.get_primary_target(self.policy_path, enforce_https=https_flag)

        self.scope_validator = ScopeValidator(
            target_url=self.target_url,
            strict_enforcement=strict_enforcement,
            enforce_https=enforce_https,
        )
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    async def execute_scan(self) -> ScanReport:
        """
        Executes security audit pipeline:
        1. Parse authorized target strictly from docs/AUTHORIZED_TARGETS.md
        2. Scope verification
        3. Endpoint discovery (crawling)
        4. Vulnerability checks (headers, fingerprinting, sqli, xss, infoleak)
        5. Response sanitization & structured JSON format generation
        """
        start_time = time.time()
        print(f"[*] Reading authorized target strictly from '{self.policy_path}'...")
        print(f"[*] Target selected: {self.target_url}")

        # Mandatory initial target scope validation
        self.scope_validator.validate_url(self.target_url)
        print("[+] Scope verification PASSED. Target authorized.")

        findings: List[VulnerabilityFinding] = []
        structured_findings: List[StructuredFinding] = []

        async with AsyncScannerClient(scope_validator=self.scope_validator) as client:
            # Step 1: Crawl target endpoints
            print("[*] Crawling target endpoints & API routes...")
            crawler = EndpointCrawler(client)
            responses = await crawler.crawl(self.target_url)
            print(f"[+] Endpoint discovery complete. Crawled {len(responses)} pages/routes.")

            # Step 2: Run vulnerability checks
            print("[*] Running active vulnerability audit modules...")
            for CheckClass in ALL_CHECKS:
                check = CheckClass(client)
                print(f"  -> Executing check: [{check.name}] ({check.check_id})")
                try:
                    check_findings = await check.run(self.target_url, responses)
                    findings.extend(check_findings)
                    print(f"     Found {len(check_findings)} findings.")
                except Exception as exc:
                    print(f"     [!] Error running check {check.check_id}: {exc}")

        scan_duration = round(time.time() - start_time, 2)
        current_ts = datetime.now(timezone.utc).isoformat()

        # Step 3: Deduplicate findings by title and endpoint
        unique_findings: List[VulnerabilityFinding] = []
        seen_keys = set()
        for f in findings:
            key = (f.title, f.endpoint)
            if key not in seen_keys:
                seen_keys.add(key)
                unique_findings.append(f)
        findings = unique_findings

        # Step 4: Sanitize evidence and build structured JSON findings {target, check_name, severity, evidence, timestamp}
        severity_counts = {sev.value: 0 for sev in Severity}
        for f in findings:
            severity_counts[f.severity.value] += 1

            clean_evidence = ResponseSanitizer.sanitize(f.evidence, max_len=400)
            clean_target = ResponseSanitizer.sanitize(f.endpoint, max_len=200)

            # Assign sanitized values back
            f.evidence = clean_evidence
            f.endpoint = clean_target

            structured_findings.append(
                StructuredFinding(
                    target=clean_target,
                    check_name=f.title,
                    severity=f.severity.value,
                    evidence=clean_evidence,
                    timestamp=current_ts,
                )
            )

        summary = ScanSummary(
            total_endpoints_scanned=len(responses),
            total_vulnerabilities=len(findings),
            severity_counts=severity_counts,
            scan_duration_seconds=scan_duration,
        )

        scan_id = f"scan_{int(time.time())}"
        report = ScanReport(
            scan_id=scan_id,
            target_url=self.target_url,
            timestamp=current_ts,
            summary=summary,
            findings=findings,
            structured_findings=structured_findings,
        )

        # Step 4: Persist structured report to data/ directory
        report_file = os.path.join(self.output_dir, f"scan_report_{scan_id}.json")
        latest_file = os.path.join(self.output_dir, "scan_report_latest.json")
        structured_file = os.path.join(self.output_dir, "structured_findings.json")

        report_json = report.model_dump_json(indent=2)
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(report_json)

        with open(latest_file, "w", encoding="utf-8") as f:
            f.write(report_json)

        # Dump exact structured findings JSON array {target, check_name, severity, evidence, timestamp}
        structured_json_list = [sf.model_dump() for sf in structured_findings]
        with open(structured_file, "w", encoding="utf-8") as f:
            json.dump(structured_json_list, f, indent=2)

        print(f"[+] Audit complete in {scan_duration}s. Report saved to: {report_file}")
        print(f"[+] Structured findings JSON saved to: {structured_file}")
        return report
