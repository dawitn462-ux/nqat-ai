"""
Nuclei Scanner Service — runs the nuclei binary and parses its output
into the existing findings format.
"""

import json
import os
import subprocess
import sys

from typing import List, Union, Optional, Dict, Any

NUCLEI_PATH = os.path.join(os.getcwd(), "nuclei.exe")

# Maps nuclei's severity strings to this project's existing severity scale
SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "unknown": "INFO",
}

def run_nuclei_scan(
    targets: Union[str, List[str]],
    output_path: str = "nuclei_output.jsonl",
    tags: Optional[List[str]] = None,
    severity: Optional[str] = None,
    rate_limit: int = 150,
    concurrency: int = 25,
    timeout: int = 10,
) -> str:
    """
    Executes nuclei.exe binary against a single target URL or a list of target URLs (e.g. Katana endpoints).
    Supports dynamic threat-feed tag filtering (cve, misconfiguration, exposure, cisa-kev, epss).
    """
    if not os.path.exists(NUCLEI_PATH):
        sys.stderr.write("[!] nuclei.exe binary not found, skipping Nuclei scanner step.\n")
        return output_path

    cmd = [NUCLEI_PATH, "-jsonl", "-silent", "-duc"]

    # Handle single URL vs list of URLs (e.g., from Katana crawler)
    temp_list_file = None
    if isinstance(targets, list):
        if not targets:
            sys.stderr.write("[!] Empty target list provided to Nuclei scanner.\n")
            return output_path
        temp_list_file = "nuclei_targets_temp.txt"
        with open(temp_list_file, "w", encoding="utf-8") as tf:
            for t in targets:
                tf.write(f"{t}\n")
        cmd.extend(["-list", temp_list_file])
    else:
        cmd.extend(["-target", str(targets)])

    # Dynamic Threat Tags
    tag_str = ",".join(tags) if tags else "cve,misconfiguration,exposure,cisa-kev,epss"
    cmd.extend(["-tags", tag_str])

    if severity:
        cmd.extend(["-severity", severity])

    if rate_limit > 0:
        cmd.extend(["-rate-limit", str(rate_limit)])

    if concurrency > 0:
        cmd.extend(["-concurrency", str(concurrency)])

    cmd.extend(["-timeout", str(timeout)])

    subproc_timeout = min(30, 10 + (len(targets) * 2 if isinstance(targets, list) else 2))

    try:
        with open(output_path, "w", encoding="utf-8") as f, open("nuclei_stderr.log", "w", encoding="utf-8") as errf:
            subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=f,
                stderr=errf,
                timeout=subproc_timeout,
            )
    except subprocess.TimeoutExpired:
        sys.stderr.write("[!] Nuclei timed out\n")
    except Exception as exc:
        sys.stderr.write(f"[!] Nuclei execution warning: {exc}\n")
    finally:
        if temp_list_file and os.path.exists(temp_list_file):
            try:
                os.remove(temp_list_file)
            except Exception:
                pass

    return output_path


def parse_nuclei_findings(output_path: str) -> List[Dict[str, Any]]:
    """
    Parses nuclei's JSONL output file into a list of dicts matching
    this project's findings schema, enriched with classification info (CVE, CWE, CVSS score).
    """
    findings = []
    if not os.path.exists(output_path):
        return findings

    with open(output_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = entry.get("info", {})
            template_name = info.get("name", entry.get("template-id", "Unknown Nuclei Finding"))
            severity_raw = str(info.get("severity", "unknown")).lower()
            severity = SEVERITY_MAP.get(severity_raw, "INFO")
            matched_url = entry.get("matched-at", entry.get("host", ""))
            extracted_results = entry.get("extracted-results", [])
            extracted_str = f" | Extracted: {', '.join(extracted_results)}" if extracted_results else ""
            matcher_name = entry.get("matcher-name", "")
            matcher_str = f" [matcher: {matcher_name}]" if matcher_name else ""
            
            # Classification details (CVE, CWE, CVSS score)
            classification = info.get("classification", {})
            cve_ids = classification.get("cve-id", [])
            cwe_ids = classification.get("cwe-id", [])
            cvss_score = classification.get("cvss-score", None)

            primary_cve = cve_ids[0] if isinstance(cve_ids, list) and cve_ids else (cve_ids if isinstance(cve_ids, str) else None)
            primary_cwe = cwe_ids[0] if isinstance(cwe_ids, list) and cwe_ids else (cwe_ids if isinstance(cwe_ids, str) else None)

            cve_str = f" [CVE: {primary_cve}]" if primary_cve else ""

            desc = info.get("description", "")
            desc_str = f" | {desc}" if desc and not extracted_str else ""

            # Format raw tool evidence tracing to exact Nuclei output line
            evidence = f"Nuclei matched '{template_name}' at {matched_url}{matcher_str}{cve_str}{extracted_str}{desc_str}".strip()

            findings.append({
                "check_name": f"NUCLEI: {template_name}",
                "severity": severity,
                "evidence": evidence,
                "matched_at": matched_url,
                "cve_id": primary_cve,
                "cwe_id": primary_cwe,
                "cvss_score": cvss_score,
                "raw_output": entry,
            })

    return findings
