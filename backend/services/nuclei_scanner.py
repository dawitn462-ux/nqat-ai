import json
import os
import subprocess
import sys
import logging
from typing import List, Union, Optional, Dict, Any

logger = logging.getLogger("nkat.nuclei")

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NUCLEI_PATH = os.path.join(PROJECT_ROOT, "nuclei.exe")

SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "unknown": "INFO",
}


def get_nuclei_info() -> Dict[str, Any]:
    """
    Checks if Nuclei binary is present and returns its version information.
    """
    if not os.path.exists(NUCLEI_PATH):
        return {"available": False, "version": None, "path": NUCLEI_PATH}

    try:
        res = subprocess.run(
            [NUCLEI_PATH, "-version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5
        )
        out = (res.stdout or "") + (res.stderr or "")
        ver = "v3.11.1"
        for line in out.splitlines():
            if "Version:" in line or "Nuclei Engine Version:" in line:
                ver = line.split(":")[-1].strip()
                break
        return {"available": True, "version": ver, "path": NUCLEI_PATH}
    except Exception as exc:
        logger.warning(f"Failed to query Nuclei version: {exc}")
        return {"available": True, "version": "v3.11.1", "path": NUCLEI_PATH}


def run_nuclei_scan(
    targets: Union[str, List[str]],
    output_path: str = "nuclei_output.jsonl",
    tags: Optional[List[str]] = None,
    severity: Optional[str] = None,
    rate_limit: int = 150,
    concurrency: int = 25,
    timeout: int = 10,
    scan_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Executes nuclei.exe binary against a single target URL or a list of target URLs.
    Includes safe argument list execution, timeout enforcement, and non-destructive profile enforcement.
    """
    if not os.path.exists(NUCLEI_PATH):
        logger.warning("nuclei.exe binary not found, skipping Nuclei scanner step.")
        return {
            "status": "TOOL_UNAVAILABLE",
            "output_path": output_path,
            "raw_count": 0,
            "exit_code": -1,
            "error": "nuclei.exe not found on system PATH or project root"
        }

    # Ensure parent output directory exists
    out_dir = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(out_dir, exist_ok=True)
    stderr_path = os.path.join(out_dir, f"nuclei_stderr_{scan_id or 'run'}.log")

    cmd = [NUCLEI_PATH, "-jsonl", "-silent", "-duc", "-dut", "-no-color"]

    # Exclude intrusive / destructive checks from default profiles
    cmd.extend(["-exclude-tags", "dos,fuzz,rce-blind"])

    temp_list_file = None
    if isinstance(targets, list):
        if not targets:
            logger.info("Empty target list provided to Nuclei scanner.")
            return {"status": "SKIPPED", "output_path": output_path, "raw_count": 0, "exit_code": 0}
        temp_list_file = os.path.join(out_dir, f"nuclei_targets_temp_{scan_id or os.getpid()}.txt")
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
    exit_code = 0
    err_msg = None

    try:
        with open(output_path, "w", encoding="utf-8") as f, open(stderr_path, "w", encoding="utf-8") as errf:
            res = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=f,
                stderr=errf,
                timeout=subproc_timeout,
            )
            exit_code = res.returncode
    except subprocess.TimeoutExpired:
        logger.warning(f"Nuclei execution timed out after {subproc_timeout}s.")
        err_msg = f"Timed out after {subproc_timeout}s"
        exit_code = 124
    except Exception as exc:
        logger.warning(f"Nuclei execution error: {exc}")
        err_msg = str(exc)
        exit_code = 1
    finally:
        if temp_list_file and os.path.exists(temp_list_file):
            try:
                os.remove(temp_list_file)
            except Exception:
                pass

    raw_findings = parse_nuclei_findings(output_path)
    meta = {
        "status": "COMPLETED" if exit_code == 0 else ("TIMED_OUT" if exit_code == 124 else "FAILED"),
        "output_path": output_path,
        "raw_count": len(raw_findings),
        "exit_code": exit_code,
        "error": err_msg,
        "findings": raw_findings
    }
    return NucleiScanResult(output_path, meta)


class NucleiScanResult(str):
    """
    Subclasses str so callers expecting output_path (str) continue working seamlessly,
    while also providing access to metadata (.status, .findings, .exit_code).
    """
    def __new__(cls, output_path: str, meta: Dict[str, Any]):
        obj = str.__new__(cls, output_path)
        obj.meta = meta
        obj.status = meta.get("status")
        obj.output_path = output_path
        obj.findings = meta.get("findings", [])
        obj.raw_count = meta.get("raw_count", 0)
        obj.exit_code = meta.get("exit_code", 0)
        obj.error = meta.get("error")
        return obj

    def get(self, key, default=None):
        return self.meta.get(key, default)

    def __getitem__(self, item):
        if isinstance(item, str):
            return self.meta[item]
        return super().__getitem__(item)


def parse_nuclei_findings(output_path: Union[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Defensively parses Nuclei's JSONL output into canonical structured finding dictionaries,
    enriching with CVE, CWE, CVSS score, template ID, and raw tool output.
    """
    findings = []
    if isinstance(output_path, dict) and "output_path" in output_path:
        output_path = output_path["output_path"]

    path_str = str(output_path)
    if not os.path.exists(path_str):
        return findings

    with open(path_str, "r", encoding="utf-8") as f:

        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = entry.get("info", {})
            template_id = entry.get("template-id") or entry.get("templateID") or "unknown-template"
            template_name = info.get("name") or template_id
            severity_raw = str(info.get("severity", "unknown")).lower()
            severity = SEVERITY_MAP.get(severity_raw, "INFO")
            matched_url = entry.get("matched-at") or entry.get("host") or ""
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

            evidence = f"Nuclei matched '{template_name}' ({template_id}) at {matched_url}{matcher_str}{cve_str}{extracted_str}{desc_str}".strip()

            findings.append({
                "template_id": template_id,
                "check_name": f"NUCLEI: {template_name}",
                "severity": severity,
                "evidence": evidence,
                "matched_at": matched_url,
                "cve_id": primary_cve,
                "cwe_id": primary_cwe,
                "cvss_score": float(cvss_score) if cvss_score is not None else None,
                "detection_source": "NUCLEI",
                "request_evidence": entry.get("request"),
                "response_evidence": entry.get("response"),
                "raw_output": entry,
            })

    return findings

