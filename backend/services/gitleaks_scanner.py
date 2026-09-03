"""
Gitleaks Secret Scanner Service — Mission 21 Part 3
---------------------------------------------------
When an exposed Git repository (.git) is detected, attempts to safely clone/fetch
the exposed repository into a temporary directory and executes `gitleaks detect`
to extract real leaked secrets (API keys, passwords, private keys, tokens).

Includes strict guardrails:
- Maximum download size limit (e.g. 50 MB)
- Strict execution timeout (e.g. 30 seconds)
"""

import os
import sys
import shutil
import tempfile
import subprocess
import json
from typing import List, Dict, Any

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GITLEAKS_PATH = os.path.join(PROJECT_ROOT, "gitleaks.exe")


def scan_exposed_git_repo_with_gitleaks(
    target_url: str,
    max_time_seconds: int = 30,
    max_size_bytes: int = 50 * 1024 * 1024
) -> List[Dict[str, Any]]:
    """
    Attempts to clone an exposed .git directory from target_url into a temporary location,
    enforcing time and size limits, and runs gitleaks detect on the cloned repo.
    
    Returns a list of secret finding dicts:
    [
       {
          "rule_id": "generic-api-key",
          "description": "Found API key",
          "secret": "AKIA...",
          "file": "config.json",
          "start_line": 12
       }
    ]
    """
    git_url = target_url.rstrip("/")
    if not git_url.endswith(".git"):
        git_url = f"{git_url}/.git"

    found_secrets: List[Dict[str, Any]] = []

    if not os.path.exists(GITLEAKS_PATH):
        sys.stderr.write(f"[!] Gitleaks binary not found at '{GITLEAKS_PATH}'. Skipping deep secret leak scan.\n")
        return found_secrets

    temp_dir = tempfile.mkdtemp(prefix="nkat_gitleaks_")
    try:
        # 1. Attempt git clone with timeout and depth=1
        clone_cmd = [
            "git", "clone", "--depth", "1", git_url, temp_dir
        ]
        
        try:
            res = subprocess.run(
                clone_cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=max_time_seconds
            )
        except subprocess.TimeoutExpired:
            sys.stderr.write(f"[!] Git clone timed out after {max_time_seconds}s for '{git_url}'. Aborting.\n")
            return found_secrets
        except Exception as exc:
            sys.stderr.write(f"[!] Git clone failed for '{git_url}': {exc}\n")
            return found_secrets

        # Check total directory size guardrail
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(temp_dir):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                total_size += os.path.getsize(fp)
                if total_size > max_size_bytes:
                    sys.stderr.write(f"[!] Repository size exceeded {max_size_bytes} bytes limit. Aborting secret scan.\n")
                    return found_secrets

        # 2. Run gitleaks detect against temporary repo directory
        report_json_path = os.path.join(temp_dir, "gitleaks_report.json")
        gitleaks_cmd = [
            GITLEAKS_PATH,
            "detect",
            "--source", temp_dir,
            "--report-format", "json",
            "--report-path", report_json_path,
            "--no-git",
            "-v"
        ]

        try:
            subprocess.run(
                gitleaks_cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=max_time_seconds
            )

            if os.path.exists(report_json_path):
                with open(report_json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for item in data:
                            found_secrets.append({
                                "rule_id": item.get("RuleID", "exposed-secret"),
                                "description": item.get("Description", "Exposed Secret / Credential"),
                                "secret": item.get("Secret", "*****"),
                                "file": item.get("File", "Unknown"),
                                "start_line": item.get("StartLine", 0)
                            })
        except subprocess.TimeoutExpired:
            sys.stderr.write(f"[!] Gitleaks scan timed out after {max_time_seconds}s.\n")
        except Exception as exc:
            sys.stderr.write(f"[!] Gitleaks scan execution error: {exc}\n")

    finally:
        # Clean up temporary clone directory safely
        shutil.rmtree(temp_dir, ignore_errors=True)

    return found_secrets
