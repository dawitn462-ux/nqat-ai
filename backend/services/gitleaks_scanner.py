import os
import sys
import shutil
import tempfile
import subprocess
import json
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger("nkat.gitleaks")

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GITLEAKS_PATH = os.path.join(PROJECT_ROOT, "gitleaks.exe")


def redact_secret_value(secret: Optional[str]) -> str:
    """
    Strict Secret Redaction Guardrail:
    Redacts exposed secret values so sensitive credentials are never displayed
    in dashboards, reports, logs, or notifications.
    """
    if not secret:
        return "[REDACTED]"
    secret_str = str(secret).strip()
    if len(secret_str) <= 6:
        return "****"
    if len(secret_str) <= 12:
        return f"{secret_str[:2]}...{secret_str[-2:]}"
    return f"{secret_str[:4]}...{secret_str[-4:]}"


def get_gitleaks_info() -> Dict[str, Any]:
    """
    Checks if Gitleaks binary is present and returns its version.
    """
    if not os.path.exists(GITLEAKS_PATH):
        return {"available": False, "version": None, "path": GITLEAKS_PATH}

    try:
        res = subprocess.run(
            [GITLEAKS_PATH, "version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5
        )
        ver = (res.stdout or "").strip() or "8.18.4"
        return {"available": True, "version": ver, "path": GITLEAKS_PATH}
    except Exception as exc:
        logger.warning(f"Error checking Gitleaks version: {exc}")
        return {"available": True, "version": "8.18.4", "path": GITLEAKS_PATH}


def scan_local_directory_with_gitleaks(
    repo_path: str,
    max_time_seconds: int = 30
) -> List[Dict[str, Any]]:
    """
    Executes Gitleaks against an authorized local repository directory on disk,
    strictly redacting all discovered secret values.
    """
    found_secrets: List[Dict[str, Any]] = []
    if not os.path.exists(GITLEAKS_PATH):
        logger.warning(f"Gitleaks binary not found at '{GITLEAKS_PATH}'.")
        return found_secrets

    if not os.path.exists(repo_path):
        logger.warning(f"Target repository path '{repo_path}' does not exist.")
        return found_secrets

    temp_dir = tempfile.mkdtemp(prefix="nkat_gitleaks_local_")
    report_json_path = os.path.join(temp_dir, "gitleaks_local_report.json")

    cmd = [
        GITLEAKS_PATH,
        "detect",
        "--source", os.path.abspath(repo_path),
        "--report-format", "json",
        "--report-path", report_json_path,
        "--no-git",
        "-v"
    ]

    try:
        subprocess.run(
            cmd,
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
                        raw_sec = item.get("Secret", "")
                        found_secrets.append({
                            "rule_id": item.get("RuleID", "exposed-secret"),
                            "description": item.get("Description", "Exposed Secret / Credential"),
                            "secret": redact_secret_value(raw_sec),
                            "raw_secret_sha256": hash(raw_sec) if raw_sec else None,
                            "file": item.get("File", "Unknown"),
                            "start_line": item.get("StartLine", 0),
                            "detection_source": "GITLEAKS",
                            "severity": "HIGH",
                            "status": "CONFIRMED"
                        })
    except subprocess.TimeoutExpired:
        logger.warning(f"Gitleaks local scan timed out after {max_time_seconds}s.")
    except Exception as exc:
        logger.warning(f"Gitleaks local scan error: {exc}")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return found_secrets


def scan_exposed_git_repo_with_gitleaks(
    target_url: str,
    max_time_seconds: int = 30,
    max_size_bytes: int = 50 * 1024 * 1024
) -> List[Dict[str, Any]]:
    """
    Attempts to clone an exposed .git directory from target_url into a temporary location,
    enforcing time and size limits, and runs gitleaks detect on the cloned repo.
    Redacts all secrets by default.
    """
    git_url = target_url.rstrip("/")
    if not git_url.endswith(".git"):
        git_url = f"{git_url}/.git"

    found_secrets: List[Dict[str, Any]] = []

    if not os.path.exists(GITLEAKS_PATH):
        logger.warning(f"Gitleaks binary not found at '{GITLEAKS_PATH}'. Skipping deep secret leak scan.")
        return found_secrets

    temp_dir = tempfile.mkdtemp(prefix="nkat_gitleaks_")
    try:
        clone_cmd = [
            "git", "clone", "--depth", "1", git_url, temp_dir
        ]

        try:
            subprocess.run(
                clone_cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=max_time_seconds
            )
        except subprocess.TimeoutExpired:
            logger.warning(f"Git clone timed out after {max_time_seconds}s for '{git_url}'. Aborting.")
            return found_secrets
        except Exception as exc:
            logger.warning(f"Git clone failed for '{git_url}': {exc}")
            return found_secrets

        total_size = 0
        for dirpath, dirnames, filenames in os.walk(temp_dir):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                total_size += os.path.getsize(fp)
                if total_size > max_size_bytes:
                    logger.warning(f"Repository size exceeded {max_size_bytes} bytes limit. Aborting secret scan.")
                    return found_secrets

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
                            raw_sec = item.get("Secret", "")
                            found_secrets.append({
                                "rule_id": item.get("RuleID", "exposed-secret"),
                                "description": item.get("Description", "Exposed Secret / Credential"),
                                "secret": redact_secret_value(raw_sec),
                                "file": item.get("File", "Unknown"),
                                "start_line": item.get("StartLine", 0),
                                "detection_source": "GITLEAKS",
                                "severity": "HIGH",
                                "status": "CONFIRMED"
                            })
        except subprocess.TimeoutExpired:
            logger.warning(f"Gitleaks scan timed out after {max_time_seconds}s.")
        except Exception as exc:
            logger.warning(f"Gitleaks scan execution error: {exc}")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return found_secrets

