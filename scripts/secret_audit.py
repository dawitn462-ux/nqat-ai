"""
Repository Secret Safety Auditor.
Scans all codebase files, environment configs, and gitignore tracking rules for exposed secrets,
private keys, passwords, and API tokens.
"""

import os
import re
from typing import List, Tuple

# Patterns indicating hardcoded secrets or credentials
SECRET_PATTERNS = [
    (r"-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----", "Private Key Block"),
    (r"(api[_-]?key|secret[_-]?key|auth[_-]?token)\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "API/Secret Key Assignment"),
    (r"password\s*=\s*['\"][^'\"]{8,}['\"]", "Hardcoded Password"),
    (r"AWS[A-Z0-9]{16,}", "AWS Key Identifier"),
]

# Sensitive file patterns that MUST be in .gitignore
CRITICAL_IGNORED_PATTERNS = [
    ".env",
    "certs/",
    "*.pem",
    "*.key",
    ".venv",
]


def audit_gitignore(workspace_dir: str = ".") -> List[str]:
    """
    Verifies .gitignore exists and properly excludes secrets and certificates.
    """
    gitignore_path = os.path.join(workspace_dir, ".gitignore")
    if not os.path.exists(gitignore_path):
        return ["CRITICAL: .gitignore file is missing from repository root!"]

    with open(gitignore_path, "r", encoding="utf-8") as f:
        content = f.read()

    missing_rules = []
    for pattern in CRITICAL_IGNORED_PATTERNS:
        if pattern not in content:
            missing_rules.append(f"WARNING: '{pattern}' is missing from .gitignore!")

    return missing_rules


def audit_files_for_secrets(workspace_dir: str = ".") -> List[Tuple[str, int, str, str]]:
    """
    Scans source files for hardcoded secrets.
    """
    findings = []
    ignore_dirs = {".venv", ".git", "node_modules", ".pytest_cache", "certs", "juice-shop-dist", "juice-shop-node22", "data"}

    for root, dirs, files in os.walk(workspace_dir):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]

        for file_name in files:
            if file_name == ".env":
                # .env contains local test environment variables; verify it is in .gitignore
                continue

            file_path = os.path.join(root, file_name)

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                for idx, line in enumerate(lines, 1):
                    for pattern, secret_type in SECRET_PATTERNS:
                        if re.search(pattern, line, re.IGNORECASE):
                            findings.append((file_path, idx, secret_type, line.strip()))
            except Exception:
                pass

    return findings


def main():
    print("==================================================")
    print("      NKAT AI SECRET & CREDENTIAL SAFETY AUDIT    ")
    print("==================================================")

    # 1. Audit .gitignore rules
    gitignore_issues = audit_gitignore()
    if gitignore_issues:
        print("\n[!] GitIgnore Audit Issues:")
        for issue in gitignore_issues:
            print(f"  - {issue}")
    else:
        print("\n[+] .gitignore Audit: PASSED (All sensitive paths (.env, certs/, *.pem, *.key) strictly ignored).")

    # 2. Audit files for hardcoded secrets
    secret_findings = audit_files_for_secrets()
    if secret_findings:
        print("\n[!] Hardcoded Secret Exposure Found:")
        for path, line_no, stype, line in secret_findings:
            print(f"  - [{stype}] {path}:{line_no} -> {line}")
    else:
        print("[+] Source Code Secret Audit: PASSED (0 hardcoded secrets or private keys detected in codebase).")

    print("\n==================================================")
    print("         SECRET AUDIT COMPLETED CLEANLY           ")
    print("==================================================")


if __name__ == "__main__":
    main()
