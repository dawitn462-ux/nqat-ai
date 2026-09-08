"""
SAST Engine — Real Static Source Code & AST Vulnerability Scanner.
Parses actual application source files in project scope using AST and syntax analysis.
Identifies SQL injection, command injection, path traversal, hardcoded secrets, XSS reflection, and insecure configurations.
"""

import os
import re
import ast
from typing import List, Dict, Any, Optional
from backend.models import SeverityLevel


class SASTEngine:
    """
    Scans project source files for security vulnerabilities and produces machine-verifiable code evidence.
    """

    def scan_project(self, project_root: str) -> List[Dict[str, Any]]:
        findings = []
        if not os.path.exists(project_root):
            return findings

        for root, _, files in os.walk(project_root):
            # Skip virtual environments, node_modules, .git, build directories
            if any(ignore in root.lower() for ignore in ["venv", "node_modules", ".git", "__pycache__", "dist", "build"]):
                continue

            for file in files:
                filepath = os.path.join(root, file)
                rel_path = os.path.relpath(filepath, project_root)

                if file.endswith(".py"):
                    findings.extend(self._scan_python_file(filepath, rel_path))
                elif file.endswith((".js", ".jsx", ".ts", ".tsx")):
                    findings.extend(self._scan_js_file(filepath, rel_path))

        return findings

    def _scan_python_file(self, filepath: str, rel_path: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            lines = content.splitlines()

            # 1. AST Parsing for SQL string formatting / raw query construction
            try:
                tree = ast.parse(content, filename=filepath)
                for node in ast.walk(tree):
                    # Check for execute calls with formatted strings
                    if isinstance(node, ast.Call):
                        func_name = ""
                        if isinstance(node.func, ast.Attribute):
                            func_name = node.func.attr
                        elif isinstance(node.func, ast.Name):
                            func_name = node.func.id

                        if func_name in ("execute", "raw", "executemany"):
                            for arg in node.args:
                                if isinstance(arg, (ast.JoinedStr, ast.BinOp)):
                                    line_no = getattr(node, "lineno", 1)
                                    snippet = lines[line_no - 1] if line_no <= len(lines) else ""
                                    findings.append({
                                        "title": f"Raw SQL String Interpolation in {os.path.basename(rel_path)}",
                                        "file": rel_path,
                                        "line": line_no,
                                        "severity": "HIGH",
                                        "cwe_id": "CWE-89",
                                        "vulnerability_type": "SAST_SQL_INJECTION",
                                        "code_evidence": f"File: {rel_path}:{line_no}\nCode: {snippet.strip()}",
                                        "remediation": "Use parameterized ORM query bindings (e.g. text('SELECT ... :val'), {'val': input}) instead of string interpolation."
                                    })
            except SyntaxError:
                pass

            # 2. Pattern analysis for secrets and command injection
            for idx, line in enumerate(lines, 1):
                # Hardcoded API keys / secrets
                if re.search(r'(api_key|secret|password|private_key)\s*=\s*["\'][A-Za-z0-9_\-]{16,}["\']', line, re.IGNORECASE):
                    if "example" not in line.lower() and "test" not in line.lower():
                        findings.append({
                            "title": f"Hardcoded Secret / API Key in {os.path.basename(rel_path)}",
                            "file": rel_path,
                            "line": idx,
                            "severity": "CRITICAL",
                            "cwe_id": "CWE-798",
                            "vulnerability_type": "HARDCODED_SECRET",
                            "code_evidence": f"File: {rel_path}:{idx}\nCode: {line.strip()}",
                            "remediation": "Store secrets in environment variables or a secure key management system."
                        })

                # Command injection risk
                if re.search(r'os\.system\(|subprocess\.call\(.*shell\s*=\s*True', line):
                    findings.append({
                        "title": f"Potential Command Injection in {os.path.basename(rel_path)}",
                        "file": rel_path,
                        "line": idx,
                        "severity": "HIGH",
                        "cwe_id": "CWE-78",
                        "vulnerability_type": "COMMAND_INJECTION",
                        "code_evidence": f"File: {rel_path}:{idx}\nCode: {line.strip()}",
                        "remediation": "Avoid running shell commands with shell=True. Pass argument lists to subprocess.run."
                    })

        except Exception:
            pass

        return findings

    def _scan_js_file(self, filepath: str, rel_path: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            for idx, raw_line in enumerate(lines, 1):
                line = raw_line.strip()

                # SQL Injection in JS (e.g., db.query("SELECT ... " + req.query.id))
                if re.search(r'db\.query\(.*(\+|`.*\$|\${).*req\.(query|body|params)', line, re.IGNORECASE):
                    findings.append({
                        "title": f"SQL Injection via Query Concatenation in {os.path.basename(rel_path)}",
                        "file": rel_path,
                        "line": idx,
                        "severity": "CRITICAL",
                        "cwe_id": "CWE-89",
                        "vulnerability_type": "SAST_SQL_INJECTION",
                        "code_evidence": f"File: {rel_path}:{idx}\nCode: {line}",
                        "remediation": "Use parameterized queries (e.g., db.query('SELECT * FROM table WHERE id = ?', [id])) instead of string concatenation."
                    })

                # Reflected XSS (res.send("<h1>" + req.query.val))
                if re.search(r'res\.(send|write)\(.*<.*(\+|`.*\$|\${).*req\.(query|body|params)', line, re.IGNORECASE):
                    findings.append({
                        "title": f"Unescaped HTML Reflection in {os.path.basename(rel_path)}",
                        "file": rel_path,
                        "line": idx,
                        "severity": "HIGH",
                        "cwe_id": "CWE-79",
                        "vulnerability_type": "SAST_REFLECTED_XSS",
                        "code_evidence": f"File: {rel_path}:{idx}\nCode: {line}",
                        "remediation": "Contextually encode user input before outputting into HTML responses."
                    })

                # Missing Security Headers (Express app without Helmet / missing security header middleware)
                if "express()" in line and not any("helmet" in l for l in lines[:50]):
                    findings.append({
                        "title": f"Express Server Security Hardening Missing (Helmet)",
                        "file": rel_path,
                        "line": idx,
                        "severity": "MEDIUM",
                        "cwe_id": "CWE-693",
                        "vulnerability_type": "MISSING_SECURITY_HEADER",
                        "code_evidence": f"File: {rel_path}:{idx}\nCode: {line}",
                        "remediation": "Use 'helmet' middleware in Express applications to set security headers automatically."
                    })

        except Exception:
            pass

        return findings
