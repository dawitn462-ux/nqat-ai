"""
Wordlist-Based Backup & Hidden File Discovery Check (SecLists Integration).
Scans for exposed backup archives, configuration files, and hidden endpoints
using SecLists raft-large-files.txt and common.txt dictionaries.
"""

import os
import sys
from typing import List, Dict, Set
from urllib.parse import urljoin
from scanner.checks.base import BaseCheck
from scanner.models import HTTPResponse, VulnerabilityFinding, Severity
from scanner.exceptions import RequestEngineError, ScopeViolationError

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WORDLIST_DIR = os.path.join(PROJECT_ROOT, "data", "wordlists", "SecLists", "Discovery", "Web-Content")

RAFT_LARGE_PATH = os.path.join(WORDLIST_DIR, "raft-large-files.txt")
COMMON_PATH = os.path.join(WORDLIST_DIR, "common.txt")

# High risk backup extensions & critical files
HIGH_RISK_EXTENSIONS = {".bak", ".zip", ".tar.gz", ".tgz", ".7z", ".old", ".save", ".env", ".config", ".sql", ".db", ".log", ".key"}


def load_wordlist_candidates(max_entries: int = 500) -> List[str]:
    """
    Loads candidate paths from SecLists raft-large-files.txt and common.txt.
    Returns a prioritized, deduplicated list of relative paths.
    """
    candidates: Set[str] = set()

    for wordlist_path in (RAFT_LARGE_PATH, COMMON_PATH):
        if os.path.exists(wordlist_path):
            try:
                with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if not line.startswith("/"):
                            line = "/" + line
                        candidates.add(line)
                        if len(candidates) >= max_entries:
                            break
            except Exception as exc:
                sys.stderr.write(f"[!] Error reading wordlist '{wordlist_path}': {exc}\n")

    # High-priority backup fallback defaults if wordlists are small or missing
    fallback_defaults = [
        "/.env", "/.git/config", "/backup.zip", "/database.sql", "/dump.sql",
        "/config.bak", "/app.bak", "/index.php.bak", "/server.log", "/db.sqlite"
    ]
    for fb in fallback_defaults:
        candidates.add(fb)

    # Sort candidates prioritizing high-risk extensions and critical paths first
    def priority_key(path: str) -> int:
        lower = path.lower()
        if any(lower.endswith(ext) for ext in HIGH_RISK_EXTENSIONS) or ".git" in lower or ".env" in lower:
            return 0
        return 1

    sorted_candidates = sorted(list(candidates), key=priority_key)
    return sorted_candidates[:max_entries]


class BackupDiscoveryCheck(BaseCheck):
    check_id = "BACKUP_DISCOVERY_001"
    name = "Wordlist-Based Backup & Hidden File Discovery"
    description = "Discovers hidden files, backup archives (.bak, .zip, .sql, .env), and sensitive endpoints using SecLists dictionaries."

    async def run(
        self, target_url: str, responses: Dict[str, HTTPResponse]
    ) -> List[VulnerabilityFinding]:
        import asyncio
        findings: List[VulnerabilityFinding] = []
        base_url = target_url.rstrip("/")
        candidates = load_wordlist_candidates(max_entries=50)

        async def probe_candidate(rel_path: str):
            probe_url = urljoin(base_url, rel_path)
            if not self.client.scope_validator.is_in_scope(probe_url):
                return None
            try:
                res = await self.client.get(probe_url)
                if res.status_code == 200 and len(res.body) > 15:
                    body_lower = res.body.lower()
                    if "<html" in body_lower and ("page not found" in body_lower or "404" in body_lower or "error" in body_lower):
                        return None
                    ext = os.path.splitext(rel_path.lower())[1]
                    severity = Severity.HIGH if (ext in HIGH_RISK_EXTENSIONS or "env" in rel_path.lower() or "sql" in rel_path.lower()) else Severity.MEDIUM
                    return VulnerabilityFinding(
                        id=f"{self.check_id}_{rel_path.upper().replace('/', '_').replace('.', '_')}",
                        title=f"Exposed Backup or Sensitive File Discovered ({rel_path})",
                        severity=severity,
                        description=f"Wordlist discovery revealed an exposed file at '{probe_url}' using SecLists web-content dictionaries.",
                        endpoint=probe_url,
                        evidence=f"HTTP 200 OK | Size: {len(res.body)} bytes | Path: {rel_path}",
                        cwe="CWE-530",
                        remediation=f"Remove or restrict access to exposed file '{rel_path}' on production web server.",
                    )
            except Exception:
                return None
            return None

        results = await asyncio.gather(*[probe_candidate(p) for p in candidates], return_exceptions=True)
        for r in results:
            if isinstance(r, VulnerabilityFinding):
                findings.append(r)

        return findings
