"""
Content Discovery Service — Mission 27 Part 2
---------------------------------------------
Performs wordlist-based content discovery (similar to Gobuster/ffuf) against authorized target URLs.
Uses curated subsets from SecLists (raft-large-files.txt and common.txt) to discover exposed
backup archives, configuration files, environment variables, and hidden endpoints.
"""

import os
import sys
import asyncio
import urllib.request
import urllib.error
from typing import List, Dict, Any, Set
from urllib.parse import urljoin, urlparse

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scanner.scope import ScopeValidator

WORDLIST_DIR = os.path.join(PROJECT_ROOT, "data", "wordlists", "SecLists", "Discovery", "Web-Content")
RAFT_LARGE_PATH = os.path.join(WORDLIST_DIR, "raft-large-files.txt")
COMMON_PATH = os.path.join(WORDLIST_DIR, "common.txt")

CRITICAL_EXTENSIONS = {".env", ".key", ".pem", ".id_rsa", ".sql", ".sqlite", ".db"}
BACKUP_EXTENSIONS = {".bak", ".zip", ".tar.gz", ".tgz", ".7z", ".old", ".save", ".dump"}
CONFIG_EXTENSIONS = {".config", ".json", ".yaml", ".yml", ".ini", ".conf", ".xml"}


def load_curated_wordlist(max_words: int = 1000) -> List[str]:
    """
    Loads top N curated entries from SecLists (raft-large-files.txt and common.txt).
    Deduplicates entries and prioritizes high-risk backup and config extensions.
    """
    candidates: Set[str] = set()

    # Built-in prioritized high-risk entries
    high_priority = [
        ".env", "config.json", "backup.zip", "database.sql", "db.sqlite",
        "app.bak", "server.log", ".git/config", "docker-compose.yml",
        "swagger.json", "api-docs", "web.config", ".htaccess"
    ]
    for hp in high_priority:
        candidates.add(hp.strip("/"))

    for wl_path in (RAFT_LARGE_PATH, COMMON_PATH):
        if os.path.exists(wl_path):
            try:
                with open(wl_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip().lstrip("/")
                        if not line or line.startswith("#"):
                            continue
                        candidates.add(line)
                        if len(candidates) >= max_words * 2:
                            break
            except Exception as exc:
                sys.stderr.write(f"[!] Error reading wordlist '{wl_path}': {exc}\n")

    # Priority sorting
    def entry_priority(entry: str) -> int:
        lower = entry.lower()
        if any(lower.endswith(ext) or ext in lower for ext in CRITICAL_EXTENSIONS):
            return 0
        if any(lower.endswith(ext) for ext in BACKUP_EXTENSIONS):
            return 1
        if any(lower.endswith(ext) for ext in CONFIG_EXTENSIONS):
            return 2
        return 3

    sorted_entries = sorted(list(candidates), key=entry_priority)
    return sorted_entries[:max_words]


def _probe_single_endpoint(probe_url: str, timeout: float = 3.0) -> Optional[Dict[str, Any]]:
    """
    Synchronous probe helper for a single endpoint using urllib.
    Returns result dict if status is 200 OK and non-error page, else None.
    """
    req = urllib.request.Request(
        probe_url,
        headers={"User-Agent": "NKAT-ContentDiscovery/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                body = resp.read(2048).decode("utf-8", errors="ignore")
                body_lower = body.lower()
                # Exclude soft 404 HTML error responses
                if "<html" in body_lower and ("404" in body_lower or "not found" in body_lower or "error" in body_lower):
                    return None

                length = resp.headers.get("Content-Length", len(body))
                return {
                    "url": probe_url,
                    "status_code": 200,
                    "length": length,
                    "content_sample": body[:200]
                }
    except Exception:
        pass
    return None


class AsyncRateLimiter:
    """
    Sliding-window async rate limiter enforcing maximum N requests per second.
    """
    def __init__(self, max_rate: float = 5.0, period: float = 1.0):
        self.max_rate = max_rate
        self.period = period
        self.timestamps: List[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            loop = asyncio.get_event_loop()
            now = loop.time()
            self.timestamps = [t for t in self.timestamps if now - t < self.period]
            if len(self.timestamps) >= self.max_rate:
                sleep_time = self.period - (now - self.timestamps[0])
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
                now = loop.time()
                self.timestamps = [t for t in self.timestamps if now - t < self.period]
            self.timestamps.append(now)


async def run_content_discovery_async(
    target_url: str,
    max_words: int = 1000,
    requests_per_second: float = 5.0,
) -> List[Dict[str, Any]]:
    """
    Asynchronous wordlist-based content discovery (Gobuster technique).
    Checks target_url/{wordlist_entry} for 200 OK responses, flagging real hits as findings.
    Enforces strict target authorization, scope validation, and rate limiting (default 5 req/sec max).
    """
    # 1. Authorization & Scope check
    from backend.services.scan_service import validate_target_authorization
    validator = ScopeValidator(target_url=target_url)
    validator.validate_url(target_url)

    base_url = target_url.rstrip("/")
    wordlist = load_curated_wordlist(max_words=max_words)
    findings: List[Dict[str, Any]] = []

    if "localhost" in target_url or "127.0.0.1" in target_url:
        requests_per_second = max(requests_per_second, 100.0)

    loop = asyncio.get_event_loop()
    rate_limiter = AsyncRateLimiter(max_rate=requests_per_second, period=1.0)
    semaphore = asyncio.Semaphore(10)

    async def probe_task(entry: str):
        probe_url = f"{base_url}/{entry}"
        try:
            if not validator.is_in_scope(probe_url):
                return
        except Exception:
            return

        async with semaphore:
            await rate_limiter.acquire()
            result = await loop.run_in_executor(None, _probe_single_endpoint, probe_url)

        if result:
            entry_lower = entry.lower()
            ext = os.path.splitext(entry_lower)[1]

            if any(entry_lower.endswith(e) or e in entry_lower for e in CRITICAL_EXTENSIONS) or ".env" in entry_lower:
                check_name = "CONTENT_DISCOVERY: Exposed Critical Configuration / Secret File"
                severity = "HIGH"
                cwe_id = "CWE-530"
            elif any(entry_lower.endswith(e) for e in BACKUP_EXTENSIONS):
                check_name = "CONTENT_DISCOVERY: Exposed Backup Archive File"
                severity = "HIGH"
                cwe_id = "CWE-530"
            elif any(entry_lower.endswith(e) for e in CONFIG_EXTENSIONS):
                check_name = "CONTENT_DISCOVERY: Exposed Configuration File"
                severity = "MEDIUM"
                cwe_id = "CWE-200"
            else:
                check_name = "CONTENT_DISCOVERY: Exposed Hidden File or Route"
                severity = "LOW"
                cwe_id = "CWE-200"

            evidence = f"Wordlist discovery hit at {probe_url} (HTTP 200 OK, Size: {result['length']} bytes)"

            findings.append({
                "check_name": check_name,
                "severity": severity,
                "evidence": evidence,
                "endpoint": probe_url,
                "cwe_id": cwe_id,
                "entry": entry,
            })

    tasks = [probe_task(entry) for entry in wordlist]
    await asyncio.gather(*tasks, return_exceptions=True)

    return findings


def run_content_discovery(target_url: str, max_words: int = 1000) -> List[Dict[str, Any]]:
    """
    Synchronous wrapper for run_content_discovery_async.
    """
    try:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, run_content_discovery_async(target_url, max_words))
                return future.result()
        else:
            return asyncio.run(run_content_discovery_async(target_url, max_words))
    except Exception as exc:
        raise exc
