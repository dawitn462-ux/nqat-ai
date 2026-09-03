"""
Katana Crawler Service — Mission 21 Part 1
-------------------------------------------
Wraps ProjectDiscovery's Katana binary (katana.exe) to perform deep crawling,
JavaScript endpoint discovery (-jc), and JSLuice extraction (-jsl).
Parses output and returns a list of unique in-scope discovered endpoints.
"""

import os
import sys
import subprocess
from typing import List
from urllib.parse import urlparse

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scanner.scope import ScopeValidator

KATANA_PATH = os.path.join(PROJECT_ROOT, "katana.exe")


def run_katana_crawl(
    target_url: str,
    depth: int = 2,
    crawl_duration: int = 10,
    headless: bool = False,
    automatic_form_fill: bool = True,
    known_files: str = "all",
    custom_headers: dict = None,
) -> List[str]:
    """
    Executes katana.exe binary with advanced crawling flags to discover pages, forms,
    JavaScript endpoints, API routes, and hidden files.
    Returns a deduplicated list of valid, in-scope URLs.
    """
    discovered_urls: List[str] = [target_url.rstrip("/")]

    if not os.path.exists(KATANA_PATH):
        sys.stderr.write(f"[!] Katana binary not found at '{KATANA_PATH}'. Skipping Katana deep crawl.\n")
        return discovered_urls

    cmd = [
        KATANA_PATH,
        "-u", target_url,
        "-jc",
        "-jsl",
        "-d", str(depth),
        "-ct", str(crawl_duration),
        "-no-color",
        "-duc",
    ]

    if automatic_form_fill:
        cmd.append("-aff")

    if known_files:
        cmd.extend(["-kf", known_files])

    if headless:
        cmd.append("-system-chrome")

    if custom_headers:
        for k, v in custom_headers.items():
            cmd.extend(["-H", f"{k}: {v}"])

    try:
        res = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=crawl_duration + 10,
        )

        scope_validator = ScopeValidator(target_url=target_url)
        raw_output = res.stdout or ""

        for line in raw_output.splitlines():
            url_str = line.strip()
            if not url_str or not (url_str.startswith("http://") or url_str.startswith("https://")):
                continue

            # Scope check safety gate
            try:
                if scope_validator.is_in_scope(url_str):
                    discovered_urls.append(url_str.rstrip("/"))
            except Exception:
                continue

    except subprocess.TimeoutExpired:
        sys.stderr.write("[!] Katana crawl timed out.\n")
    except Exception as exc:
        sys.stderr.write(f"[!] Katana execution warning: {exc}\n")

    # Deduplicate preserving order
    seen = set()
    unique_urls = []
    for u in discovered_urls:
        if u not in seen:
            seen.add(u)
            unique_urls.append(u)

    return unique_urls
