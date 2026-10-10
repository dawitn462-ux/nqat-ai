import os
import sys
import json
import logging
import subprocess
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scanner.scope import ScopeValidator

logger = logging.getLogger("nkat.katana")
KATANA_PATH = os.path.join(PROJECT_ROOT, "katana.exe")


def get_katana_info() -> Dict[str, Any]:
    """
    Checks if Katana binary is present and returns version info.
    """
    if not os.path.exists(KATANA_PATH):
        return {"available": False, "version": None, "path": KATANA_PATH}

    try:
        res = subprocess.run(
            [KATANA_PATH, "-version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5
        )
        ver = "v1.7.0"
        out = (res.stdout or "") + (res.stderr or "")
        for line in out.splitlines():
            if "version:" in line.lower():
                ver = line.split(":")[-1].strip()
                break
        return {"available": True, "version": ver, "path": KATANA_PATH}
    except Exception as exc:
        logger.warning(f"Error checking Katana version: {exc}")
        return {"available": True, "version": "v1.7.0", "path": KATANA_PATH}


def run_katana_structured_crawl(
    target_url: str,
    depth: int = 2,
    crawl_duration: int = 10,
    headless: bool = False,
    automatic_form_fill: bool = True,
    known_files: str = "all",
    custom_headers: dict = None,
    output_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Executes katana.exe binary with JSON output (-j) to collect rich endpoint metadata:
    URLs, HTTP methods, content types, status codes, and discovery sources.
    """
    clean_target = target_url.rstrip("/")
    if not os.path.exists(KATANA_PATH):
        logger.warning(f"Katana binary not found at '{KATANA_PATH}'. Skipping deep crawl.")
        return {
            "status": "TOOL_UNAVAILABLE",
            "urls": [clean_target],
            "endpoints": [{"url": clean_target, "method": "GET", "discovery_source": "seed"}],
            "total_discovered": 1
        }

    cmd = [
        KATANA_PATH,
        "-u", target_url,
        "-jc",
        "-jsl",
        "-d", str(depth),
        "-ct", str(crawl_duration),
        "-no-color",
        "-duc",
        "-j",
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

    scope_validator = ScopeValidator(target_url=target_url)
    discovered_endpoints: List[Dict[str, Any]] = []
    discovered_urls: List[str] = [clean_target]
    seen_urls = {clean_target}
    exit_code = 0
    err_msg = None

    try:
        res = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=crawl_duration + 15,
        )
        exit_code = res.returncode
        raw_output = res.stdout or ""

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                item = json.loads(line)
                req = item.get("request", {})
                resp = item.get("response", {})
                url_str = req.get("endpoint") or item.get("endpoint") or item.get("url")
                if not url_str and isinstance(item, dict):
                    url_str = item.get("output")

                if not url_str or not url_str.startswith(("http://", "https://")):
                    continue

                clean_u = url_str.rstrip("/")
                if clean_u not in seen_urls and scope_validator.is_in_scope(clean_u):
                    seen_urls.add(clean_u)
                    discovered_urls.append(clean_u)
                    discovered_endpoints.append({
                        "url": clean_u,
                        "method": req.get("method", "GET").upper(),
                        "status_code": resp.get("status_code"),
                        "content_type": resp.get("headers", {}).get("content-type") or resp.get("content_type"),
                        "discovery_source": item.get("tag") or req.get("tag", "katana_crawler"),
                        "depth": item.get("depth", 1)
                    })
            except json.JSONDecodeError:
                # Fallback text line parse
                url_str = line
                if url_str.startswith(("http://", "https://")):
                    clean_u = url_str.rstrip("/")
                    if clean_u not in seen_urls and scope_validator.is_in_scope(clean_u):
                        seen_urls.add(clean_u)
                        discovered_urls.append(clean_u)
                        discovered_endpoints.append({
                            "url": clean_u,
                            "method": "GET",
                            "discovery_source": "katana_text"
                        })

    except subprocess.TimeoutExpired:
        logger.warning(f"Katana crawl timed out after {crawl_duration + 15}s.")
        exit_code = 124
        err_msg = "Katana crawl timed out"
    except Exception as exc:
        logger.warning(f"Katana execution warning: {exc}")
        exit_code = 1
        err_msg = str(exc)

    return {
        "status": "COMPLETED" if exit_code == 0 else ("TIMED_OUT" if exit_code == 124 else "FAILED"),
        "urls": discovered_urls,
        "endpoints": discovered_endpoints,
        "total_discovered": len(discovered_urls),
        "exit_code": exit_code,
        "error": err_msg
    }


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
    Backward-compatible wrapper returning deduplicated list of in-scope URLs.
    """
    res = run_katana_structured_crawl(
        target_url=target_url,
        depth=depth,
        crawl_duration=crawl_duration,
        headless=headless,
        automatic_form_fill=automatic_form_fill,
        known_files=known_files,
        custom_headers=custom_headers
    )
    return res.get("urls", [target_url.rstrip("/")])

