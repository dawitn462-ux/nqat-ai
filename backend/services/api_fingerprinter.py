"""
API Endpoint Fingerprinting Service — Mission 21 Part 2
-------------------------------------------------------
Inspects discovered endpoints by analyzing HTTP Content-Type headers,
JSON body structures, and URI path conventions to distinguish
"API Issue" (REST/JSON API) from "Web Page Issue" (HTML/Static Page).
"""

import json
import re
from typing import Dict, Any, Tuple
import httpx


def fingerprint_endpoint(url: str, response_headers: Dict[str, str] = None, response_body: str = None) -> Tuple[bool, str]:
    """
    Fingerprints an endpoint URL to determine if it is a JSON/REST API or a standard Web Page.
    Returns (is_api_endpoint: bool, category_label: str)
    e.g. (True, "API Issue") or (False, "Web Page Issue").
    """
    url_lower = (url or "").lower()

    # 1. URI Path pattern check
    api_path_patterns = [
        r"/api/", r"/rest/", r"/v1/", r"/v2/", r"/graphql", r"/swagger", r"/api-docs",
        r"\.json$", r"/user/login", r"/products/search", r"/auth/"
    ]
    path_matches_api = any(re.search(pat, url_lower) for pat in api_path_patterns)

    # 2. Response Headers check
    headers_lower = {k.lower(): str(v).lower() for k, v in (response_headers or {}).items()}
    content_type = headers_lower.get("content-type", "")

    is_json_content_type = any(ct in content_type for ct in [
        "application/json", "application/ld+json", "application/hal+json", "application/vnd.api+json"
    ])

    # 3. Response Body JSON structure check
    is_json_body = False
    if response_body:
        body_trimmed = response_body.strip()
        if (body_trimmed.startswith("{") and body_trimmed.endswith("}")) or (body_trimmed.startswith("[") and body_trimmed.endswith("]")):
            try:
                parsed = json.loads(body_trimmed)
                if isinstance(parsed, (dict, list)):
                    is_json_body = True
            except Exception:
                pass

    # If headers or body indicate JSON, or if path matches API pattern with non-HTML content
    if is_json_content_type or is_json_body or (path_matches_api and "text/html" not in content_type):
        return True, "API Issue"

    # Fallback live fetch if headers/body were not provided
    if response_headers is None and response_body is None and url_lower.startswith(("http://", "https://")):
        try:
            with httpx.Client(timeout=3.0, verify=False, follow_redirects=True) as client:
                resp = client.get(url)
                ct = resp.headers.get("content-type", "").lower()
                if "application/json" in ct or ct.startswith("application/"):
                    return True, "API Issue"
                try:
                    json.loads(resp.text)
                    return True, "API Issue"
                except Exception:
                    pass
        except Exception:
            pass

    return False, "Web Page Issue"
