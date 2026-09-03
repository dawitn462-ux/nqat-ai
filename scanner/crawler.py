"""
Scope-Enforced Web and API Endpoint Crawler.
Discovers pages, forms, and API routes on target test environments.
"""

import re
from typing import Set, List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from scanner.client import AsyncScannerClient
from scanner.models import HTTPResponse
from scanner.exceptions import ScopeViolationError, RequestEngineError


class EndpointCrawler:
    """
    Crawls target web application and API endpoints bounded strictly by scope rules.
    """

    KNOWN_API_ROUTES = [
        "/",
        "/#/login",
        "/#/register",
        "/#/search",
        "/#/score-board",
        "/rest/user/login",
        "/rest/products/search?q=",
        "/rest/admin/application-configuration",
        "/api/Challenges",
        "/api/Quantitys",
        "/api-docs",
        "/swagger-ui",
        "/ftp",
        "/assets",
        "/redirect",
    ]

    def __init__(self, client: AsyncScannerClient, max_depth: int = 2, max_pages: int = 25):
        self.client = client
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: Set[str] = set()
        self.responses: Dict[str, HTTPResponse] = {}

    async def crawl(self, start_url: str) -> Dict[str, HTTPResponse]:
        """
        Main crawling execution method.
        """
        # First populate known API routes relative to start_url
        base = start_url.rstrip("/")
        for route in self.KNOWN_API_ROUTES:
            full_url = urljoin(base, route)
            if self.client.scope_validator.is_in_scope(full_url):
                self.discovered_endpoints.add(full_url)

        queue = [(start_url, 0)]
        self.discovered_endpoints.add(start_url)

        while queue and len(self.visited_urls) < self.max_pages:
            current_url, depth = queue.pop(0)

            if current_url in self.visited_urls:
                continue

            # Scope check safety gate
            if not self.client.scope_validator.is_in_scope(current_url):
                continue

            self.visited_urls.add(current_url)

            try:
                res = await self.client.get(current_url)
                self.responses[current_url] = res

                if depth < self.max_depth and "text/html" in res.headers.get("content-type", "").lower():
                    links = self._extract_links(current_url, res.body)
                    for link in links:
                        if (
                            link not in self.visited_urls
                            and self.client.scope_validator.is_in_scope(link)
                        ):
                            self.discovered_endpoints.add(link)
                            queue.append((link, depth + 1))
            except (RequestEngineError, ScopeViolationError):
                continue

        return self.responses

    def _extract_links(self, base_url: str, html_content: str) -> Set[str]:
        """
        Parses HTML links, form actions, and script references.
        """
        extracted = set()
        try:
            soup = BeautifulSoup(html_content, "html.parser")

            # Extract <a> hrefs
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                    extracted.add(urljoin(base_url, href))

            # Extract <form> actions
            for form in soup.find_all("form", action=True):
                action = form["action"].strip()
                if action:
                    extracted.add(urljoin(base_url, action))

            # Extract <script> src attributes
            for script in soup.find_all("script", src=True):
                src = script["src"].strip()
                if src:
                    extracted.add(urljoin(base_url, src))

            # Regex search for API endpoints in inline JS
            js_routes = re.findall(r'["\'](/(?:api|rest|ftp|assets)/[a-zA-Z0-9_\-/\?=]+)["\']', html_content)
            for r in js_routes:
                extracted.add(urljoin(base_url, r))

        except Exception:
            pass

        return extracted
