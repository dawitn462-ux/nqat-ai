"""
Hardened Async HTTP/HTTPS Scanner Client.
Integrates strict ScopeValidator guardrails and TLS/SSL support on every outbound request.
"""

import asyncio
import time
import os
import ssl
from typing import Dict, Any, Optional
import httpx
from dotenv import load_dotenv

from scanner.scope import ScopeValidator
from scanner.models import HTTPRequest, HTTPResponse
from scanner.exceptions import RequestEngineError, ScopeViolationError

load_dotenv()


class AsyncScannerClient:
    """
    Async HTTP/HTTPS request client bounded by strict target scope enforcement,
    TLS/SSL context management, concurrency controls, and configurable timeouts.
    """

    def __init__(
        self,
        scope_validator: Optional[ScopeValidator] = None,
        max_concurrency: Optional[int] = None,
        timeout_seconds: Optional[float] = None,
        retries: Optional[int] = None,
        user_agent: Optional[str] = None,
        ssl_verify: bool = False,
    ):
        self.scope_validator = scope_validator or ScopeValidator()

        concurrency_val = int(os.getenv("MAX_CONCURRENCY", "5"))
        self.max_concurrency = max_concurrency or concurrency_val
        self.semaphore = asyncio.Semaphore(self.max_concurrency)

        timeout_val = float(os.getenv("SCAN_TIMEOUT", "30"))
        self.timeout = timeout_seconds or timeout_val

        retries_val = int(os.getenv("REQUEST_RETRIES", "3"))
        self.retries = retries or retries_val

        self.user_agent = user_agent or "NKAT-AI-SecurityScanner/1.0 (HTTPS Audit)"
        self.headers = {"User-Agent": self.user_agent, "Accept": "*/*"}
        self.ssl_verify = ssl_verify
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        # Configure SSL context for local HTTPS test targets
        ssl_context = ssl.create_default_context()
        if not self.ssl_verify:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            headers=self.headers,
            follow_redirects=True,
            verify=ssl_context if not self.ssl_verify else True,
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.aclose()
            self._client = None

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        json_data: Optional[Dict[str, Any]] = None,
    ) -> HTTPResponse:
        """
        Executes an HTTP/HTTPS request after enforcing mandatory scope validation.
        """
        # Mandatory scope validation before dispatching request
        self.scope_validator.validate_url(url)

        if not self._client:
            raise RequestEngineError("AsyncScannerClient must be used within an 'async with' context.")

        req_headers = {**self.headers, **(headers or {})}

        async with self.semaphore:
            last_exception = None
            for attempt in range(self.retries + 1):
                try:
                    start_time = time.monotonic()
                    res = await self._client.request(
                        method=method.upper(),
                        url=url,
                        headers=req_headers,
                        params=params,
                        content=body.encode("utf-8") if body else None,
                        json=json_data,
                    )
                    elapsed_ms = (time.monotonic() - start_time) * 1000.0

                    return HTTPResponse(
                        url=str(res.url),
                        status_code=res.status_code,
                        headers=dict(res.headers),
                        body=res.text,
                        elapsed_ms=round(elapsed_ms, 2),
                    )
                except httpx.RequestError as exc:
                    last_exception = exc
                    if attempt < self.retries:
                        await asyncio.sleep(0.2 * (attempt + 1))
                    else:
                        raise RequestEngineError(
                            f"HTTP/HTTPS request to '{url}' failed after {self.retries + 1} attempts: {exc}"
                        ) from exc

            raise RequestEngineError(f"HTTP/HTTPS request failed: {last_exception}")

    async def get(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("DELETE", url, **kwargs)
