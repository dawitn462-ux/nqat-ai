"""
Strict Security Scope Enforcement Module (HTTPS Enforced).
Guards all outbound requests and scanner targets against unauthorized network locations and insecure protocols.
"""

import ipaddress
import os
from urllib.parse import urlparse
from typing import List, Set, Optional
from dotenv import load_dotenv

from scanner.exceptions import ScopeViolationError, ScanConfigError

load_dotenv()


class ScopeValidator:
    """
    Validates target URLs against explicit authorization rules and HTTPS enforcement.
    Prevents SSRF, unauthorized scanning, insecure transport, and out-of-scope requests.
    """

    DEFAULT_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
    ALLOWED_SCHEMES = {"http", "https"}
    ALLOWED_PORTS = {3000, 8443, 80, 443}

    def __init__(
        self,
        target_url: Optional[str] = None,
        allowed_hosts: Optional[List[str]] = None,
        strict_enforcement: Optional[bool] = None,
        enforce_https: Optional[bool] = None,
    ):
        target_url_env = os.getenv("TARGET_URL", "https://localhost:3000")
        self.target_url = target_url or target_url_env
        parsed_target = urlparse(self.target_url)

        if not parsed_target.hostname:
            raise ScanConfigError(f"Invalid TARGET_URL in configuration: '{self.target_url}'")

        self.target_scheme = parsed_target.scheme.lower()
        self.target_host = parsed_target.hostname.lower()
        self.target_port = parsed_target.port or (443 if self.target_scheme == "https" else 80)

        # Parse allowed hosts
        hosts_env = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1,::1")
        configured_hosts = allowed_hosts or [h.strip() for h in hosts_env.split(",") if h.strip()]
        self.allowed_hosts: Set[str] = set(h.lower() for h in configured_hosts)
        self.allowed_hosts.update(self.DEFAULT_ALLOWED_HOSTS)
        if self.target_host:
            self.allowed_hosts.add(self.target_host)

        strict_env = os.getenv("STRICT_SCOPE_ENFORCEMENT", "true").lower() in ("true", "1", "yes")
        self.strict_enforcement = strict_enforcement if strict_enforcement is not None else strict_env

        https_env = os.getenv("ENFORCE_HTTPS", "false").lower() in ("true", "1", "yes")
        self.enforce_https = enforce_https if enforce_https is not None else https_env

    def validate_url(self, url: str) -> bool:
        """
        Validates whether a URL is within authorized scan scope and complies with HTTPS rules.
        Raises ScopeViolationError if out of scope or violating HTTPS enforcement.
        """
        if not url or not isinstance(url, str):
            raise ScopeViolationError(str(url), "URL must be a non-empty string.")

        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()

        # Scheme check
        if scheme not in self.ALLOWED_SCHEMES:
            raise ScopeViolationError(
                url, f"Unauthorized scheme '{scheme}'. Allowed schemes: {self.ALLOWED_SCHEMES}"
            )

        if self.enforce_https and scheme != "https":
            raise ScopeViolationError(
                url, "HTTPS enforcement is enabled. Insecure HTTP scheme is strictly prohibited."
            )

        if not hostname:
            raise ScopeViolationError(url, "URL lacks a valid hostname.")

        # Host check
        if hostname not in self.allowed_hosts:
            try:
                ip_obj = ipaddress.ip_address(hostname)
                if not ip_obj.is_loopback:
                    raise ScopeViolationError(
                        url, f"Host IP '{hostname}' is not a local loopback address."
                    )
            except ValueError:
                raise ScopeViolationError(
                    url,
                    f"Host '{hostname}' is not in authorized host list: {sorted(list(self.allowed_hosts))}",
                )

        # Port check
        port = parsed.port or (443 if scheme == "https" else 80)
        if self.strict_enforcement and port not in self.ALLOWED_PORTS and port != self.target_port:
            raise ScopeViolationError(
                url,
                f"Port {port} is not in authorized target port list ({self.ALLOWED_PORTS}).",
            )

        return True

    def is_in_scope(self, url: str) -> bool:
        """
        Safe boolean check for scope membership without raising exceptions.
        """
        try:
            return self.validate_url(url)
        except ScopeViolationError:
            return False
