"""
Target Authorization & SSRF Prevention Module — NQAT AI Enterprise Security Platform
-------------------------------------------------------------------------------------
Enforces strict target authorization, DNS resolution validation, DNS rebinding defenses,
and SSRF prevention before any scan job or active security probe is dispatched.
"""

import ipaddress
import socket
import logging
from typing import Dict, Any, List, Optional, Tuple, Set
from urllib.parse import urlparse
from datetime import datetime, timezone
from sqlalchemy.orm import Session
import httpx

from backend.models import DomainTarget, DomainVerificationStatus, TargetStatus
from scanner.target_parser import TargetParser
from scanner.exceptions import ScopeViolationError

logger = logging.getLogger("nkat.target_authorization")

# Cloud metadata addresses and hostnames
PROHIBITED_METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "100.100.100.200",  # Alibaba cloud metadata
    "fd00:ec2::254",    # AWS IPv6 metadata
}


class TargetAuthorizationError(Exception):
    """Raised when target authorization validation fails."""
    pass


class SSRFSecurityError(TargetAuthorizationError):
    """Raised when target resolves to an unauthorized internal or metadata IP."""
    pass


def parse_and_normalize_url(url: str) -> Tuple[str, str, int, str]:
    """
    Normalizes URL and extracts (normalized_url, hostname, port, scheme).
    """
    clean_url = (url or "").strip().rstrip("/")
    if not clean_url:
        raise TargetAuthorizationError("Target URL cannot be empty.")

    if not clean_url.startswith(("http://", "https://")):
        clean_url = f"http://{clean_url}"

    parsed = urlparse(clean_url)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise TargetAuthorizationError(f"Unsupported URL scheme '{scheme}'. Only HTTP and HTTPS are permitted.")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise TargetAuthorizationError(f"Invalid URL: missing hostname in '{url}'.")

    port = parsed.port or (443 if scheme == "https" else 80)
    normalized = f"{scheme}://{hostname}:{port}" if parsed.port else f"{scheme}://{hostname}"
    return normalized, hostname, port, scheme


def resolve_dns_ips(hostname: str) -> List[str]:
    """
    Resolves hostname to all associated IPv4 and IPv6 addresses.
    """
    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = list(set(item[4][0] for item in addr_info))
        return ips
    except socket.gaierror as exc:
        raise TargetAuthorizationError(f"DNS resolution failed for hostname '{hostname}': {exc}")
    except Exception as exc:
        raise TargetAuthorizationError(f"DNS lookup error for hostname '{hostname}': {exc}")


def is_ip_restricted(ip_str: str) -> Tuple[bool, str]:
    """
    Evaluates whether an IP address belongs to private, loopback, link-local,
    multicast, reserved, or cloud metadata ranges.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, f"Invalid IP address format: {ip_str}"

    if ip_str in PROHIBITED_METADATA_HOSTS:
        return True, "Cloud metadata endpoint"

    if ip_obj.is_loopback:
        return True, "Loopback destination (127.0.0.0/8, ::1)"

    if ip_obj.is_private:
        return True, "Private RFC 1918 network destination"

    if ip_obj.is_link_local:
        return True, "Link-local destination (169.254.0.0/16)"

    if ip_obj.is_multicast:
        return True, "Multicast destination"

    if ip_obj.is_reserved:
        return True, "Reserved IP space"

    if getattr(ip_obj, "is_unspecified", False):
        return True, "Unspecified destination (0.0.0.0, ::)"

    return False, "Public IP"


def is_authorized_lab_target(target_clean: str, hostname: str, port: int) -> bool:
    """
    Checks if target is an explicitly approved isolated laboratory environment.
    """
    lab_hosts = {"localhost", "127.0.0.1", "::1"}
    if hostname in lab_hosts:
        # Check if in docs/AUTHORIZED_TARGETS.md policy document
        try:
            auth_targets = TargetParser.get_authorized_targets()
            for auth in auth_targets:
                auth_norm, a_host, a_port, _ = parse_and_normalize_url(auth)
                if (a_host in lab_hosts and a_port == port) or (auth.rstrip("/") == target_clean):
                    return True
        except Exception:
            pass

    return False


def validate_and_authorize_target(
    target_url: str,
    db: Optional[Session] = None,
    org_id: Optional[int] = None,
    allow_lab_exceptions: bool = True
) -> Dict[str, Any]:
    """
    Full target authorization and SSRF validation gate.
    1. Normalizes URL and validates scheme/hostname.
    2. Checks authorization policy:
       - Registered and verified DomainTarget in DB, OR
       - Explicitly authorized laboratory target in docs/AUTHORIZED_TARGETS.md.
    3. Resolves DNS and checks all resulting IPs against SSRF boundaries.
    4. Returns authorization context dict with target details, verified status, and resolved IPs.
    """
    normalized_url, hostname, port, scheme = parse_and_normalize_url(target_url)

    is_lab = is_authorized_lab_target(normalized_url, hostname, port)
    is_authorized = False
    auth_source = None
    target_record_id = None

    # 1. Check database domain verification if DB provided
    if db is not None:
        from backend.services.domain_verification_service import normalize_domain, is_domain_verified_and_active

        domain_name, _ = normalize_domain(hostname)
        query = db.query(DomainTarget).filter(DomainTarget.domain == domain_name)
        if org_id is not None:
            query = query.filter(DomainTarget.organization_id == org_id)

        matched_target = query.first()
        if matched_target:
            if matched_target.status == DomainVerificationStatus.VERIFIED.value:
                if not is_domain_verified_and_active(matched_target):
                    matched_target.status = DomainVerificationStatus.EXPIRED.value
                    db.commit()
                    raise TargetAuthorizationError(
                        f"Target '{target_url}' verification has EXPIRED (>30 days). Mandatory re-verification is required."
                    )
                if matched_target.target_status in (TargetStatus.BLOCKED.value, TargetStatus.REVOKED.value):
                    raise TargetAuthorizationError(f"Target '{target_url}' is marked as {matched_target.target_status}.")

                is_authorized = True
                auth_source = "DATABASE_VERIFIED_DOMAIN"
                target_record_id = matched_target.id

    # 2. Check static authorization policy (docs/AUTHORIZED_TARGETS.md)
    if not is_authorized:
        try:
            auth_targets = TargetParser.get_authorized_targets()
            for auth in auth_targets:
                a_norm, a_host, a_port, _ = parse_and_normalize_url(auth)
                if a_norm == normalized_url or (a_host == hostname and a_port == port):
                    is_authorized = True
                    auth_source = "POLICY_AUTHORIZED_TARGETS"
                    break
        except Exception as exc:
            logger.debug(f"Static policy parse notice: {exc}")

    if not is_authorized:
        raise TargetAuthorizationError(
            f"Target '{target_url}' is NOT authorized for scanning. "
            f"Mandatory ownership verification (DNS TXT or File check) is required prior to scanning."
        )

    # 3. Resolve DNS and validate IPs
    resolved_ips = resolve_dns_ips(hostname)
    if not resolved_ips:
        raise TargetAuthorizationError(f"DNS resolution returned no IP addresses for '{hostname}'.")

    for ip_str in resolved_ips:
        restricted, reason = is_ip_restricted(ip_str)
        if restricted:
            if is_lab and allow_lab_exceptions:
                logger.info(f"Target '{hostname}' ({ip_str}) matches authorized laboratory exception: {reason}")
            else:
                raise SSRFSecurityError(
                    f"SSRF Protection: Target '{hostname}' resolved to prohibited address {ip_str} ({reason}). "
                    f"Scanning internal network boundaries, loopback, and cloud metadata is strictly forbidden."
                )

    return {
        "target_url": normalized_url,
        "hostname": hostname,
        "port": port,
        "scheme": scheme,
        "resolved_ips": resolved_ips,
        "is_lab_target": is_lab,
        "authorization_source": auth_source,
        "target_record_id": target_record_id,
        "authorized_at": datetime.now(timezone.utc).isoformat()
    }


def validate_redirect_target(request: httpx.Request, allowed_hosts: Set[str], allow_lab: bool = False):
    """
    Event hook for httpx to inspect redirect URLs and block redirects from escaping the authorized scope.
    """
    redirect_url = str(request.url)
    try:
        _, redirect_host, _, _ = parse_and_normalize_url(redirect_url)
    except Exception as exc:
        raise SSRFSecurityError(f"Redirect escaped to invalid URL: {exc}")

    if redirect_host not in allowed_hosts:
        raise SSRFSecurityError(
            f"Redirect scope violation: Connection redirected from authorized scope to unauthorized host '{redirect_host}'."
        )

    # Re-validate DNS of redirect host
    ips = resolve_dns_ips(redirect_host)
    for ip_str in ips:
        restricted, reason = is_ip_restricted(ip_str)
        if restricted and not allow_lab:
            raise SSRFSecurityError(
                f"Redirect SSRF violation: Redirect destination '{redirect_host}' resolved to restricted IP {ip_str} ({reason})."
            )


def create_safe_http_client(
    target_url: str,
    timeout: float = 10.0,
    follow_redirects: bool = True
) -> httpx.Client:
    """
    Creates an httpx client with redirect validation and SSRF boundary protections.
    """
    _, host, _, _ = parse_and_normalize_url(target_url)
    allowed_hosts = {host, "localhost", "127.0.0.1"} if host in ("localhost", "127.0.0.1") else {host}
    is_lab = host in ("localhost", "127.0.0.1")

    def on_redirect_hook(response: httpx.Response):
        if response.is_redirect and "location" in response.headers:
            loc = response.headers["location"]
            # Build full URL if relative
            if loc.startswith("/"):
                loc = f"{response.url.scheme}://{response.url.netloc}{loc}"
            try:
                _, loc_host, _, _ = parse_and_normalize_url(loc)
                if loc_host not in allowed_hosts:
                    raise SSRFSecurityError(f"Redirect escaped to unauthorized host: {loc_host}")
            except Exception as exc:
                raise SSRFSecurityError(f"Redirect validation failed: {exc}")

    return httpx.Client(
        timeout=timeout,
        verify=False,
        follow_redirects=follow_redirects,
        event_hooks={"response": [on_redirect_hook]}
    )
