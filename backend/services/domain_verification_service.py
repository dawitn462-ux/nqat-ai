"""
Domain Ownership Verification Service.
Provides domain normalization, verification token generation, DNS TXT verification,
and HTTP file-based verification for scoped target authorization.
"""

import os
import sys
import secrets
from datetime import datetime, timedelta, timezone
from typing import Tuple, Optional
from urllib.parse import urlparse
import httpx

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.models import DomainTarget, DomainVerificationStatus, DomainVerificationMethod, DomainAuditLog


def get_user_domain_submission_count_24h(db, user_id: int) -> int:
    """
    Returns the count of domain submission attempts for a specific user in the past 24 hours.
    Strictly isolated per user_id.
    """
    if not user_id:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=1)
    return db.query(DomainAuditLog).filter(
        DomainAuditLog.user_id == user_id,
        DomainAuditLog.timestamp >= cutoff,
        DomainAuditLog.result.in_(["SUBMITTED", "VERIFIED", "SUBMITTED_EXISTING"])
    ).count()


def check_domain_submission_rate_limit(db, user_id: int, max_limit: int = 3) -> bool:
    """
    Enforces daily rate limit of max_limit (3) domain target submissions / challenge token requests
    SEPARATELY FOR EACH INDIVIDUAL USER (user_id) per 24 hours.
    Returns True if allowed, False if limit is exceeded.
    """
    if not user_id:
        return True
    attempts_count = get_user_domain_submission_count_24h(db, user_id=user_id)
    return attempts_count < max_limit


def log_domain_audit(
    db,
    user_id: Optional[int],
    domain: str,
    method: str,
    result: str,
    details: Optional[str] = None
) -> DomainAuditLog:
    """
    Logs every domain submission or verification attempt with user_id, domain, method, timestamp, result.
    """
    audit_rec = DomainAuditLog(
        user_id=user_id,
        domain=domain,
        method=method or DomainVerificationMethod.DNS_TXT.value,
        timestamp=datetime.now(timezone.utc),
        result=result,
        details=details
    )
    db.add(audit_rec)
    db.commit()
    db.refresh(audit_rec)
    return audit_rec



def normalize_domain(raw_input: str) -> Tuple[str, str]:
    """
    Parses a raw URL or domain string.
    Returns a tuple of (clean_domain_hostname, clean_target_url).
    Example: "https://example.com:8080/test" -> ("example.com", "https://example.com:8080")
             "sub.example.com" -> ("sub.example.com", "http://sub.example.com")
    """
    raw = (raw_input or "").strip()
    if not raw.startswith("http://") and not raw.startswith("https://"):
        url_str = "http://" + raw
    else:
        url_str = raw

    parsed = urlparse(url_str)
    hostname = parsed.hostname or parsed.path.split("/")[0].split(":")[0]
    hostname = hostname.lower().strip()

    scheme = parsed.scheme if parsed.scheme in ("http", "https") else "http"
    port_str = f":{parsed.port}" if parsed.port else ""
    target_url = f"{scheme}://{hostname}{port_str}"

    return hostname, target_url


def generate_verification_token() -> str:
    """
    Generates a cryptographically secure random verification token.
    """
    return f"nkat-verify-{secrets.token_hex(16)}"


def verify_dns_txt_ownership(domain: str, expected_token: str) -> Tuple[bool, str]:
    """
    Verifies domain ownership via real DNS TXT record lookup across multiple live resolvers:
    1. dnspython library (if installed)
    2. Google DNS-over-HTTPS (DoH) REST API (https://dns.google/resolve)
    3. Cloudflare DNS-over-HTTPS (DoH) REST API (https://cloudflare-dns.com/dns-query)
    4. System nslookup subprocess tool fallback
    """
    challenge_domain = f"_nkat-challenge.{domain}"
    domains_to_check = [challenge_domain, domain]
    doh_headers = {"Accept": "application/dns-json", "User-Agent": "NKAT-Domain-Verification-Agent/1.0"}

    # 1. Attempt dnspython if installed
    try:
        import dns.resolver
        for target in domains_to_check:
            try:
                answers = dns.resolver.resolve(target, "TXT")
                for rdata in answers:
                    txt_val = "".join([b.decode("utf-8") if isinstance(b, bytes) else str(b) for b in rdata.strings])
                    if expected_token in txt_val:
                        return True, f"Verified DNS TXT record at '{target}' via dnspython"
            except Exception:
                continue
    except ImportError:
        pass

    # 2. Check via Google DNS-over-HTTPS (DoH) REST API
    try:
        with httpx.Client(timeout=6.0, verify=False) as client:
            for target in domains_to_check:
                try:
                    resp = client.get(f"https://dns.google/resolve?name={target}&type=TXT", headers=doh_headers)
                    if resp.status_code == 200:
                        data = resp.json()
                        answers = data.get("Answer", [])
                        for ans in answers:
                            txt_data = str(ans.get("data", ""))
                            if expected_token in txt_data:
                                return True, f"Verified DNS TXT record at '{target}' via Google DNS (DoH)"
                except Exception:
                    continue
    except Exception:
        pass

    # 3. Check via Cloudflare DNS-over-HTTPS (DoH) REST API
    try:
        with httpx.Client(timeout=6.0, verify=False) as client:
            for target in domains_to_check:
                try:
                    resp = client.get(f"https://cloudflare-dns.com/dns-query?name={target}&type=TXT", headers=doh_headers)
                    if resp.status_code == 200:
                        data = resp.json()
                        answers = data.get("Answer", [])
                        for ans in answers:
                            txt_data = str(ans.get("data", ""))
                            if expected_token in txt_data:
                                return True, f"Verified DNS TXT record at '{target}' via Cloudflare DNS (DoH)"
                except Exception:
                    continue
    except Exception:
        pass

    # 4. Check via system nslookup command fallback
    import subprocess
    for target in domains_to_check:
        try:
            res = subprocess.run(["nslookup", "-q=TXT", target], capture_output=True, text=True, timeout=5)
            output = res.stdout or ""
            if expected_token in output:
                return True, f"Verified DNS TXT record at '{target}' via system nslookup"
        except Exception:
            continue

    return False, (
        f"DNS TXT record matching '{expected_token}' not found on "
        f"'{challenge_domain}' or '{domain}'. Checked dnspython, Google DoH, Cloudflare DoH, and nslookup. "
        f"Please set a TXT record on '{challenge_domain}' or '{domain}' with value '{expected_token}'."
    )


def verify_file_ownership(target_url_or_domain: str, expected_token: str) -> Tuple[bool, str]:
    """
    Verifies domain ownership by fetching /.well-known/nkat-verification.txt via real HTTP GET.
    """
    hostname, clean_url = normalize_domain(target_url_or_domain)
    
    candidate_urls = [
        f"{clean_url}/.well-known/nkat-verification.txt",
        f"{clean_url}/nkat-verify.txt",
        f"http://{hostname}/.well-known/nkat-verification.txt",
        f"https://{hostname}/.well-known/nkat-verification.txt",
    ]

    seen = set()
    unique_urls = []
    for u in candidate_urls:
        if u not in seen:
            seen.add(u)
            unique_urls.append(u)

    errors = []
    headers = {"User-Agent": "NKAT-Domain-Verification-Agent/1.0"}
    with httpx.Client(timeout=8.0, verify=False, follow_redirects=True, headers=headers) as client:
        for url in unique_urls:
            try:
                resp = client.get(url)
                if resp.status_code == 200 and expected_token in resp.text:
                    return True, f"Verified ownership file at '{url}'"
                else:
                    errors.append(f"{url} (HTTP {resp.status_code})")
            except Exception as exc:
                errors.append(f"{url} ({type(exc).__name__})")

    return False, (
        f"Verification token '{expected_token}' not found at HTTP file endpoints: "
        f"{', '.join(errors)}. Place a text file at /.well-known/nkat-verification.txt containing '{expected_token}'."
    )


def verify_domain_ownership(
    db,
    domain_target_id: int,
    method_override: Optional[str] = None
) -> DomainTarget:
    """
    Performs verification check for a DomainTarget record and updates its status in the DB.
    """
    domain_rec = db.query(DomainTarget).filter(DomainTarget.id == domain_target_id).first()
    if not domain_rec:
        raise ValueError(f"DomainTarget record with ID {domain_target_id} not found.")

    method = method_override or domain_rec.verification_method or DomainVerificationMethod.DNS_TXT.value
    domain_rec.verification_method = method

    # Pre-authorized targets (loopback/localhost) bypass external DNS/file verification
    preauthorized_hosts = ("localhost", "127.0.0.1", "0.0.0.0", "::1")
    if domain_rec.domain in preauthorized_hosts or domain_rec.domain.endswith(".localhost"):
        success = True
        message = "Pre-authorized target automatically verified."
    elif method == DomainVerificationMethod.FILE.value:
        target = domain_rec.target_url or domain_rec.domain
        success, message = verify_file_ownership(target, domain_rec.verification_token)
    else:
        success, message = verify_dns_txt_ownership(domain_rec.domain, domain_rec.verification_token)

    if success:
        domain_rec.status = DomainVerificationStatus.VERIFIED.value
        domain_rec.verified_at = datetime.now(timezone.utc)
        domain_rec.last_error = None
    else:
        domain_rec.status = DomainVerificationStatus.FAILED.value
        domain_rec.last_error = message

    db.commit()
    db.refresh(domain_rec)
    return domain_rec


VERIFICATION_EXPIRY_DAYS = 30


def is_domain_verified_and_active(domain_rec: DomainTarget, expiry_days: int = VERIFICATION_EXPIRY_DAYS) -> bool:
    """
    Part 4 — Verification Expiry Check.
    Returns True if domain is VERIFIED and verified_at timestamp is within expiry_days (e.g., 30 days).
    Pre-authorized targets (localhost, owasp.org, etc.) bypass 30-day expiry.
    """
    if not domain_rec:
        return False

    preauthorized_hosts = ("localhost", "127.0.0.1", "0.0.0.0", "::1")
    if domain_rec.domain in preauthorized_hosts or domain_rec.domain.endswith(".localhost"):
        return True

    if domain_rec.status != DomainVerificationStatus.VERIFIED.value:
        return False

    if not domain_rec.verified_at:
        return False

    v_time = domain_rec.verified_at
    if v_time.tzinfo is None:
        v_time = v_time.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    if now - v_time > timedelta(days=expiry_days):
        return False

    return True


def reverify_domain_target(db, domain_rec: DomainTarget, user_id: Optional[int] = None) -> Tuple[bool, str]:
    """
    Part 3 — Re-verification before re-scan execution.
    Re-tests DNS TXT or HTTP File token.
    If missing/failed: sets status FAILED, logs audit trail entry, and returns (False, error).
    If verified: updates verified_at timestamp, logs audit trail entry, and returns (True, success).
    """
    updated_rec = verify_domain_ownership(db, domain_rec.id)
    if updated_rec.status == DomainVerificationStatus.VERIFIED.value:
        log_domain_audit(
            db=db,
            user_id=user_id,
            domain=updated_rec.domain,
            method=updated_rec.verification_method,
            result="REVERIFIED",
            details="Scheduled re-verification check succeeded."
        )
        return True, "Re-verification succeeded."
    else:
        log_domain_audit(
            db=db,
            user_id=user_id,
            domain=updated_rec.domain,
            method=updated_rec.verification_method,
            result="FAILED_REVERIFICATION",
            details=f"Scheduled re-verification check failed: {updated_rec.last_error or 'Challenge token missing or invalid.'}"
        )
        return False, updated_rec.last_error or "Scheduled re-verification check failed."

