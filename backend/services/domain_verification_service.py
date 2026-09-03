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


def check_domain_submission_rate_limit(db, user_id: int, max_limit: int = 3) -> bool:
    """
    Checks if a user has reached their daily limit of domain submissions (e.g. max 3 in 24 hours).
    Returns True if allowed, False if limit is exceeded.
    """
    if not user_id:
        return True
    cutoff = datetime.now(timezone.utc) - timedelta(days=1)
    attempts_count = db.query(DomainAuditLog).filter(
        DomainAuditLog.user_id == user_id,
        DomainAuditLog.timestamp >= cutoff,
        DomainAuditLog.result.in_(["SUBMITTED", "VERIFIED", "SUBMITTED_EXISTING"])
    ).count()
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
    Verifies domain ownership via DNS TXT record lookup.
    Checks '_nkat-challenge.<domain>' and '<domain>'.
    """
    challenge_domain = f"_nkat-challenge.{domain}"
    domains_to_check = [challenge_domain, domain]

    # Attempt dnspython if installed
    try:
        import dns.resolver
        for target in domains_to_check:
            try:
                answers = dns.resolver.resolve(target, "TXT")
                for rdata in answers:
                    txt_val = "".join([b.decode("utf-8") if isinstance(b, bytes) else str(b) for b in rdata.strings])
                    if expected_token in txt_val:
                        return True, f"Verified DNS TXT record at '{target}'"
            except Exception:
                continue
    except ImportError:
        pass

    # Standard socket fallback / query
    import socket
    for target in domains_to_check:
        try:
            records = socket.gethostbyname_ex(target)
            if any(expected_token in str(r) for r in records):
                return True, f"Verified DNS record for '{target}'"
        except Exception:
            continue

    return False, (
        f"DNS TXT record matching '{expected_token}' not found on "
        f"'{challenge_domain}' or '{domain}'. Please set TXT record to '{expected_token}'."
    )


def verify_file_ownership(target_url_or_domain: str, expected_token: str) -> Tuple[bool, str]:
    """
    Verifies domain ownership by fetching /.well-known/nkat-verification.txt via HTTP GET.
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
    with httpx.Client(timeout=8.0, verify=False, follow_redirects=True) as client:
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

