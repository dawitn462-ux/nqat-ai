"""
Mission 27 Test Suite — Wordlist-Based Backup & Hidden File Discovery (SecLists Integration)
"""

import os
import sys
import pytest
from unittest.mock import AsyncMock, MagicMock

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scanner.checks.backup_discovery import (
    BackupDiscoveryCheck,
    load_wordlist_candidates,
    RAFT_LARGE_PATH,
    COMMON_PATH,
)
from scanner.models import HTTPResponse


def test_seclists_wordlist_files_exist():
    """Verify SecLists raft-large-files.txt and common.txt files exist on disk."""
    assert os.path.exists(RAFT_LARGE_PATH), f"SecLists raft-large-files.txt missing at {RAFT_LARGE_PATH}"
    assert os.path.exists(COMMON_PATH), f"SecLists common.txt missing at {COMMON_PATH}"
    assert os.path.getsize(RAFT_LARGE_PATH) > 1000
    assert os.path.getsize(COMMON_PATH) > 1000


def test_load_wordlist_candidates():
    """Verify wordlist candidate loader prioritizes critical backup extensions."""
    candidates = load_wordlist_candidates(max_entries=200)
    assert isinstance(candidates, list)
    assert len(candidates) > 0

    # Ensure critical paths like /.env or backup extensions are in candidates
    has_critical = any(".env" in c or ".bak" in c or ".sql" in c or ".zip" in c for c in candidates)
    assert has_critical, "Wordlist candidates should include critical backup/config patterns"


@pytest.mark.asyncio
async def test_backup_discovery_check_execution():
    """Verify BackupDiscoveryCheck detects exposed backup endpoint HTTP 200 OK responses."""
    mock_client = AsyncMock()
    mock_client.scope_validator = MagicMock()
    mock_client.scope_validator.is_in_scope.return_value = True

    # Simulate exposed /.env response
    async def mock_get(url):
        if "/.env" in url or "backup.zip" in url:
            return HTTPResponse(
                url=url,
                status_code=200,
                headers={"content-type": "text/plain"},
                body="DB_PASSWORD=supersecret_123\nAPI_KEY=xyz",
                elapsed=0.05
            )
        return HTTPResponse(url=url, status_code=404, headers={}, body="Not Found", elapsed=0.05)

    mock_client.get.side_effect = mock_get

    check = BackupDiscoveryCheck(mock_client)
    findings = await check.run("http://127.0.0.1:3000", {})

    assert isinstance(findings, list)
    assert len(findings) > 0
    assert any(f.severity.value == "HIGH" for f in findings)
    assert any("Backup" in f.title or "Exposed" in f.title for f in findings)


def test_load_curated_wordlist():
    """Verify content discovery service loads curated SecLists wordlist subset."""
    from backend.services.content_discovery import load_curated_wordlist
    words = load_curated_wordlist(max_words=100)
    assert isinstance(words, list)
    assert len(words) <= 100
    assert len(words) > 0
    assert ".env" in words or "backup.zip" in words or "config.json" in words


@pytest.mark.asyncio
async def test_content_discovery_service_execution():
    """Verify content discovery service probes endpoints and returns structured findings for HTTP 200 hits."""
    from backend.services.content_discovery import run_content_discovery_async
    from unittest.mock import patch

    def mock_probe(url, timeout=3.0):
        if ".env" in url or "config.json" in url:
            return {
                "url": url,
                "status_code": 200,
                "length": 150,
                "content_sample": "SECRET_KEY=12345"
            }
        return None

    with patch("backend.services.content_discovery._probe_single_endpoint", side_effect=mock_probe):
        findings = await run_content_discovery_async("http://localhost:3000", max_words=50)

    assert isinstance(findings, list)
    assert len(findings) >= 1
    f = findings[0]
    assert "check_name" in f
    assert "severity" in f
    assert "evidence" in f
    assert "CONTENT_DISCOVERY" in f["check_name"]


@pytest.mark.asyncio
async def test_rate_limiting_enforcement():
    """Verify AsyncRateLimiter strictly enforces max 5 requests per second."""
    import time
    from backend.services.content_discovery import AsyncRateLimiter

    limiter = AsyncRateLimiter(max_rate=5.0, period=1.0)
    start_t = time.time()

    # Acquire 6 rate tokens
    for _ in range(6):
        await limiter.acquire()

    elapsed = time.time() - start_t
    # 6 requests at 5 req/sec must take at least 1.0 second
    assert elapsed >= 0.8, f"Rate limiter should throttle requests to 5 req/sec (took {elapsed:.2f}s)"


def test_authorization_rejection_for_unauthorized_target():
    """Verify content discovery rejects unauthorized out-of-scope targets."""
    from backend.services.content_discovery import run_content_discovery
    with pytest.raises(ValueError):
        run_content_discovery("https://unauthorized-external-domain.com/evil")
