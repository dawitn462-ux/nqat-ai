"""
Authorized Target Policy Parser.
Extracts authorized target URLs exclusively from docs/AUTHORIZED_TARGETS.md policy document.
Prohibits unapproved or free-text target overrides.
"""

import os
import re
from typing import List
from urllib.parse import urlparse

from scanner.exceptions import ScopeViolationError, ScanConfigError


class TargetParser:
    """
    Parses authorized target scope strictly from docs/AUTHORIZED_TARGETS.md.
    """

    DEFAULT_POLICY_PATH = os.path.join("docs", "AUTHORIZED_TARGETS.md")

    @classmethod
    def get_authorized_targets(cls, policy_path: str = DEFAULT_POLICY_PATH) -> List[str]:
        """
        Parses policy markdown file and returns list of authorized target URLs.
        Raises ScopeViolationError if file missing or no authorized targets found.
        """
        if not os.path.exists(policy_path):
            raise ScanConfigError(f"Mandatory authorization policy missing at '{policy_path}'")

        authorized_urls: List[str] = []

        with open(policy_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        for line in lines:
            # Check for table rows containing AUTHORIZED status
            if "AUTHORIZED" in line and not line.strip().startswith("#"):
                # Extract URLs enclosed in backticks or matching http(s)://
                matches = re.findall(r'`(https?://[^\`]+)`', line)
                if not matches:
                    matches = re.findall(r'(https?://[^\s\|]+)', line)

                for url in matches:
                    clean_url = url.strip("`").strip()
                    parsed = urlparse(clean_url)
                    if parsed.scheme in ("http", "https") and parsed.hostname:
                        if clean_url not in authorized_urls:
                            authorized_urls.append(clean_url)

        if not authorized_urls:
            raise ScopeViolationError(
                policy_path,
                "No explicitly AUTHORIZED targets were found in policy document.",
            )

        return authorized_urls

    @classmethod
    def get_primary_target(cls, policy_path: str = DEFAULT_POLICY_PATH, enforce_https: bool = False) -> str:
        """
        Returns the primary authorized target URL matching scheme requirements from policy document.
        """
        targets = cls.get_authorized_targets(policy_path)
        if enforce_https:
            https_targets = [t for t in targets if t.startswith("https://")]
            if https_targets:
                return https_targets[0]
        return targets[0]
