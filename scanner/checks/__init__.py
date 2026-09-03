"""
Scanner Core Vulnerability Check Modules.
"""

from scanner.checks.base import BaseCheck
from scanner.checks.security_headers import SecurityHeadersCheck
from scanner.checks.info_leak import InfoLeakCheck
from scanner.checks.sqli import SQLInjectionCheck
from scanner.checks.xss import XSSCheck
from scanner.checks.fingerprint import SoftwareFingerprintCheck
from scanner.checks.backup_discovery import BackupDiscoveryCheck

ALL_CHECKS = [
    SecurityHeadersCheck,
    SoftwareFingerprintCheck,
    InfoLeakCheck,
    SQLInjectionCheck,
    XSSCheck,
    BackupDiscoveryCheck,
]
