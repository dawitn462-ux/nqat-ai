"""
Scanner Core Exceptions
"""

class ScannerException(Exception):
    """Base exception for all scanner errors."""
    pass


class ScopeViolationError(ScannerException):
    """
    Raised when an outbound HTTP request or target URL violates strict scope rules.
    Guards against scanning unauthorized domains, IPs, or ports.
    """
    def __init__(self, url: str, reason: str):
        self.url = url
        self.reason = reason
        super().__init__(f"Scope Violation for target '{url}': {reason}")


class ScanConfigError(ScannerException):
    """Raised when scanner environment or runtime configuration is invalid."""
    pass


class RequestEngineError(ScannerException):
    """Raised when an HTTP request fails unexpectedly in the engine."""
    pass
