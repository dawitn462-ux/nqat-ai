"""
Scanner Core Pydantic Models for scan targets, HTTP transactions, findings, and reports.
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class StructuredFinding(BaseModel):
    """
    Exact output JSON finding schema:
    {target, check_name, severity, evidence, timestamp}
    """
    target: str
    check_name: str
    severity: str
    evidence: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ScanTarget(BaseModel):
    url: str
    allowed_hosts: List[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1", "::1"])
    target_port: int = 3000
    metadata: Dict[str, Any] = Field(default_factory=dict)


class HTTPRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: Dict[str, str] = Field(default_factory=dict)
    params: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None


class HTTPResponse(BaseModel):
    url: str
    status_code: int
    headers: Dict[str, str] = Field(default_factory=dict)
    body: str = ""
    elapsed_ms: float = 0.0


class VulnerabilityFinding(BaseModel):
    id: str
    title: str
    severity: Severity
    description: str
    endpoint: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    cwe: Optional[str] = None
    remediation: Optional[str] = None


class ScanSummary(BaseModel):
    total_endpoints_scanned: int = 0
    total_vulnerabilities: int = 0
    severity_counts: Dict[str, int] = Field(
        default_factory=lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    )
    scan_duration_seconds: float = 0.0


class ScanReport(BaseModel):
    scan_id: str
    target_url: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    summary: ScanSummary
    findings: List[VulnerabilityFinding] = Field(default_factory=list)
    structured_findings: List[StructuredFinding] = Field(default_factory=list)
