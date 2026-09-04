"""
Pydantic Schemas for API Request/Response Serialization.
"""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class FindingBase(BaseModel):
    check_name: str
    severity: str
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    config_snippet: Optional[str] = None
    status: str = "OPEN"
    ml_confidence: Optional[float] = None
    ml_predicted_label: Optional[int] = None
    review_deadline: Optional[datetime] = None
    owasp_category: Optional[str] = None
    cwe_id: Optional[str] = None
    is_in_cisa_kev: Optional[bool] = False
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    is_api_endpoint: Optional[bool] = False
    priority_tier: Optional[str] = "P3"
    contextual_risk_score: Optional[float] = None
    risk_acceptance_reason: Optional[str] = None
    reverified_at: Optional[datetime] = None
    sla_deadline: Optional[datetime] = None
    is_sla_breached: Optional[bool] = False
    historical_context_note: Optional[str] = None
    full_fix_guide: Optional[dict] = None
    remediation_guide: Optional[str] = None


class FindingCreate(FindingBase):
    pass


class FindingApprovalRequest(BaseModel):
    approved_by: Optional[str] = "admin"


class FindingStatusUpdateRequest(BaseModel):
    status: str
    actor: Optional[str] = "analyst"
    reason: Optional[str] = None


class ReverifyFindingResponse(BaseModel):
    finding_id: int
    status: str
    is_reverified: bool
    details: str
    reverified_at: datetime


class EventWebhookRequest(BaseModel):
    event_type: str = "CODE_DEPLOY"  # CODE_DEPLOY, COMMIT_PUSH, CVE_ALERT
    target_url: str
    commit_sha: Optional[str] = None
    environment: Optional[str] = "production"
    triggered_by: Optional[str] = "CI_CD_Pipeline"


class FindingResponse(FindingBase):
    id: int
    subdomain_id: int
    approved_at: Optional[datetime] = None
    approved_by: Optional[str] = None
    review_deadline: Optional[datetime] = None
    previous_state: Optional[str] = None
    owasp_category: Optional[str] = None
    cwe_id: Optional[str] = None
    is_in_cisa_kev: Optional[bool] = False
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    is_api_endpoint: Optional[bool] = False
    priority_tier: Optional[str] = "P3"
    contextual_risk_score: Optional[float] = None
    risk_acceptance_reason: Optional[str] = None
    reverified_at: Optional[datetime] = None
    sla_deadline: Optional[datetime] = None
    is_sla_breached: Optional[bool] = False
    historical_context_note: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuditLogResponse(BaseModel):
    id: int
    finding_id: int
    action: str
    actor: str
    actor_name: Optional[str] = None
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class SubdomainBase(BaseModel):
    hostname: str
    ip_address: Optional[str] = None
    is_api_endpoint: Optional[bool] = False


class SubdomainCreate(SubdomainBase):
    pass


class SubdomainResponse(SubdomainBase):
    id: int
    scan_id: int
    is_api_endpoint: Optional[bool] = False
    discovered_at: datetime
    findings: List[FindingResponse] = []

    model_config = ConfigDict(from_attributes=True)


class ScanBase(BaseModel):
    target: str


class ScanCreate(ScanBase):
    pass


class ScanResponse(ScanBase):
    id: int
    organization_id: Optional[int] = None
    status: str
    created_at: datetime
    subdomains: List[SubdomainResponse] = []

    model_config = ConfigDict(from_attributes=True)


class ScanStatusUpdate(BaseModel):
    status: str


class DomainSubmissionCreate(BaseModel):
    domain: str
    verification_method: Optional[str] = "dns_txt"


class DomainVerificationRequest(BaseModel):
    verification_method: Optional[str] = None


class DomainTargetResponse(BaseModel):
    id: int
    organization_id: int
    domain: str
    target_url: Optional[str] = None
    verification_token: str
    verification_method: str
    status: str
    verified_at: Optional[datetime] = None
    last_error: Optional[str] = None
    created_at: datetime
    dns_txt_record_name: Optional[str] = None
    dns_txt_record_value: Optional[str] = None
    file_verification_url: Optional[str] = None
    file_verification_content: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class NotificationResponse(BaseModel):
    id: int
    organization_id: int
    domain_id: Optional[int] = None
    scan_id: Optional[int] = None
    finding_id: Optional[int] = None
    title: str
    message: str
    severity: str
    is_read: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class NotificationMarkRead(BaseModel):
    is_read: bool = True


class DomainAuditLogResponse(BaseModel):
    id: int
    user_id: Optional[int] = None
    domain: str
    method: str
    timestamp: datetime
    result: str
    details: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)



