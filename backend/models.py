"""
SQLAlchemy Database Models for NKAT AI Backend.
Defines tables: scans, subdomains, findings.
"""

import enum
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, Float, String, Text, DateTime, ForeignKey, Enum, Boolean, func, UniqueConstraint
from sqlalchemy.orm import relationship
from backend.database import Base


class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class FindingStatus(str, enum.Enum):
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"
    AUTO_APPROVED = "AUTO_APPROVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class SeverityLevel(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(255), nullable=False, unique=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    users = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="organization", cascade="all, delete-orphan")
    domain_targets = relationship("DomainTarget", back_populates="organization", cascade="all, delete-orphan")
    notifications = relationship("InAppNotification", back_populates="organization", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Organization(id={self.id}, name='{self.name}')>"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    username = Column(String(150), nullable=False, unique=True, index=True)
    email = Column(String(255), nullable=True, unique=True, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default=UserRole.ANALYST.value, index=True)
    is_email_verified = Column(Boolean, nullable=False, default=False, index=True)
    email_verification_token = Column(String(255), nullable=True, index=True)
    email_verification_code = Column(String(10), nullable=True, index=True)
    email_verification_sent_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    organization = relationship("Organization", back_populates="users")

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}', verified={self.is_email_verified})>"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True, index=True)
    target = Column(String(255), nullable=False, index=True)
    status = Column(String(50), nullable=False, default=ScanStatus.PENDING.value, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    organization = relationship("Organization", back_populates="scans")
    subdomains = relationship("Subdomain", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Scan(id={self.id}, target='{self.target}', status='{self.status}')>"


class Subdomain(Base):
    __tablename__ = "subdomains"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    hostname = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(100), nullable=True)
    is_api_endpoint = Column(Boolean, default=False, nullable=True, index=True)
    discovered_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scan = relationship("Scan", back_populates="subdomains")
    findings = relationship("Finding", back_populates="subdomain", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Subdomain(id={self.id}, hostname='{self.hostname}', ip='{self.ip_address}', is_api={self.is_api_endpoint})>"


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("subdomain_id", "check_name", "evidence", name="uq_subdomain_check_evidence"),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    subdomain_id = Column(Integer, ForeignKey("subdomains.id", ondelete="CASCADE"), nullable=False, index=True)
    check_name = Column(String(255), nullable=False, index=True)
    severity = Column(String(50), nullable=False, index=True)
    evidence = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    config_snippet = Column(Text, nullable=True)
    status = Column(String(50), nullable=False, default=FindingStatus.OPEN.value, index=True)
    ml_confidence = Column(Float, nullable=True)
    ml_predicted_label = Column(Integer, nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    approved_by = Column(String(255), nullable=True)
    review_deadline = Column(DateTime(timezone=True), nullable=True, index=True)
    previous_state = Column(Text, nullable=True)
    owasp_category = Column(String(255), nullable=True, index=True)
    cwe_id = Column(String(50), nullable=True, index=True)
    is_in_cisa_kev = Column(Boolean, default=False, nullable=True, index=True)
    epss_score = Column(Float, nullable=True, index=True)
    epss_percentile = Column(Float, nullable=True)
    is_api_endpoint = Column(Boolean, default=False, nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    subdomain = relationship("Subdomain", back_populates="findings")

    @property
    def full_fix_guide(self):
        from backend.services.remediation_advisor import generate_recommendation
        f_dict = {"id": self.id, "check_name": self.check_name, "evidence": self.evidence}
        rec = generate_recommendation(f_dict)
        return rec.get("full_fix_guide")

    @property
    def remediation_guide(self):
        from backend.services.remediation_advisor import generate_recommendation
        f_dict = {"id": self.id, "check_name": self.check_name, "evidence": self.evidence}
        rec = generate_recommendation(f_dict)
        return rec.get("remediation_guide")

    def __repr__(self):
        return f"<Finding(id={self.id}, check_name='{self.check_name}', severity='{self.severity}', status='{self.status}')>"


class FeedbackLabel(Base):
    __tablename__ = "feedback_labels"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    features_snapshot = Column(Text, nullable=False)
    human_label = Column(String(50), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    finding = relationship("Finding")

    def __repr__(self):
        return f"<FeedbackLabel(id={self.id}, finding_id={self.finding_id}, label='{self.human_label}')>"


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    action = Column(String(50), nullable=False, index=True)
    actor = Column(String(50), nullable=False)
    actor_name = Column(String(255), nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    finding = relationship("Finding")

    def __repr__(self):
        return f"<AuditLog(id={self.id}, finding_id={self.finding_id}, action='{self.action}', actor='{self.actor}')>"


class DomainVerificationStatus(str, enum.Enum):
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"



class DomainVerificationMethod(str, enum.Enum):
    DNS_TXT = "dns_txt"
    FILE = "file"


class DomainTarget(Base):
    __tablename__ = "domain_targets"
    __table_args__ = (
        UniqueConstraint("organization_id", "domain", name="uq_org_domain"),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    domain = Column(String(255), nullable=False, index=True)
    target_url = Column(String(255), nullable=True)
    verification_token = Column(String(255), nullable=False, index=True)
    verification_method = Column(String(50), nullable=False, default=DomainVerificationMethod.DNS_TXT.value)
    status = Column(String(50), nullable=False, default=DomainVerificationStatus.PENDING.value, index=True)
    verified_at = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    organization = relationship("Organization", back_populates="domain_targets")

    def __repr__(self):
        return f"<DomainTarget(id={self.id}, domain='{self.domain}', status='{self.status}')>"


class InAppNotification(Base):
    __tablename__ = "in_app_notifications"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    domain_id = Column(Integer, ForeignKey("domain_targets.id", ondelete="CASCADE"), nullable=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=True, index=True)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(50), nullable=False, default="INFO", index=True)
    is_read = Column(Boolean, nullable=False, default=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    organization = relationship("Organization", back_populates="notifications")
    domain_target = relationship("DomainTarget")
    scan = relationship("Scan")
    finding = relationship("Finding")

    def __repr__(self):
        return f"<InAppNotification(id={self.id}, title='{self.title}', is_read={self.is_read})>"


class DomainAuditLog(Base):
    __tablename__ = "domain_audit_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    domain = Column(String(255), nullable=False, index=True)
    method = Column(String(50), nullable=False, default=DomainVerificationMethod.DNS_TXT.value)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    result = Column(String(50), nullable=False, index=True)
    details = Column(Text, nullable=True)

    user = relationship("User")

    def __repr__(self):
        return f"<DomainAuditLog(id={self.id}, user_id={self.user_id}, domain='{self.domain}', result='{self.result}')>"


class Post(Base):
    __tablename__ = "posts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    title = Column(String(255), nullable=False)
    tag = Column(String(100), default="ANNOUNCEMENT")
    tag_color = Column(String(50), default="#00f0ff")
    author = Column(String(100), default="Admin Security Ops")
    read_time = Column(String(50), default="3 min read")
    image_url = Column(Text, nullable=True)
    video_url = Column(Text, nullable=True)
    snippet = Column(Text, nullable=False)
    content = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class PlatformActivityLog(Base):
    __tablename__ = "platform_activity_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    username = Column(String(100), nullable=True, index=True)
    action_type = Column(String(100), nullable=False, index=True)  # LOGIN, SCAN_TRIGGER, FINDING_APPROVE, FINDING_REJECT, DOMAIN_SUBMIT, ROLE_CHANGE
    target_resource = Column(String(255), nullable=True)
    ip_address = Column(String(50), nullable=True, default="127.0.0.1")
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    user = relationship("User")

    def __repr__(self):
        return f"<PlatformActivityLog(id={self.id}, username='{self.username}', action_type='{self.action_type}', target='{self.target_resource}')>"





