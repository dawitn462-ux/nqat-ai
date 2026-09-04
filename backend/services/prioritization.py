"""
Dynamic Unified Prioritization & Risk Scoring Engine (Pillar 3).
Calculates composite Contextual Risk Score (0-100), assigns P1-P4 priority tiers,
and computes strict severity-based SLA deadlines.

Formula:
  ContextualRiskScore = min(100, (CVSS_Base * 2.5) + (EPSS * 35) + (KEV_Bonus * 20) + (Asset_Criticality * 15) - Historical_FP_Discount)
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from backend.models import Finding
from backend.services.adaptive_ml import analyze_historical_decision_context

logger = logging.getLogger("nkat.prioritization")

SEVERITY_BASE_CVSS = {
    "CRITICAL": 9.5,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.5,
    "INFO": 1.0,
}

SLA_DAYS_MAP = {
    "P1": 2,    # 48 hours (Immediate Blocker)
    "P2": 7,    # 7 days (High Risk)
    "P3": 30,   # 30 days (Medium Risk)
    "P4": 60,   # 60 days (Low Risk)
}


def calculate_contextual_risk_score(
    severity: str,
    epss_score: Optional[float] = None,
    is_in_cisa_kev: bool = False,
    is_api_endpoint: bool = False,
    fp_discount: float = 0.0
) -> float:
    """
    Computes real-time composite Contextual Risk Score (0.0 to 100.0).
    """
    base_cvss = SEVERITY_BASE_CVSS.get(str(severity).upper(), 3.0)
    cvss_weight = base_cvss * 2.5  # Max ~23.75

    epss_weight = (epss_score or 0.0) * 35.0  # Max 35.0
    kev_bonus = 20.0 if is_in_cisa_kev else 0.0  # Max 20.0
    asset_criticality = 15.0 if is_api_endpoint else 5.0  # Max 15.0

    raw_score = cvss_weight + epss_weight + kev_bonus + asset_criticality - fp_discount
    final_score = max(0.0, min(100.0, raw_score))
    return round(final_score, 1)


def determine_priority_tier(
    risk_score: float,
    severity: str,
    epss_score: Optional[float] = None,
    is_in_cisa_kev: bool = False
) -> str:
    """
    Categorizes finding into P1-P4 priority bands based on composite score & threat metrics.
    """
    sev_upper = str(severity).upper()
    epss = epss_score or 0.0

    # P1 - Immediate Blocker
    if is_in_cisa_kev or epss >= 0.50 or risk_score >= 75.0 or (sev_upper == "CRITICAL" and epss >= 0.10):
        return "P1"

    # P2 - High Risk
    if risk_score >= 50.0 or epss >= 0.10 or sev_upper in ("CRITICAL", "HIGH"):
        return "P2"

    # P3 - Medium Risk
    if risk_score >= 25.0 or sev_upper == "MEDIUM":
        return "P3"

    # P4 - Low Risk / Info
    return "P4"


def calculate_sla_deadline(priority_tier: str, start_time: Optional[datetime] = None) -> datetime:
    """
    Computes strict SLA deadline timestamp based on priority tier.
    """
    if start_time is None:
        start_time = datetime.now(timezone.utc)
    days = SLA_DAYS_MAP.get(priority_tier, 30)
    return start_time + timedelta(days=days)


def enrich_finding_prioritization(db: Session, finding: Finding) -> Finding:
    """
    Applies adaptive historical learning, calculates Contextual Risk Score,
    assigns Priority Tier (P1-P4), and calculates SLA deadline.
    """
    # 1. Fetch historical FP discount
    hist_ctx = analyze_historical_decision_context(db, finding.check_name)
    fp_discount = hist_ctx.get("fp_discount", 0.0)

    # 2. Compute Contextual Risk Score
    score = calculate_contextual_risk_score(
        severity=finding.severity,
        epss_score=finding.epss_score,
        is_in_cisa_kev=finding.is_in_cisa_kev or False,
        is_api_endpoint=finding.is_api_endpoint or False,
        fp_discount=fp_discount
    )
    finding.contextual_risk_score = score

    # 3. Determine Priority Tier
    tier = determine_priority_tier(
        risk_score=score,
        severity=finding.severity,
        epss_score=finding.epss_score,
        is_in_cisa_kev=finding.is_in_cisa_kev or False
    )
    finding.priority_tier = tier

    # 4. Compute SLA Deadline if not already set
    if not finding.sla_deadline:
        start = finding.created_at or datetime.now(timezone.utc)
        finding.sla_deadline = calculate_sla_deadline(tier, start)

    # 5. Check SLA breach
    now = datetime.now(timezone.utc)
    if finding.sla_deadline and finding.status not in ("RESOLVED", "CLOSED", "RISK_ACCEPTED", "FALSE_POSITIVE"):
        if now > finding.sla_deadline:
            finding.is_sla_breached = True

    finding.historical_context_note = hist_ctx.get("historical_note")
    return finding
