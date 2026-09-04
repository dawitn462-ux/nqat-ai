"""
Adaptive Organizational Context & Historical ML Triage Service.
Analyzes team decision history (FeedbackLabel, AuditLog) and asset criticality
to dynamically inject organizational context into finding predictions and risk scoring.
"""

import logging
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.models import FeedbackLabel, AuditLog, Finding, Subdomain

logger = logging.getLogger("nkat.adaptive_ml")


def analyze_historical_decision_context(db: Session, check_name: str, org_id: Optional[int] = None) -> Dict[str, Any]:
    """
    Analyzes historical analyst decisions for a specific check_name across the system or specific org.
    Returns:
      - total_reviews: Total feedback records
      - fp_rate: Proportion of FALSE_POSITIVE labels
      - resolved_rate: Proportion of RESOLVED labels
      - historical_note: Human-readable contextual summary
      - fp_discount: Discount factor for false positive patterns (0.0 to 30.0)
    """
    query = (
        db.query(FeedbackLabel.human_label)
        .join(Finding, FeedbackLabel.finding_id == Finding.id)
        .filter(Finding.check_name == check_name)
    )

    labels = [row[0] for row in query.all()]
    if not labels:
        return {
            "total_reviews": 0,
            "fp_rate": 0.0,
            "resolved_rate": 0.0,
            "historical_note": "No prior organizational decision history.",
            "fp_discount": 0.0,
            "confidence_adjustment": 0.0
        }

    total = len(labels)
    fp_count = labels.count("FALSE_POSITIVE") + labels.count("REJECT")
    resolved_count = labels.count("RESOLVED") + labels.count("APPROVE")

    fp_rate = fp_count / total
    resolved_rate = resolved_count / total

    fp_discount = 0.0
    confidence_adjustment = 0.0
    note_parts = [f"Reviewed {total} time(s) historically."]

    if fp_rate >= 0.70:
        fp_discount = 25.0 * fp_rate
        confidence_adjustment = -0.20
        note_parts.append(f"⚠️ High historical False Positive rate ({fp_rate:.0%}). Analyst review recommended.")
    elif fp_rate >= 0.40:
        fp_discount = 12.0 * fp_rate
        confidence_adjustment = -0.10
        note_parts.append(f"Moderate historical False Positive rate ({fp_rate:.0%}).")
    elif resolved_rate >= 0.80:
        note_parts.append(f"✅ High historical confirmed resolution rate ({resolved_rate:.0%}).")
        confidence_adjustment = 0.10

    return {
        "total_reviews": total,
        "fp_rate": round(fp_rate, 4),
        "resolved_rate": round(resolved_rate, 4),
        "historical_note": " ".join(note_parts),
        "fp_discount": round(fp_discount, 2),
        "confidence_adjustment": round(confidence_adjustment, 2)
    }


def enrich_finding_with_adaptive_context(db: Session, finding: Finding) -> Finding:
    """
    Enriches a finding instance with adaptive context notes and adjusted ML confidence.
    """
    context = analyze_historical_decision_context(db, finding.check_name)
    finding.historical_context_note = context["historical_note"]

    if finding.ml_confidence is not None:
        adj = context["confidence_adjustment"]
        finding.ml_confidence = max(0.0, min(1.0, finding.ml_confidence + adj))

    return finding
