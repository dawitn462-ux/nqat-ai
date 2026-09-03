"""
ML Classification Router — Serving Endpoint for Champion Model Inference
-----------------------------------------------------------------------
Provides POST /api/v1/classify endpoint loading models/best_classifier.json once at startup.
Reuses feature extraction logic from scripts/prepare_finding_dataset.py to prevent feature drift.
Includes /api/v1/ versioning and API Key authentication dependencies.
"""

import os
import sys
import json
import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scripts.prepare_finding_dataset import extract_finding_features_v2
from backend.auth import verify_api_key

logger = logging.getLogger("nkat.classification")
router = APIRouter(prefix="/api/v1", tags=["ML Classification"])

MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "best_classifier.json")

# Global model state loaded ONCE at startup
CHAMPION_MODEL = None


def load_champion_model():
    global CHAMPION_MODEL
    if os.path.exists(MODEL_PATH):
        try:
            import xgboost as xgb
            model_obj = xgb.XGBClassifier()
            model_obj.load_model(MODEL_PATH)
            CHAMPION_MODEL = model_obj
            logger.info(f"Champion XGBoost model loaded from {MODEL_PATH} at startup.")
        except Exception as exc:
            logger.error(f"Error loading XGBoost model from {MODEL_PATH}: {exc}")
    else:
        logger.warning(f"Model file not found at {MODEL_PATH}")


# Trigger model load on module import
load_champion_model()


class ClassificationRequest(BaseModel):
    check_name: str
    severity: Optional[str] = "LOW"
    evidence: Optional[str] = None


class ClassificationResponse(BaseModel):
    predicted_label: int
    label_name: str
    confidence_score: float
    features: List[float]


class NvdClassificationRequest(BaseModel):
    description: str
    attack_vector: Optional[str] = "NETWORK"
    exploitability_score: Optional[float] = 2.8


class NvdClassificationResponse(BaseModel):
    predicted_severity: str
    confidence: float
    severity_probabilities: dict
    top_keywords: List[str]
    features_extracted: dict


@router.post("/classify", response_model=ClassificationResponse, dependencies=[Depends(verify_api_key)])
def classify_finding(req: ClassificationRequest):
    """
    ML Classification Endpoint:
    Scores raw finding check_name/evidence text using champion finding-level model. Requires X-API-Key header.
    """
    if CHAMPION_MODEL is None:
        raise HTTPException(
            status_code=status.HTTP_533_SERVICE_UNAVAILABLE if hasattr(status, "HTTP_533_SERVICE_UNAVAILABLE") else status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Champion ML model artifact (models/best_classifier.json) is not loaded."
        )

    features = extract_finding_features_v2(req.check_name, req.severity or "LOW", req.evidence or "")

    try:
        pred_probs = CHAMPION_MODEL.predict_proba([features])[0]
        pred_label = int(CHAMPION_MODEL.predict([features])[0])
        confidence = float(pred_probs[pred_label])
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference error scoring finding: {exc}"
        )

    label_name = "malicious_vulnerability" if pred_label == 1 else "benign_traffic"

    return {
        "predicted_label": pred_label,
        "label_name": label_name,
        "confidence_score": round(confidence, 4),
        "features": features
    }


@router.post("/classify-cve", response_model=NvdClassificationResponse, dependencies=[Depends(verify_api_key)])
def classify_cve_text(req: NvdClassificationRequest):
    """
    NVD CVE Text Classifier Endpoint:
    Classifies CVSS severity (CRITICAL, HIGH, MEDIUM, LOW) directly from NVD CVE description text
    using the ML classifier trained on 2,484 real NVD CVE records.
    """
    from backend.services.nvd_classifier_service import classify_cve_description

    res = classify_cve_description(
        description_text=req.description,
        attack_vector=req.attack_vector or "NETWORK",
        exploitability_score=req.exploitability_score or 2.8
    )

    if res.get("predicted_severity") == "UNKNOWN":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=res.get("error", "Invalid description text provided.")
        )

    return res

