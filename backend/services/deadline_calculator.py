"""
Deadline Calculator Service — severity-based review deadline computation.
Supports configurable timeout thresholds via environment variables (.env).
"""

import os
from datetime import datetime, timezone, timedelta

# Production defaults in minutes
DEFAULT_DEADLINES_MINUTES = {
    "CRITICAL": 60,       # 1 hour
    "HIGH": 240,         # 4 hours
    "MEDIUM": 1440,      # 24 hours
    "LOW": 4320,         # 72 hours
    "INFO": 4320,        # 72 hours
}


def get_deadline_minutes_for_severity(severity: str) -> int:
    """
    Returns review deadline in minutes for a given severity string.
    Reads environment variable override (e.g. DEADLINE_CRITICAL_MINUTES) or uses default.
    """
    sev_upper = str(severity).upper()
    env_var_name = f"DEADLINE_{sev_upper}_MINUTES"
    
    default_mins = DEFAULT_DEADLINES_MINUTES.get(sev_upper, 4320)
    val_str = os.getenv(env_var_name)
    if val_str:
        try:
            return int(val_str)
        except ValueError:
            pass
    return default_mins


def calculate_review_deadline(severity: str, base_time: datetime = None) -> datetime:
    """
    Calculates review_deadline datetime based on severity and base_time (default: UTC NOW).
    """
    if base_time is None:
        base_time = datetime.now(timezone.utc)

    minutes = get_deadline_minutes_for_severity(severity)
    return base_time + timedelta(minutes=minutes)
