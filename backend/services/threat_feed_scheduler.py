"""
15-Minute Threat Feed Polling Daemon — Mission 28 Part 2
---------------------------------------------------------
Background APScheduler daemon refreshing all 5 threat feed sources (CISA KEV, EPSS,
GitHub Advisories, URLhaus, ThreatFox) every 15 minutes on one unified scheduler tick.
"""

import logging
from apscheduler.schedulers.background import BackgroundScheduler
from backend.services.threat_feed_client import update_threat_feed_caches

logger = logging.getLogger("nkat.threat_feed_scheduler")

_threat_scheduler = None


def start_threat_feed_scheduler() -> BackgroundScheduler:
    """
    Initializes and starts the 15-minute background threat feed polling scheduler.
    """
    global _threat_scheduler

    if _threat_scheduler and _threat_scheduler.running:
        logger.info("[Threat Feed Scheduler] Daemon is already running.")
        return _threat_scheduler

    # Initial cache update on startup
    try:
        update_threat_feed_caches()
    except Exception as exc:
        logger.warning(f"[Threat Feed Scheduler] Initial startup cache update notice: {exc}")

    _threat_scheduler = BackgroundScheduler(daemon=True)
    _threat_scheduler.add_job(
        func=update_threat_feed_caches,
        trigger="interval",
        minutes=15,
        id="unified_5source_15min_polling_job",
        name="Refresh CISA KEV + EPSS + GHSA + URLhaus + ThreatFox threat intelligence caches",
        replace_existing=True
    )
    _threat_scheduler.start()
    logger.info("[+] [Threat Feed Scheduler] 15-Minute Unified 5-Source Polling Daemon started successfully.")
    return _threat_scheduler


def shutdown_threat_feed_scheduler():
    """
    Gracefully stops the 15-minute background threat feed scheduler.
    """
    global _threat_scheduler

    if _threat_scheduler and _threat_scheduler.running:
        _threat_scheduler.shutdown(wait=False)
        logger.info("[*] [Threat Feed Scheduler] 15-Minute Polling Daemon shut down cleanly.")
        _threat_scheduler = None
