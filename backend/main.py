"""
FastAPI Main Application Entrypoint — Enterprise Backend Hardening Edition.
Configures API versioning (/api/v1/), slowapi rate limiting, centralized logging, and global JSON exception handlers.
"""

import os
import sys
import logging
import threading
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import text
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

# Configure Centralized Structured Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("nkat.backend")

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from contextlib import asynccontextmanager
from backend.database import get_db, Base, engine
from backend.schemas import ScanCreate
from backend.routers import scans, subdomains, findings, classification, agent, auth, threat_graph
from backend.services.auto_approval_scheduler import start_auto_approval_scheduler, shutdown_auto_approval_scheduler
from backend.services.threat_feed_scheduler import start_threat_feed_scheduler, shutdown_threat_feed_scheduler
from backend.services.continuous_monitoring_scheduler import start_continuous_monitoring_scheduler, shutdown_continuous_monitoring_scheduler
from backend.services.auth_service import seed_default_organization_and_user
from backend.services.scan_service import validate_target_authorization, run_scan_pipeline_background
from backend.models import Scan, ScanStatus


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing database migrations and tables...")
    with engine.connect() as conn:
        def ensure_column(table_name: str, col_name: str, col_def: str):
            res = conn.execute(text(f"PRAGMA table_info({table_name});")).fetchall()
            existing_cols = [row[1] for row in res]
            if col_name not in existing_cols:
                logger.info(f"Adding missing column '{col_name}' to table '{table_name}'...")
                conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_def};"))

        try:
            ensure_column("findings", "review_deadline", "TIMESTAMP")
            ensure_column("findings", "previous_state", "TEXT")
            ensure_column("findings", "owasp_category", "TEXT")
            ensure_column("findings", "cwe_id", "TEXT")
            ensure_column("findings", "is_in_cisa_kev", "BOOLEAN")
            ensure_column("findings", "epss_score", "FLOAT")
            ensure_column("findings", "epss_percentile", "FLOAT")
            ensure_column("findings", "is_api_endpoint", "BOOLEAN DEFAULT 0")
            ensure_column("findings", "priority_tier", "TEXT DEFAULT 'P3'")
            ensure_column("findings", "contextual_risk_score", "FLOAT")
            ensure_column("findings", "risk_acceptance_reason", "TEXT")
            ensure_column("findings", "reverified_at", "TIMESTAMP")
            ensure_column("findings", "sla_deadline", "TIMESTAMP")
            ensure_column("findings", "is_sla_breached", "BOOLEAN DEFAULT 0")
            ensure_column("findings", "historical_context_note", "TEXT")
            ensure_column("subdomains", "is_api_endpoint", "BOOLEAN DEFAULT 0")
            ensure_column("scans", "organization_id", "INTEGER")
            ensure_column("users", "email", "TEXT")
            ensure_column("users", "is_email_verified", "BOOLEAN DEFAULT 0")
            ensure_column("users", "email_verification_token", "TEXT")
            ensure_column("users", "email_verification_code", "TEXT")
            ensure_column("users", "email_verification_sent_at", "TIMESTAMP")
            conn.commit()
        except Exception as exc:
            logger.warning(f"Database migration notice: {exc}")
    Base.metadata.create_all(bind=engine)

    # Seed Default Organization and Admin User, then backfill existing scans
    try:
        from backend.database import SessionLocal
        db_seed = SessionLocal()
        seed_res = seed_default_organization_and_user(db_seed)
        default_org_id = seed_res["organization_id"]
        
        # Backfill existing scans with organization_id
        with engine.connect() as conn:
            conn.execute(text(f"UPDATE scans SET organization_id = {default_org_id} WHERE organization_id IS NULL;"))
            conn.commit()

        from backend.models import PlatformActivityLog
        if db_seed.query(PlatformActivityLog).count() == 0:
            from backend.services.activity_logger import log_platform_activity
            log_platform_activity(db_seed, "LOGIN", user_id=1, username="admin", target_resource="Platform Web Console", details="Admin login session initialized")
            log_platform_activity(db_seed, "SCAN_TRIGGER", user_id=1, username="admin", target_resource="Target: http://localhost:3000", details="Automated vulnerability scan pipeline executed")
            log_platform_activity(db_seed, "ROLE_CHANGE", user_id=1, username="admin", target_resource="User: admin", details="Promoted to Super Admin role")

        db_seed.close()
        logger.info(f"Default Organization & User seeded and scans backfilled successfully: {seed_res}")
    except Exception as exc:
        logger.warning(f"Warning seeding default organization/user or backfilling: {exc}")

    start_auto_approval_scheduler()
    start_threat_feed_scheduler()
    start_continuous_monitoring_scheduler()
    logger.info("Background schedulers (Auto-approval, 15-min Threat Feed & Continuous Monitoring) started successfully.")
    yield
    shutdown_auto_approval_scheduler()
    shutdown_threat_feed_scheduler()
    shutdown_continuous_monitoring_scheduler()
    logger.info("Backend application shutdown complete.")


app = FastAPI(
    title="NKAT Sentinel — Hardened Security Scanner API",
    description="Backend REST API wrapping security audit engine, subdomain discovery, findings store, ML scoring, rate limiting, and API key / JWT authentication.",
    version="2.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Register slowapi rate limiter state
app.state.limiter = scans.limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Enable CORS for HTTPS Dashboard and local origins
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:[0-9]+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response

uploads_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "uploads")
os.makedirs(uploads_dir, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=uploads_dir), name="uploads")

@app.get("/favicon.ico", include_in_schema=False)
@app.get("/favicon.png", include_in_schema=False)
@app.get("/favicon.svg", include_in_schema=False)
def get_favicon(request: Request):
    filename = request.url.path.lstrip("/")
    dist_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend", "dist", filename)
    public_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend", "public", filename)
    if os.path.exists(dist_file):
        return FileResponse(dist_file)
    elif os.path.exists(public_file):
        return FileResponse(public_file)
    return Response(status_code=404)

# Register Centralized Error Handlers
@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "HTTPException",
            "detail": exc.detail,
            "status_code": exc.status_code
        }
    )


@app.middleware("http")
async def waf_traffic_middleware(request: Request, call_next):
    path_and_query = str(request.url)
    if not (
        request.url.path.startswith("/uploads") or 
        request.url.path.startswith("/assets") or 
        request.url.path.startswith("/favicon") or
        request.url.path.startswith("/api/v1/posts") or
        request.url.path.startswith("/api/v1/admin")
    ):
        client_ip = request.client.host if request.client else "127.0.0.1"
        try:
            from backend.services.waf_service import analyze_request_payload, trigger_waf_blocked_attack_alerts
            res = analyze_request_payload(
                method=request.method,
                path=path_and_query,
                payload=str(request.query_params),
                client_ip=client_ip
            )
            if res.get("action") == "BLOCKED":
                # Fire In-App Notification Alert & Real Email Alert BEFORE blocking request!
                try:
                    from backend.database import SessionLocal
                    db_session = SessionLocal()
                    trigger_waf_blocked_attack_alerts(
                        db=db_session,
                        client_ip=client_ip,
                        path=path_and_query,
                        classification=res.get("classification"),
                        ml_confidence=res.get("ml_confidence", 0.95),
                        reason=res.get("reason", "Malicious attack signature matched."),
                        payload=str(request.query_params)
                    )
                    db_session.close()
                except Exception as alert_err:
                    logger.warning(f"Error firing WAF attack alert: {alert_err}")

                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "WAF_ATTACK_BLOCKED",
                        "detail": f" WAF Security Intercept: {res.get('reason')} ({res.get('classification')})",
                        "classification": res.get("classification"),
                        "ml_confidence": res.get("ml_confidence"),
                        "status_code": 403
                    }
                )
        except Exception:
            pass
    response = await call_next(request)
    return response


from backend.routers import scans, subdomains, findings, classification, agent, auth, threat_graph, domains, notifications, admin, posts, events

# Mount Versioned Routers
app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(posts.router)
app.include_router(domains.router)
app.include_router(notifications.router)
app.include_router(events.router)
app.include_router(scans.router)
app.include_router(subdomains.router)
app.include_router(findings.router)
app.include_router(classification.router)
app.include_router(agent.router)
app.include_router(threat_graph.router)


@app.get("/", include_in_schema=False)
def root_redirect():
    """
    Redirects root endpoint to interactive OpenAPI docs (/docs).
    """
    return RedirectResponse(url="/docs")


from fastapi import Body

@app.post("/api/scan", tags=["Legacy Compatibility"], status_code=status.HTTP_201_CREATED)
def legacy_scan(payload: ScanCreate = Body(...), db: Session = Depends(get_db)):
    try:
        validated_target = validate_target_authorization(payload.target, db=db)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Target '{payload.target}' is NOT authorized for scanning (authorization check failed: {exc})."
        )
    scan_obj = Scan(target=validated_target, status=ScanStatus.PENDING.value)
    db.add(scan_obj)
    db.commit()
    db.refresh(scan_obj)
    
    thread = threading.Thread(
        target=run_scan_pipeline_background,
        args=(scan_obj.id, validated_target),
        daemon=True
    )
    thread.start()
    return scan_obj


from backend.schemas import ScanCreate, ScanResponse

@app.get("/api/scan/{scan_id}", response_model=ScanResponse, tags=["Legacy Compatibility"])
def legacy_get_scan(scan_id: int, request: Request, db: Session = Depends(get_db)):
    return scans.get_scan(scan_id, request=request, db=db)


@app.post("/api/classify", tags=["Legacy Compatibility"])
def legacy_classify(payload: classification.ClassificationRequest = Body(...)):
    return classification.classify_finding(payload)


@app.get("/api/v1/health", tags=["Health"])
@app.get("/api/health", tags=["Health"])
def healthcheck(db: Session = Depends(get_db)):
    """
    Backend healthcheck endpoint verifying database connection.
    """
    try:
        db.execute(text("SELECT 1;"))
        db_status = "connected"
    except Exception as exc:
        db_status = f"error: {str(exc)}"

    return {
        "status": "healthy" if db_status == "connected" else "unhealthy",
        "app": "NKAT Sentinel Hardened Security Backend",
        "database": db_status,
        "version": "v1"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
