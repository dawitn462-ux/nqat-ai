"""
Database Connection & Session Management.
Configures SQLAlchemy engine, session maker, and Base model class.
"""

import os
import sys
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

load_dotenv()

is_pytest = "pytest" in sys.modules or "pytest" in os.environ.get("PYTEST_CURRENT_TEST", "") or "PYTEST_CURRENT_TEST" in os.environ

DEFAULT_DATABASE_URL = "sqlite:///./nkat_dev.db"
env_db_url = os.getenv("DATABASE_URL")

if is_pytest or not env_db_url or os.getenv("USE_SQLITE", "true").lower() == "true":
    DATABASE_URL = "sqlite:///./nkat_dev.db"
else:
    DATABASE_URL = env_db_url

if DATABASE_URL.startswith("postgres"):
    try:
        engine = create_engine(
            DATABASE_URL,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=5,
            connect_args={"connect_timeout": 1}
        )
        with engine.connect() as conn:
            pass
    except Exception as exc:
        sys.stderr.write(f"[!] PostgreSQL unavailable ({exc}). Falling back to local SQLite.\n")
        DATABASE_URL = "sqlite:///./nkat_dev.db"
        engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False}
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Register models onto Base.metadata and ensure DB tables exist
import backend.models
from sqlalchemy import inspect, text

try:
    Base.metadata.create_all(bind=engine)
    # Check and add new columns to users and findings tables if missing in existing DB
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    with engine.begin() as conn:
        if "users" in tables:
            existing_cols = {col["name"] for col in inspector.get_columns("users")}
            if "email_verification_expires_at" not in existing_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN email_verification_expires_at DATETIME"))
            if "auth_provider" not in existing_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN auth_provider VARCHAR(50) DEFAULT 'local'"))
            if "google_sub" not in existing_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN google_sub VARCHAR(255)"))

        if "findings" in tables:
            f_cols = {col["name"] for col in inspector.get_columns("findings")}
            if "priority_tier" not in f_cols:
                conn.execute(text("ALTER TABLE findings ADD COLUMN priority_tier VARCHAR(50) DEFAULT 'P3'"))
            if "contextual_risk_score" not in f_cols:
                conn.execute(text("ALTER TABLE findings ADD COLUMN contextual_risk_score FLOAT"))
            if "risk_acceptance_reason" not in f_cols:
                conn.execute(text("ALTER TABLE findings ADD COLUMN risk_acceptance_reason TEXT"))
            if "reverified_at" not in f_cols:
                conn.execute(text("ALTER TABLE findings ADD COLUMN reverified_at DATETIME"))
            if "sla_deadline" not in f_cols:
                conn.execute(text("ALTER TABLE findings ADD COLUMN sla_deadline DATETIME"))
            if "is_sla_breached" not in f_cols:
                conn.execute(text("ALTER TABLE findings ADD COLUMN is_sla_breached BOOLEAN DEFAULT 0"))
            if "historical_context_note" not in f_cols:
                conn.execute(text("ALTER TABLE findings ADD COLUMN historical_context_note TEXT"))
except Exception as exc:
    sys.stderr.write(f"[!] Notice creating or updating DB tables: {exc}\n")


def get_db():
    """
    FastAPI dependency yielding a database session per request.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
