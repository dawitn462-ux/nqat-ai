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

try:
    Base.metadata.create_all(bind=engine)
except Exception as exc:
    sys.stderr.write(f"[!] Notice creating DB tables: {exc}\n")


def get_db():
    """
    FastAPI dependency yielding a database session per request.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
