"""
Unit tests for Advanced AI Threat Correlation & Attack Path Graph Engine
-------------------------------------------------------------------------
Verifies:
- Directed Graph DAG node and edge generation.
- Compound attack path detection (e.g. Exposed Git Repo + SQL Injection).
- Composite threat vector score (0-100) calculation.
- GET /api/v1/scans/{scan_id}/threat-graph REST endpoint integration.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.database import Base, get_db
from backend.models import Scan, Subdomain, Finding, FindingStatus, ScanStatus
from backend.services.threat_correlation import compute_attack_path_graph


@pytest.fixture(autouse=True)
def setup_threat_graph_db():
    SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    yield TestingSessionLocal, engine
    app.dependency_overrides.clear()


def test_threat_correlation_graph_building(setup_threat_graph_db):
    TestingSessionLocal, _ = setup_threat_graph_db
    db = TestingSessionLocal()

    # Seed scan with compound vulnerability scenario
    scan = Scan(target="http://localhost:3000", status=ScanStatus.COMPLETED.value)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    sub = Subdomain(scan_id=scan.id, hostname="localhost", ip_address="127.0.0.1")
    db.add(sub)
    db.commit()
    db.refresh(sub)

    f1 = Finding(subdomain_id=sub.id, check_name="Exposed Git Repository", severity="HIGH", status=FindingStatus.OPEN.value)
    f2 = Finding(subdomain_id=sub.id, check_name="SQL Injection Vulnerability", severity="CRITICAL", status=FindingStatus.OPEN.value)
    db.add_all([f1, f2])
    db.commit()

    graph = compute_attack_path_graph(db, scan.id)

    assert graph["scan_id"] == scan.id
    assert graph["target"] == "http://localhost:3000"
    assert graph["composite_threat_score"] >= 75.0
    assert graph["threat_level"] in ("HIGH", "CRITICAL")

    # Verify DAG Nodes & Edges
    node_types = {n["type"] for n in graph["nodes"]}
    assert "TargetAsset" in node_types
    assert "SubdomainAsset" in node_types
    assert "VulnerabilityNode" in node_types
    assert "AttackImpactNode" in node_types

    # Verify Compound Attack Path detection
    assert len(graph["attack_chains"]) > 0
    chain_names = [c["chain_name"] for c in graph["attack_chains"]]
    assert "Full Infrastructure Compromise via Exposure & SQLi" in chain_names

    db.close()


def test_threat_graph_api_endpoint(setup_threat_graph_db):
    TestingSessionLocal, _ = setup_threat_graph_db
    db = TestingSessionLocal()

    scan = Scan(target="http://localhost:3000", status=ScanStatus.COMPLETED.value)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    sub = Subdomain(scan_id=scan.id, hostname="localhost")
    db.add(sub)
    db.commit()
    db.refresh(sub)

    f1 = Finding(subdomain_id=sub.id, check_name="Security Headers Audit", severity="MEDIUM")
    db.add(f1)
    db.commit()
    scan_id = scan.id
    db.close()

    client = TestClient(app)
    res = client.get(f"/api/v1/scans/{scan_id}/threat-graph")

    assert res.status_code == 200
    data = res.json()
    assert data["scan_id"] == scan_id
    assert "composite_threat_score" in data
    assert len(data["nodes"]) >= 3
