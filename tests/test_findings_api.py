"""
Unit & Integration Tests for Findings API & Recommendation Approval Workflow (Mission 5 Part 2)
Includes X-API-Key auth headers for hardened state-changing endpoints.
"""

import unittest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base, get_db
from backend.main import app
from backend.models import Scan, Subdomain, Finding, FindingStatus

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

API_KEY_HEADERS = {"X-API-Key": "nkat_secret_api_key_2026"}


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


class TestFindingsAPI(unittest.TestCase):

    def setUp(self):
        app.dependency_overrides[get_db] = override_get_db

    @classmethod
    def setUpClass(cls):
        app.dependency_overrides[get_db] = override_get_db
        Base.metadata.create_all(bind=engine)
        cls.client = TestClient(app)

        db = TestingSessionLocal()
        scan = db.query(Scan).filter(Scan.target == "http://localhost:3000").first()
        if not scan:
            scan = Scan(target="http://localhost:3000", status="COMPLETED")
            db.add(scan)
            db.commit()
            db.refresh(scan)

        sub = db.query(Subdomain).filter(Subdomain.scan_id == scan.id, Subdomain.hostname == "localhost").first()
        if not sub:
            sub = Subdomain(scan_id=scan.id, hostname="localhost", ip_address="127.0.0.1")
            db.add(sub)
            db.commit()
            db.refresh(sub)

        cls.subdomain_id = sub.id
        db.close()

    def test_01_create_finding_with_recommendation(self):
        payload = {
            "check_name": "Missing Security Header: Content-Security-Policy",
            "severity": "MEDIUM",
            "evidence": "Header Content-Security-Policy absent in HTTP response"
        }
        res = self.client.post(f"/api/v1/subdomains/{self.subdomain_id}/findings", json=payload, headers=API_KEY_HEADERS)
        self.assertEqual(res.status_code, 201)

        data = res.json()
        self.assertEqual(data["check_name"], payload["check_name"])
        self.assertIsNotNone(data["recommendation"])
        self.assertIn("Content-Security-Policy", data["recommendation"])
        self.assertIsNotNone(data["config_snippet"])
        self.assertEqual(data["status"], "OPEN")

        self.__class__.finding_id = data["id"]

    def test_02_approve_finding(self):
        fid = getattr(self.__class__, "finding_id", 1)
        res = self.client.patch(f"/api/v1/findings/{fid}/approve", json={"approved_by": "sec_auditor_alice"}, headers=API_KEY_HEADERS)
        self.assertEqual(res.status_code, 200)

        data = res.json()
        self.assertEqual(data["status"], "RESOLVED")
        self.assertEqual(data["approved_by"], "sec_auditor_alice")
        self.assertIsNotNone(data["approved_at"])

    def test_03_reject_finding(self):
        fid = getattr(self.__class__, "finding_id", 1)
        res = self.client.patch(f"/api/v1/findings/{fid}/reject", json={"approved_by": "sec_auditor_bob"}, headers=API_KEY_HEADERS)
        self.assertEqual(res.status_code, 200)

        data = res.json()
        self.assertEqual(data["status"], "OPEN")
        self.assertEqual(data["approved_by"], "rejected_by_sec_auditor_bob")
        self.assertIsNotNone(data["approved_at"])


if __name__ == "__main__":
    unittest.main()
