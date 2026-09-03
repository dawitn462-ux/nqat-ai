"""
Unit Tests for Remediation Advisor Service (Mission 5 Part 1)
"""

import unittest
from backend.services.remediation_advisor import generate_recommendation


class TestRemediationAdvisor(unittest.TestCase):

    def test_missing_security_header_csp(self):
        finding = {"id": 101, "check_name": "Missing Security Header: Content-Security-Policy"}
        res = generate_recommendation(finding)

        self.assertEqual(res["finding_id"], 101)
        self.assertIn("Content-Security-Policy", res["recommendation_title"])
        self.assertIn("default-src 'self'", res["config_snippet"])
        self.assertEqual(res["remediation_type"], "HEADER_CONFIG")

    def test_missing_security_header_x_frame(self):
        finding = {"id": 102, "check_name": "Missing Security Header: X-Frame-Options"}
        res = generate_recommendation(finding)

        self.assertIn("X-Frame-Options", res["recommendation_title"])
        self.assertIn("SAMEORIGIN", res["config_snippet"])

    def test_exposed_git_repository(self):
        finding = {"id": 201, "check_name": "Exposed Git Repository"}
        res = generate_recommendation(finding)

        self.assertEqual(res["finding_id"], 201)
        self.assertIn("Block Public Access to .git Directory", res["recommendation_title"])
        self.assertIn("deny all;", res["config_snippet"])
        self.assertEqual(res["remediation_type"], "SERVER_CONFIG")

    def test_sql_injection(self):
        finding = {"id": 301, "check_name": "SQL Injection in search parameter"}
        res = generate_recommendation(finding)

        self.assertEqual(res["finding_id"], 301)
        self.assertIn("Parameterized Queries", res["recommendation_title"])
        self.assertIn("cursor.execute", res["config_snippet"])
        self.assertEqual(res["remediation_type"], "CODE_FIX")

    def test_nuclei_cve_with_metadata_patch(self):
        finding = {
            "id": 401,
            "check_name": "CVE-2023-46604 ActiveMQ RCE",
            "metadata": {"patched_version": "5.18.3"}
        }
        res = generate_recommendation(finding)

        self.assertEqual(res["finding_id"], 401)
        self.assertIn("CVE-2023-46604", res["recommendation_title"])
        self.assertIn("5.18.3", res["recommendation"])
        self.assertEqual(res["remediation_type"], "SOFTWARE_UPDATE")

    def test_nuclei_cve_without_metadata_patch(self):
        finding = {
            "id": 402,
            "check_name": "CVE-2021-44228 Log4j RCE"
        }
        res = generate_recommendation(finding)

        self.assertIn("CVE-2021-44228", res["recommendation_title"])
        self.assertIn("latest stable version", res["recommendation"])
        self.assertEqual(res["remediation_type"], "SOFTWARE_UPDATE")

    def test_unrecognized_finding_fallback(self):
        finding = {
            "id": 501,
            "check_name": "Custom Proprietary Flaw XYZ"
        }
        res = generate_recommendation(finding)

        self.assertEqual(res["finding_id"], 501)
        self.assertIn("Manual Security Review Recommended", res["recommendation_title"])
        self.assertTrue(len(res["recommendation"]) > 0)
        self.assertEqual(res["remediation_type"], "MANUAL_REVIEW")


if __name__ == "__main__":
    unittest.main()
