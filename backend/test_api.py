
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

import api
import database


class ConsentGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"

        self.db_patcher = patch.object(
            database, "DATABASE_PATH", self.db_path
        )
        self.db_patcher.start()

        database.initialize_database()

        self.client = api.app.test_client()

    def tearDown(self):
        self.db_patcher.stop()
        self.temp_dir.cleanup()

    def post_consent(self, purpose, action):
        return self.client.post(
            "/api/consents",
            json={
                "user_id": "test-user",
                "purpose": purpose,
                "action": action,
            },
        )

    def access(self, purpose):
        return self.client.post(
            "/api/data-access",
            json={
                "user_id": "test-user",
                "purpose": purpose,
            },
        )

    def test_health(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)

    def test_grant_consent(self):
        response = self.post_consent("Analytics", "grant")
        self.assertEqual(response.status_code, 201)
        self.assertTrue(response.json["granted"])

    def test_deny_consent(self):
        response = self.post_consent("Analytics", "deny")
        self.assertEqual(response.status_code, 201)
        self.assertFalse(response.json["granted"])

    def test_withdraw_consent(self):
        self.post_consent("Analytics", "grant")
        response = self.post_consent("Analytics", "withdraw")
        self.assertEqual(response.status_code, 201)
        self.assertFalse(response.json["granted"])

    def test_granted_access_allowed(self):
        self.post_consent("Analytics", "grant")
        response = self.access("Analytics")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["allowed"])

    def test_access_denied_without_consent(self):
        response = self.access("Marketing")
        self.assertEqual(response.status_code, 403)

    def test_access_denied_after_withdrawal(self):
        self.post_consent("Analytics", "grant")
        self.post_consent("Analytics", "withdraw")
        response = self.access("Analytics")
        self.assertEqual(response.status_code, 403)

    def test_invalid_purpose_rejected(self):
        response = self.post_consent("Unknown", "grant")
        self.assertEqual(response.status_code, 400)

    def test_invalid_action_rejected(self):
        response = self.post_consent("Analytics", "maybe")
        self.assertEqual(response.status_code, 400)

    def test_marketing_consent_is_separate(self):
        self.post_consent("Analytics", "grant")
        self.assertEqual(self.access("Analytics").status_code, 200)
        self.assertEqual(self.access("Marketing").status_code, 403)

    def test_third_party_consent(self):
        response = self.post_consent(
            "Third-Party Sharing", "grant"
        )
        self.assertEqual(response.status_code, 201)

    def test_consent_state_is_readable(self):
        self.post_consent("Analytics", "grant")
        response = self.client.get(
            "/api/consents?user_id=test-user"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json), 1)
        self.assertEqual(response.json[0]["purpose"], "Analytics")

    def test_audit_records_grant_and_withdrawal(self):
        self.post_consent("Analytics", "grant")
        self.post_consent("Analytics", "withdraw")
        response = self.client.get("/api/audit")
        self.assertEqual(response.status_code, 200)

        actions = [event["action"] for event in response.json]
        self.assertIn("grant", actions)
        self.assertIn("withdraw", actions)

    def test_audit_export_is_csv(self):
        self.post_consent("Analytics", "grant")
        response = self.client.get("/api/audit/export")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.content_type)
        self.assertIn(b"notice_version", response.data)

    def test_latest_consent_decision_applies(self):
        self.post_consent("Analytics", "grant")
        self.post_consent("Analytics", "deny")
        self.assertEqual(self.access("Analytics").status_code, 403)


    def test_old_notice_consent_is_rejected(self):
        self.post_consent("Analytics", "grant")

        original_version = api.NOTICE_VERSION
        try:
            api.NOTICE_VERSION = "2.0"
            response = self.access("Analytics")
            self.assertEqual(response.status_code, 403)
        finally:
            api.NOTICE_VERSION = original_version

if __name__ == "__main__":
    unittest.main(verbosity=2)
