import os
import unittest
from unittest.mock import patch

from app import app
from gemini_service import GeminiUnavailable


INTERNAL_TOKEN = "unit-test-internal-token"
ENDPOINT = "/api/ai/analyze-alert"


class TestAnalyzeAlertAPI(unittest.TestCase):
    def setUp(self):
        self.env_patch = patch.dict(
            os.environ,
            {"SOC_AI_INTERNAL_TOKEN": INTERNAL_TOKEN},
        )
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        self.client = app.test_client()
        self.headers = {"Authorization": f"Bearer {INTERNAL_TOKEN}"}

    def post_alert(self, alert, headers=None):
        return self.client.post(
            ENDPOINT,
            json={"alert": alert},
            headers=self.headers if headers is None else headers,
        )

    def test_missing_token_is_rejected(self):
        response = self.client.post(ENDPOINT, json={"alert": {"rule": {}}})
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.get_json()["ok"])

    def test_missing_server_token_configuration_is_rejected(self):
        with patch.dict(os.environ, {"SOC_AI_INTERNAL_TOKEN": ""}):
            response = self.post_alert({"rule": {"id": "1001"}})
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.get_json()["ok"])

    def test_incorrect_token_is_rejected(self):
        response = self.post_alert(
            {"rule": {"id": "1001"}},
            headers={"Authorization": "Bearer incorrect-token"},
        )
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.get_json()["ok"])

    def test_valid_token_analyzes_only_sanitized_alert(self):
        original = {"rule": {"id": "1001"}, "password": "private"}
        sanitized = {"rule": {"id": "1001"}, "password": "[REDACTED_SECRET]"}
        call_order = []

        def sanitize(alert):
            call_order.append("sanitize")
            self.assertEqual(alert, original)
            return sanitized

        def explain(alert):
            call_order.append("explain")
            self.assertEqual(alert, sanitized)
            return "Analysis text"

        with patch("app.sanitize_alert", side_effect=sanitize), patch(
            "app.explain_alert", side_effect=explain
        ):
            response = self.post_alert(original)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {"ok": True, "analysis": "Analysis text"},
        )
        self.assertEqual(call_order, ["sanitize", "explain"])

    def test_missing_or_invalid_alert_is_rejected(self):
        invalid_payloads = (
            {},
            {"alert": None},
            {"alert": []},
            {"alert": "text"},
            {"alert": {}},
        )
        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                response = self.client.post(
                    ENDPOINT,
                    json=payload,
                    headers=self.headers,
                )
                self.assertEqual(response.status_code, 400)
                self.assertFalse(response.get_json()["ok"])

    def test_malformed_json_is_rejected(self):
        response = self.client.post(
            ENDPOINT,
            data="{malformed",
            content_type="application/json",
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.get_json()["ok"])

    def test_unsupported_content_type_is_rejected(self):
        response = self.client.post(
            ENDPOINT,
            data='{"alert": {"rule": {}}}',
            content_type="text/plain",
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 400)

    def test_provider_failure_returns_safe_json_error(self):
        with patch("app.sanitize_alert", side_effect=lambda alert: alert), patch(
            "app.explain_alert",
            side_effect=GeminiUnavailable("private provider detail"),
        ):
            response = self.post_alert({"rule": {"id": "1001"}})

        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.get_json(),
            {
                "ok": False,
                "error": "AI analysis is temporarily unavailable",
            },
        )
        self.assertNotIn(b"private provider detail", response.data)

    def test_unexpected_error_returns_safe_json(self):
        with patch("app.sanitize_alert", side_effect=lambda alert: alert), patch(
            "app.explain_alert", side_effect=RuntimeError("private detail")
        ):
            response = self.post_alert({"rule": {"id": "1001"}})

        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.get_json(),
            {"ok": False, "error": "AI analysis could not be completed"},
        )
        self.assertNotIn(b"private detail", response.data)

    def test_oversized_request_returns_json_error(self):
        oversized_body = b'{"alert":{"value":"' + b"x" * (1024 * 1024) + b'"}}'
        response = self.client.post(
            ENDPOINT,
            data=oversized_body,
            content_type="application/json",
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(
            response.get_json(),
            {"ok": False, "error": "Request body is too large"},
        )


if __name__ == "__main__":
    unittest.main()
