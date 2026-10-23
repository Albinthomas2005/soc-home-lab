import unittest

from privacy_filter import sanitize_alert, sanitize_text


class TestPrivacyFilter(unittest.TestCase):

    def test_redacts_email(self):
        result = sanitize_text("user email: analyst@example.com")
        self.assertNotIn("analyst@example.com", result)
        self.assertIn("[REDACTED_EMAIL]", result)

    def test_redacts_bearer_token(self):
        result = sanitize_text("Authorization: Bearer abc123token")
        self.assertNotIn("abc123token", result)
        self.assertIn("[REDACTED_TOKEN]", result)

    def test_redacts_password_field(self):
        result = sanitize_alert({"password": "MySecret123"})
        self.assertEqual(result["password"], "[REDACTED_SECRET]")

    def test_redacts_api_key_field(self):
        result = sanitize_alert({"api_key": "fake-test-key-123"})
        self.assertEqual(result["api_key"], "[REDACTED_SECRET]")

    def test_redacts_public_ipv4(self):
        result = sanitize_text("Source IP: 8.8.8.8")
        self.assertNotIn("8.8.8.8", result)
        self.assertIn("[REDACTED_PUBLIC_IP]", result)

    def test_preserves_private_lab_ip(self):
        result = sanitize_text("Source IP: 192.168.1.50")
        self.assertIn("192.168.1.50", result)

    def test_recursively_sanitizes_nested_data(self):
        alert = {
            "data": {
                "email": "analyst@example.com",
                "password": "fake-password",
            }
        }
        result = sanitize_alert(alert)
        self.assertNotIn("analyst@example.com", str(result))
        self.assertNotIn("fake-password", str(result))

    def test_does_not_modify_input(self):
        alert = {"password": "fake-password"}
        sanitize_alert(alert)
        self.assertEqual(alert["password"], "fake-password")


if __name__ == "__main__":
    unittest.main()
