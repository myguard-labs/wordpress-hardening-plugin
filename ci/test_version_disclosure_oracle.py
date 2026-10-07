"""Keep the response-header regression tied to the origin's actual fixtures."""

import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "tests/integration/backend/nginx.conf"
REGRESSION = ROOT / "tests/regression/wordpress-hardening-plugin/9522701.yaml"
HEADERS = {
    9522701: (1, "X-Pingback", "https://example.test/xmlrpc.php"),
    9522702: (3, "X-Powered-By", "PHP/8.3"),
    9522703: (5, "Link", "<https://api.w.org/>; rel=\"https://api.w.org/\""),
}


class VersionDisclosureOracleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        config = BACKEND.read_text()
        cls.locations = {
            path: body
            for path, body in re.findall(r"location = (\S+) \{([^}]+)\}", config)
        }
        suite = yaml.safe_load(REGRESSION.read_text())
        cls.enabled = suite["meta"]["enabled"]
        cls.titles = [case["test_title"] for case in suite["tests"]]
        cls.tests = {
            case["test_title"]: case["stages"][0]
            for case in suite["tests"]
        }

    def test_target_headers_have_live_positive_cases(self):
        self.assertTrue(self.enabled)
        for rule_id, (case_number, header, value) in HEADERS.items():
            with self.subTest(rule_id=rule_id):
                stage = self.tests[f"9522701-{case_number}"]
                body = self.locations[stage["input"]["uri"]]
                self.assertIn(f"add_header {header} '{value}';", body)
                self.assertEqual(f'id "{rule_id}"', stage["output"]["log_contains"])
                self.assertIn("default_type text/plain;", body)
                self.assertIn("return 200 'ok';", body)

    def test_non_target_headers_have_negative_cases(self):
        for rule_id, (case_number, header, value) in HEADERS.items():
            with self.subTest(rule_id=rule_id):
                stage = self.tests[f"9522701-{case_number + 1}"]
                body = self.locations[stage["input"]["uri"]]
                self.assertNotIn(f"add_header {header} '{value}';", body)
                if rule_id == 9522701:
                    self.assertNotRegex(body, r"\badd_header\s+X-Pingback\b")
                self.assertEqual(f'id "{rule_id}"', stage["output"]["no_log_contains"])
                self.assertIn("return 200 'ok';", body)
        control = self.locations["/9522700-response-oracle-control"]
        self.assertIn("add_header X-Powered-By 'nginx';", control)
        self.assertIn("add_header Link '<https://example.test/>; rel=\"alternate\"';", control)

    def test_empty_pingback_header_has_live_positive_case(self):
        # go-ftw indexes selected cases by position; title order must agree.
        self.assertEqual(
            [f"9522701-{number}" for number in range(1, 8)], self.titles
        )
        stage = self.tests["9522701-7"]
        self.assertEqual(
            "/9522701-empty-response-oracle", stage["input"]["uri"]
        )
        body = self.locations[stage["input"]["uri"]]
        # nginx omits a zero-length add_header value. A single space is sent
        # on the wire and becomes an empty value after HTTP OWS is trimmed.
        self.assertEqual(
            ["' '"], re.findall(r"\badd_header\s+X-Pingback\s+([^;]+);", body)
        )
        self.assertIn("return 200 'ok';", body)
        self.assertEqual('id "9522701"', stage["output"]["log_contains"])

        rules = (ROOT / "plugins/wordpress-hardening-before.conf").read_text()
        match = re.search(
            r'SecRule (\S+) "(\S+) ([^\"]+)"\s*\\\s*"id:9522701,',
            rules,
        )
        self.assertIsNotNone(match, "9522701 presence rule is missing")
        self.assertEqual(
            ("&RESPONSE_HEADERS:X-Pingback", "@ge", "1"), match.groups()
        )


if __name__ == "__main__":
    unittest.main()
