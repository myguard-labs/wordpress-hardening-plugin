"""Keep the xmlrpc and wp-cron path operators explicit without changing matches."""

import re
import unittest
from pathlib import Path
from unittest.mock import patch

RULES = (
    Path(__file__).resolve().parents[1] / "plugins/wordpress-hardening-before.conf"
).read_text()


def rule_pattern(rule_id):
    match = next(
        (
            rule
            for rule in re.finditer(
                r'SecRule REQUEST_FILENAME "([^"]+)"\s*\\\s*"id:(\d+),', RULES
            )
            if rule.group(2) == str(rule_id)
        ),
        None,
    )
    if match is None:
        raise AssertionError(f"REQUEST_FILENAME rule {rule_id} is missing")
    operator = match.group(1)
    if not operator.startswith("@rx "):
        raise AssertionError(f"rule {rule_id} must use explicit @rx: {operator}")
    return re.compile(operator[4:])


class ExplicitPathRegexTests(unittest.TestCase):
    def test_missing_rule_is_an_error(self):
        with (
            patch.dict(rule_pattern.__globals__, {"RULES": ""}),
            self.assertRaisesRegex(AssertionError, "9522102.*missing"),
        ):
            rule_pattern(9522102)

    def test_implicit_operator_is_an_error(self):
        implicit = (
            'SecRule REQUEST_FILENAME "^/xmlrpc\\.php" \\\n  "id:9522102,phase:2,pass"'
        )
        with (
            patch.dict(rule_pattern.__globals__, {"RULES": implicit}),
            self.assertRaisesRegex(AssertionError, "explicit @rx"),
        ):
            rule_pattern(9522102)

    def test_xmlrpc_path_boundaries(self):
        pattern = rule_pattern(9522102)
        for path in ("/xmlrpc.php", "/xmlrpc.php/extra", "/xmlrpc.php.bak"):
            with self.subTest(path=path):
                self.assertIsNotNone(pattern.search(path))
        for path in ("/index.php", "/prefix/xmlrpc.php", "/xmlrpcXphp", ""):
            with self.subTest(path=path):
                self.assertIsNone(pattern.search(path))

    def test_wp_cron_path_boundaries(self):
        pattern = rule_pattern(9522111)
        for path in ("/wp-cron.php", "/wp-cron.php/extra", "/wp-cron.php.bak"):
            with self.subTest(path=path):
                self.assertIsNotNone(pattern.search(path))
        for path in ("/index.php", "/prefix/wp-cron.php", "/wp-cronXphp", ""):
            with self.subTest(path=path):
                self.assertIsNone(pattern.search(path))


if __name__ == "__main__":
    unittest.main()
