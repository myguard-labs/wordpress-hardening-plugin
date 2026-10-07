"""Keep the CRS-953 integration oracle reachable and discriminating."""

import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "tests/integration/backend/nginx.conf"
COMPOSE = ROOT / "tests/integration/docker-compose.yml"
REGRESSION = ROOT / "tests/regression/wordpress-hardening-plugin/9522801.yaml"
CORPUS = ROOT / "tests/security/wordpress-hardening-plugin/false-positives.yaml"
RULE_IDS = (953100, 953110, 953120)


def cases(path):
    return {
        case["test_title"]: case["stages"][0]
        for case in yaml.safe_load(path.read_text())["tests"]
    }


class ResponseOracleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        config = BACKEND.read_text()
        match = re.search(
            r"location ~ (\S+) \{\s+default_type text/html;\s+return 200 '([^']+)';",
            config,
        )
        if match is None:
            raise AssertionError("PHP tutorial response location is missing")
        cls.path_pattern = re.compile(match.group(1))
        cls.body = match.group(2)
        cls.regression = cases(REGRESSION)
        cls.corpus = cases(CORPUS)

    def test_response_inspection_and_three_distinct_php_markers(self):
        self.assertEqual(
            "On",
            yaml.safe_load(COMPOSE.read_text())["x-modsec-env"]["MODSEC_RESP_BODY_ACCESS"],
        )
        for marker in ("Fatal error:", "readfile", "<?php "):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.body)

    def test_all_named_permalinks_reach_tutorial_response(self):
        for stage in (
            self.corpus["fp-tutorial-permalink-php-keywords"],
            self.regression["9522801-1"],
            self.regression["9522801-3"],
        ):
            uri = stage["input"]["uri"]
            with self.subTest(uri=uri):
                self.assertIsNotNone(self.path_pattern.fullmatch(uri))
                forbidden = re.compile(stage["output"]["no_log_contains"])
                for rule_id in RULE_IDS:
                    self.assertIsNotNone(forbidden.search(f'id "{rule_id}"'))

    def test_admin_and_rest_controls_require_all_three_detectors(self):
        controls = (
            self.regression["9522801-4"],
            self.regression["9522801-5"],
            self.regression["9522801-6"],
        )
        observed = set()
        for stage in controls:
            uri = stage["input"]["uri"]
            with self.subTest(uri=uri):
                self.assertIsNotNone(self.path_pattern.fullmatch(uri))
                assertion = stage["output"]["log_contains"]
                observed.update(
                    rule_id for rule_id in RULE_IDS if assertion == f'id "{rule_id}"'
                )
        self.assertEqual(set(RULE_IDS), observed)

    def test_other_paths_do_not_receive_php_tutorial_response(self):
        for uri in (
            "/",
            "/wp-login.php",
            "/wp-content/demo.js",
            "/wp-admin/953-response-oracle/extra",
        ):
            with self.subTest(uri=uri):
                self.assertIsNone(self.path_pattern.fullmatch(uri))


if __name__ == "__main__":
    unittest.main()
