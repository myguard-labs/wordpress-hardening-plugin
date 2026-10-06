"""Regression controls for the go-ftw positive coverage gate."""

import tempfile
import unittest
from pathlib import Path

import yaml
from check_ftw_positives import NO_POSITIVE_RULES, check_positives

ROOT = Path(__file__).resolve().parents[1]
SUITES = ROOT / "tests/regression/wordpress-hardening-plugin"
CONFIG = ROOT / "tests/integration/.ftw.yml"
WORKFLOW = ROOT / ".github/workflows/lint.yml"
DIRECT_RULES = ("9522107", "9522111", "9522122")


class FtwPositiveTests(unittest.TestCase):
    def test_encoded_null_path_has_live_positive_and_apache_boundary(self):
        suite = yaml.safe_load((SUITES / "9522309.yaml").read_text())
        self.assertEqual(
            [f"9522309-{number}" for number in range(1, 6)],
            [test["test_title"] for test in suite["tests"]],
        )
        stages = {test["test_title"]: test["stages"][0] for test in suite["tests"]}
        positive = stages["9522309-1"]
        boundary = stages["9522309-5"]
        self.assertEqual("/wp-content/uploads/image%2500.php", positive["input"]["uri"])
        self.assertEqual('id "9522309"', positive["output"]["log_contains"])
        self.assertEqual("/wp-content/uploads/image%00.php", boundary["input"]["uri"])
        self.assertEqual('id "9522309"', boundary["output"]["no_log_contains"])
        ignored = yaml.safe_load(CONFIG.read_text())["testoverride"]["ignore"]
        self.assertNotIn("9522309-1", ignored)
        self.assertNotIn("9522309-5", ignored)

    def test_lint_workflow_runs_guard(self):
        steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["validate-files"]["steps"]
        run = next(step["run"] for step in steps if step.get("name") == "CI unit tests")
        commands = [
            line.strip()
            for line in run.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        checker = "ci/check_ftw_positives.py \\"
        self.assertIn(checker, commands)
        self.assertTrue(
            any(
                line.startswith("tests/regression/wordpress-hardening-plugin ")
                for line in commands
            )
        )
        self.assertIn("tests/integration/.ftw.yml", commands)
        self.assertLess(
            commands.index(checker),
            next(
                index for index, line in enumerate(commands) if "discover -s ci" in line
            ),
        )

    def test_committed_suites_keep_live_positive(self):
        self.assertGreater(check_positives(SUITES, CONFIG), 0)

    def test_direct_rule_positives_are_live_and_not_exempted(self):
        settings = yaml.safe_load(CONFIG.read_text())
        ignored = settings["testoverride"]["ignore"]
        for rule_id in DIRECT_RULES:
            with self.subTest(rule_id=rule_id):
                self.assertNotIn(rule_id, NO_POSITIVE_RULES)
                suite = yaml.safe_load((SUITES / f"{rule_id}.yaml").read_text())
                positives = [
                    test
                    for test in suite["tests"]
                    if any(
                        stage.get("output", {}).get("log_contains") == f'id "{rule_id}"'
                        for stage in test["stages"]
                    )
                ]
                self.assertEqual(1, len(positives))
                self.assertNotIn(positives[0]["test_title"], ignored)

    def test_9522115_live_positives_are_counted(self):
        suite = yaml.safe_load((SUITES / "9522115.yaml").read_text())
        self.assertNotIn("9522115", NO_POSITIVE_RULES)
        self.assertTrue(suite["meta"]["enabled"])
        positives = [
            test
            for test in suite["tests"]
            if any("log_contains" in stage.get("output", {}) for stage in test["stages"])
        ]
        self.assertEqual(3, len(positives))
        ignored = yaml.safe_load(CONFIG.read_text())["testoverride"]["ignore"]
        self.assertTrue(all(test["test_title"] not in ignored for test in positives))
        self.assertGreater(check_positives(SUITES, CONFIG), 0)

    def test_9522120_traversal_and_benign_query_controls(self):
        suite = yaml.safe_load((SUITES / "9522120.yaml").read_text())
        tests = {test["test_title"]: test["stages"][0] for test in suite["tests"]}
        prefix = "/wp-admin/admin-ajax.php?action=revslider_show_image&img="
        self.assertEqual(
            prefix + "..%2Fwp-config.php", tests["9522120-1"]["input"]["uri"]
        )
        self.assertEqual('id "9522120"', tests["9522120-1"]["output"]["log_contains"])
        self.assertEqual(
            prefix + "../wp-config.php", tests["9522120-100"]["input"]["uri"]
        )
        self.assertEqual('id "9522120"', tests["9522120-100"]["output"]["log_contains"])
        self.assertEqual(
            "/search?q=revslider_show_image", tests["9522120-101"]["input"]["uri"]
        )
        self.assertEqual('id "9522120"', tests["9522120-101"]["output"]["no_log_contains"])
        ignored = yaml.safe_load(CONFIG.read_text())["testoverride"]["ignore"]
        self.assertNotIn("9522120-1", ignored)
        self.assertNotIn("9522120-100", ignored)
        self.assertNotIn("9522120-101", ignored)

    def test_9522115_fails_when_all_live_positives_are_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            suite = yaml.safe_load((SUITES / "9522115.yaml").read_text())
            for test in suite["tests"]:
                for stage in test["stages"]:
                    stage.get("output", {}).pop("log_contains", None)
            (root / "9522115.yaml").write_text(yaml.safe_dump(suite))
            with self.assertRaisesRegex(
                ValueError, "9522115.yaml: no non-ignored log_contains positive"
            ):
                check_positives(root, CONFIG)

    def test_author_archive_default_control_has_no_override(self):
        suite = yaml.safe_load((SUITES / "9522122.yaml").read_text())
        positive, default = suite["tests"]
        positive_stage = positive["stages"][0]
        default_stage = default["stages"][0]
        self.assertEqual("/author/john-doe/", positive_stage["input"]["uri"])
        self.assertEqual(positive_stage["input"]["uri"], default_stage["input"]["uri"])
        self.assertEqual(
            "1", positive_stage["input"]["headers"]["X-WPHard-Enable-Author-Archives"]
        )
        self.assertNotIn(
            "X-WPHard-Enable-Author-Archives", default_stage["input"]["headers"]
        )
        self.assertEqual('id "9522122"', default_stage["output"]["no_log_contains"])
        fixture = (ROOT / "tests/integration/ci-plugin/zzz-ci-config.conf").read_text()
        self.assertIn(
            'SecRule REQUEST_HEADERS:X-WPHard-Enable-Author-Archives "@streq 1"',
            fixture,
        )
        self.assertNotIn('SecAction "id:9519998', fixture)
        before = (ROOT / "plugins/wordpress-hardening-before.conf").read_text()
        self.assertIn("setvar:tx.wphard.block_author_archives=0", before)

    def test_each_direct_positive_missing_is_rejected(self):
        for rule_id in DIRECT_RULES:
            with (
                self.subTest(rule_id=rule_id),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                suite = yaml.safe_load((SUITES / f"{rule_id}.yaml").read_text())
                for test in suite["tests"]:
                    for stage in test["stages"]:
                        stage.get("output", {}).pop("log_contains", None)
                (root / f"{rule_id}.yaml").write_text(yaml.safe_dump(suite))
                with self.assertRaisesRegex(
                    ValueError, f"{rule_id}.yaml: no non-ignored"
                ):
                    check_positives(root, CONFIG)

    def test_all_positives_ignored_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "ftw.yml"
            settings = yaml.safe_load(CONFIG.read_text())
            settings["testoverride"]["ignore"].update(
                {f"9522307-{number}": "mutated" for number in (1, 2, 3, 5)}
            )
            config.write_text(yaml.safe_dump(settings))
            with self.assertRaisesRegex(ValueError, "9522307.yaml: no non-ignored"):
                check_positives(SUITES, config)

    def test_one_positive_survives_and_negative_does_not_count(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            suite = root / "9522999.yaml"
            config = root / "ftw.yml"
            config.write_text("testoverride:\n  ignore:\n    9522999-1: skipped\n")
            suite.write_text(
                "meta:\n  enabled: true\ntests:\n"
                "  - test_title: 9522999-1\n    stages:\n"
                "      - output:\n          log_contains: 'id \"9522999\"'\n"
                "  - test_title: 9522999-2\n    stages:\n"
                "      - output:\n          no_log_contains: 'id \"9522999\"'\n"
            )
            with self.assertRaisesRegex(ValueError, "no non-ignored"):
                check_positives(root, config)
            config.write_text("testoverride:\n  ignore: {}\n")
            self.assertEqual(1, check_positives(root, config))


if __name__ == "__main__":
    unittest.main()
