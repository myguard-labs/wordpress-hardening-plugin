"""Regression controls for the go-ftw positive coverage gate."""

import tempfile
import unittest
from pathlib import Path

import yaml
from check_ftw_positives import check_positives

ROOT = Path(__file__).resolve().parents[1]
SUITES = ROOT / "tests/regression/wordpress-hardening-plugin"
CONFIG = ROOT / "tests/integration/.ftw.yml"
WORKFLOW = ROOT / ".github/workflows/lint.yml"


class FtwPositiveTests(unittest.TestCase):
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
