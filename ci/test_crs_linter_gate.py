"""Exercise the mandatory plugin-compatible CRS linter gate."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "ci/check_crs_linter.py"
BEFORE = ROOT / "plugins/wordpress-hardening-before.conf"


@unittest.skipUnless(shutil.which("crs-linter"), "crs-linter is not installed")
class CrsLinterGateTests(unittest.TestCase):
    def run_gate(self, source):
        with tempfile.TemporaryDirectory() as directory:
            rules = Path(directory) / BEFORE.name
            rules.write_text(source)
            return subprocess.run(
                ["python3", str(GATE), str(rules)],
                capture_output=True, text=True, check=False,
            )

    def test_plugin_core_findings_excluded(self):
        result = self.run_gate(BEFORE.read_text())
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("crs-linter subset: passed", result.stdout)

    def test_matching_rule_glob_passes(self):
        result = subprocess.run(
            ["python3", str(GATE), str(ROOT / "plugins/wordpress-hardening-before.*")],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("crs-linter subset: passed", result.stdout)

    def test_pass_without_nolog_fails_named_gate(self):
        source = BEFORE.read_text()
        marker = "#crs-linter:ignore:pass_nolog"
        self.assertIn(marker, source)
        result = self.run_gate(source.replace(marker, "", 1))
        self.assertNotEqual(0, result.returncode)
        self.assertIn("rule uses 'pass' without 'nolog'; rule id: 9522121", result.stderr)
        self.assertIn("crs-linter subset: FAILED", result.stderr)

    def test_malformed_rule_fails_named_gate(self):
        result = self.run_gate('SecRule ARGS "@rx foo" "id:9522121,broken\n')
        self.assertNotEqual(0, result.returncode)
        self.assertIn("Can't parse config file:", result.stderr)


class CrsLinterWiringTests(unittest.TestCase):
    def test_ci_checkouts_fetch_tags_without_persisting_credentials(self):
        for name, job in (("lint.yml", "validate-files"),
                          ("plugin-lint.yml", "check-syntax")):
            with self.subTest(workflow=name):
                workflow = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())
                checkout = next(
                    step for step in workflow["jobs"][job]["steps"]
                    if step.get("uses", "").startswith("actions/checkout@")
                )
                self.assertEqual(0, checkout["with"]["fetch-depth"])
                self.assertIs(False, checkout["with"]["persist-credentials"])

    def test_nonexistent_literal_rule_path_fails(self):
        missing = ROOT / "plugins/does-not-exist.conf"
        result = subprocess.run(
            ["python3", str(GATE), str(missing)],
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn(f"no rule files matched: {missing}", result.stderr)

    def test_unmatched_rule_glob_fails(self):
        unmatched = ROOT / "plugins/no-such-rule-*.conf"
        result = subprocess.run(
            ["python3", str(GATE), str(unmatched)],
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn(f"no rule files matched: {unmatched}", result.stderr)

    def test_directory_only_rule_glob_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            rule_dir = Path(directory) / "rule-directory"
            rule_dir.mkdir()
            result = subprocess.run(
                ["python3", str(GATE), str(Path(directory) / "*")],
                capture_output=True, text=True, check=False,
            )
        self.assertNotEqual(0, result.returncode)
        self.assertIn(f"matched path is not a rule file: {rule_dir}", result.stderr)

    def test_mixed_file_and_directory_glob_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            rule_dir = Path(directory) / "rule-directory"
            rule_dir.mkdir()
            rule_file = Path(directory) / "rule.conf"
            rule_file.write_text("SecRule ARGS \"@rx foo\" \"id:9522121,phase:1,deny\"\n")
            result = subprocess.run(
                ["python3", str(GATE), str(Path(directory) / "*")],
                capture_output=True, text=True, check=False,
            )
        self.assertNotEqual(0, result.returncode)
        self.assertIn(f"matched path is not a rule file: {rule_dir}", result.stderr)

    def test_ci_and_local_run_named_gate(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/plugin-lint.yml").read_text())
        steps = workflow["jobs"]["check-syntax"]["steps"]
        gate = next(
            step for step in steps
            if step.get("name") == "Check crs-linter plugin-compatible subset"
        )
        self.assertNotIn("if", gate)
        self.assertIn("python -m pip install crs-linter==1.2.0", gate["run"])
        self.assertIn("python ci/check_crs_linter.py", gate["run"])
        local = (ROOT / "scripts/ci-local.sh").read_text()
        self.assertIn("python3 ci/check_crs_linter.py", local)


if __name__ == "__main__":
    unittest.main()
