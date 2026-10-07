"""Exercise the Coraza runtime CLI contract, including error exits."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BUILD_TIMEOUT = 300
PROBE_TIMEOUT = 30


def run_bounded(command, *, cwd, timeout, label):
    try:
        return subprocess.run(
            command, cwd=cwd, capture_output=True, text=True, check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{label} timed out after {timeout}s") from exc


class CorazaRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Class-level setup shares one workdir; unittest manages its cleanup.
        cls.temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        for name in ("main.go", "go.mod", "go.sum"):
            shutil.copyfile(ROOT / "tests/coraza" / name, cls.directory / name)
        probe_path = os.environ.get("CORAZA_PROBE_PATH", cls.directory / "coraza-probe")
        cls.probe = Path(probe_path).expanduser().resolve()
        if "CORAZA_PROBE_PATH" not in os.environ:
            result = run_bounded(
                ["go", "build", "-mod=readonly", "-o", str(cls.probe), "."],
                cwd=cls.directory, timeout=BUILD_TIMEOUT, label="Coraza probe build",
            )
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
        cls.config = cls.directory / "runner.conf"
        cls.config.write_text(
            'SecRule ARGS "@streq yes" "id:9900101,phase:2,pass,nolog"\n'
        )

    def run_probe(self, payload, *configs):
        fixture = self.directory / "transactions.json"
        fixture.write_text(payload)
        return self._run_probe(fixture, *configs)

    def _run_probe(self, fixture, *configs):
        try:
            return run_bounded(
                [str(self.probe), "-tx", str(fixture), *(str(path) for path in configs)],
                cwd=self.directory, timeout=PROBE_TIMEOUT, label="Coraza probe",
            )
        except RuntimeError as exc:
            self.fail(str(exc))

    def test_expected_rule_fires_and_cli_summary_is_preserved(self):
        result = self.run_probe(json.dumps([{
            "name": "expected-rule", "uri": "/?probe=yes", "expect_ids": [9900101],
        }]), self.config)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("PASS expected-rule", result.stdout)
        self.assertIn("fired=[9900101]", result.stdout)
        self.assertIn("1/1 passed", result.stdout)

    def test_expected_ids_must_fire(self):
        result = self.run_probe(json.dumps([{
            "name": "missing-rule", "uri": "/", "expect_ids": [9900102],
        }]), self.config)
        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        self.assertIn("FAIL missing-rule", result.stdout)
        self.assertIn("expected id 9900102 did not fire", result.stdout)
        self.assertIn("0/1 passed", result.stdout)

    def test_forbidden_rule_firing_fails(self):
        result = self.run_probe(json.dumps([{
            "name": "forbidden-rule", "uri": "/?probe=yes", "no_expect_ids": [9900101],
        }]), self.config)
        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        self.assertIn("forbidden id 9900101 fired", result.stdout)

    def test_missing_fixture_has_read_exit_code(self):
        missing = self.directory / "missing.json"
        result = self._run_probe(missing, self.config)
        self.assertEqual(2, result.returncode)
        self.assertIn(f"read {missing}:", result.stderr)

    def test_expected_interruption_is_preserved(self):
        deny = self.directory / "deny.conf"
        deny.write_text('SecAction "id:9900102,phase:1,deny,status:403,log"\n')
        result = self.run_probe(json.dumps([{
            "name": "expected-deny", "expect_interruption": True,
        }]), deny)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("PASS expected-deny", result.stdout)
        self.assertIn("1/1 passed", result.stdout)

    def test_malformed_json_has_parse_exit_code(self):
        result = self.run_probe("[", self.config)
        self.assertEqual(2, result.returncode)
        self.assertIn("parse ", result.stderr)

    def test_invalid_ruleset_has_load_exit_code(self):
        invalid = self.directory / "invalid.conf"
        invalid.write_text("SecUnknownDirective yes\n")
        result = self.run_probe("[]", invalid)
        self.assertEqual(1, result.returncode)
        self.assertIn("LOAD-FATAL:", result.stderr)

    def test_probe_timeout_is_test_failure(self):
        timeout = subprocess.TimeoutExpired("probe", PROBE_TIMEOUT)
        with (patch.object(subprocess, "run", side_effect=timeout),
              self.assertRaisesRegex(AssertionError, "Coraza probe timed out after 30s")):
            self.run_probe("[]", self.config)


class BoundedProcessTests(unittest.TestCase):
    def test_command_receives_timeout(self):
        completed = subprocess.CompletedProcess(["probe"], 0)
        with patch.object(subprocess, "run", return_value=completed) as runner:
            self.assertIs(completed, run_bounded(
                ["probe"], cwd=ROOT, timeout=PROBE_TIMEOUT, label="Coraza probe",
            ))
        runner.assert_called_once_with(
            ["probe"], cwd=ROOT, capture_output=True, text=True, check=False,
            timeout=PROBE_TIMEOUT,
        )

    def test_build_timeout_reports_setup_failure(self):
        timeout = subprocess.TimeoutExpired("go build", BUILD_TIMEOUT)
        with (patch.object(subprocess, "run", side_effect=timeout),
              self.assertRaisesRegex(RuntimeError, "Coraza probe build timed out after 300s")):
            run_bounded(["go", "build"], cwd=ROOT, timeout=BUILD_TIMEOUT,
                        label="Coraza probe build")


if __name__ == "__main__":
    unittest.main()
