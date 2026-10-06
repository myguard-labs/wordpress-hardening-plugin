"""Check isolation of stateful go-ftw identities without changing assertions."""

import io
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from run_regression import RATE_LIMIT_IDENTITIES, SUITES, prepare_suites, run_ftw


class RegressionIsolationTests(unittest.TestCase):
    def test_fresh_run_preserves_stages_and_assertions(self):
        count = sum(map(len, RATE_LIMIT_IDENTITIES.values()))
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory) / "first", Path(directory) / "second"
            prepare_suites(SUITES, first, [f"198.18.0.{n}" for n in range(1, count + 1)])
            prepare_suites(SUITES, second, [f"198.18.1.{n}" for n in range(1, count + 1)])
            threshold = Path("wordpress-hardening-plugin/9522412.yaml")
            original = (SUITES / threshold).read_text()
            a, b = (first / threshold).read_text(), (second / threshold).read_text()
            self.assertEqual(6, a.count("X-Forwarded-For: 198.18.0.3"))
            self.assertEqual(6, b.count("X-Forwarded-For: 198.18.1.3"))
            self.assertNotIn("203.0.113.77", a + b)
            self.assertEqual(original.count('log_contains: id "9522412"'),
                             a.count('log_contains: id "9522412"'))
            self.assertEqual(original.count('no_log_contains: id "9522412"'),
                             b.count('no_log_contains: id "9522412"'))
            self.assertEqual((SUITES / "wordpress-hardening-plugin/9522113.yaml").read_text(),
                             (first / "wordpress-hardening-plugin/9522113.yaml").read_text())

    def test_missing_identity_fails_closed(self):
        count = sum(map(len, RATE_LIMIT_IDENTITIES.values()))
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            fixture = source / "wordpress-hardening-plugin/9522412.yaml"
            fixture.parent.mkdir(parents=True)
            fixture.write_text("tests: []\n")
            with self.assertRaisesRegex(ValueError, "missing X-Forwarded-For"):
                prepare_suites(source, Path(directory) / "output",
                               [f"198.18.0.{n}" for n in range(1, count + 1)])

    def test_address_count_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(
            ValueError, "one fresh address"
        ):
            prepare_suites(SUITES, Path(directory), [])

    def test_failed_stage_is_failure_even_when_ftw_exits_zero(self):
        results = [type("Result", (), {"stdout": "ftw/check: checked 50 files\n"})(),
                   type("Result", (), {"stdout": "💥 9522412-1 failed in 10ms\n"
                                               "🎉 All tests successful!\n"})()]
        with (tempfile.TemporaryDirectory() as directory,
              patch("run_regression.subprocess.run", side_effect=results),
              self.assertRaisesRegex(RuntimeError, "go-ftw reported failed stages")):
            root = Path(directory)
            run_ftw(root / "ftw", root / "config", root / "suites")

    def test_clean_stage_output_passes(self):
        results = [type("Result", (), {"stdout": "ftw/check: checked 50 files\n"})(),
                   type("Result", (), {"stdout": "🎉 All tests successful!\n"})()]
        output = io.StringIO()
        with (tempfile.TemporaryDirectory() as directory,
              patch("run_regression.subprocess.run", side_effect=results) as runner,
              redirect_stdout(output)):
            root = Path(directory)
            run_ftw(root / "ftw", root / "config", root / "suites")
        self.assertEqual(2, runner.call_count)
        self.assertEqual("ftw/check: checked 50 files\n🎉 All tests successful!\n",
                         output.getvalue())

    def test_check_failure_prints_diagnostics_before_raising(self):
        diagnostic = "ftw/check: malformed suite at line 7\n"
        failure = subprocess.CalledProcessError(1, ["ftw", "check"], output=diagnostic)
        output = io.StringIO()
        with (tempfile.TemporaryDirectory() as directory,
              patch("run_regression.subprocess.run", side_effect=failure) as runner,
              redirect_stdout(output),
              self.assertRaises(subprocess.CalledProcessError) as raised):
            root = Path(directory)
            run_ftw(root / "ftw", root / "config", root / "suites")
        self.assertEqual(1, runner.call_count)
        self.assertIs(failure, raised.exception)
        self.assertIn(diagnostic, output.getvalue())

    def test_run_failure_prints_diagnostics_before_raising(self):
        diagnostic = "ftw/run: request failed with exit status 2\n"
        failure = subprocess.CalledProcessError(2, ["ftw", "run"], output=diagnostic)
        results = [type("Result", (), {"stdout": "ftw/check: checked 50 files\n"})(),
                   failure]
        output = io.StringIO()
        with (tempfile.TemporaryDirectory() as directory,
              patch("run_regression.subprocess.run", side_effect=results) as runner,
              redirect_stdout(output),
              self.assertRaises(subprocess.CalledProcessError) as raised):
            root = Path(directory)
            run_ftw(root / "ftw", root / "config", root / "suites")
        self.assertEqual(2, runner.call_count)
        self.assertIs(failure, raised.exception)
        self.assertIn(diagnostic, output.getvalue())


if __name__ == "__main__":
    unittest.main()
