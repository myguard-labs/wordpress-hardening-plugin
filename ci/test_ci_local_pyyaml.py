"""Exercise the local go-ftw dependency diagnostic with and without PyYAML."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/ci-local.sh"


class CiLocalPyYamlTests(unittest.TestCase):
    @staticmethod
    def run_checker_block(python_dir):
        script = SCRIPT.read_text(encoding="utf-8")
        start = script.index("if python3 ci/check_ftw_positives.py \\\n")
        end = script.index("if python3 -B -m unittest discover", start)
        block = script[start:end]
        harness = (
            "FAIL=0\n"
            'ok() { printf "OK: %s\\n" "$1"; }\n'
            'err() { printf "ERROR: %s\\n" "$1"; FAIL=1; }\n'
            + block
            + 'printf "CI-local: %s\\n" "$([ "$FAIL" -eq 0 ] && echo passed || echo FAILED)"\n'
            + 'exit "$FAIL"\n'
        )
        env = os.environ.copy()
        env["PATH"] = f"{python_dir}{os.pathsep}{env['PATH']}"
        return subprocess.run(
            ["bash", "-c", harness], cwd=ROOT, env=env,
            capture_output=True, text=True, check=False,
        )

    def test_missing_pyyaml_reports_hint_and_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, "-m", "venv", "--without-pip", directory],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            python_dir = Path(directory) / "bin"
            missing = subprocess.run(
                [python_dir / "python3", "-c", "import yaml"],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(0, missing.returncode)
            result = self.run_checker_block(python_dir)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("PyYAML is required for go-ftw positive coverage", result.stdout)
        self.assertIn("ERROR: go-ftw positive coverage failed", result.stdout)
        self.assertLess(
            result.stdout.index("PyYAML is required"),
            result.stdout.index("CI-local: FAILED"),
        )

    def test_installed_pyyaml_checker_passes(self):
        installed = subprocess.run(
            [sys.executable, "-c", "import yaml"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(0, installed.returncode, installed.stderr)
        result = self.run_checker_block(Path(sys.executable).parent)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("OK: go-ftw positive coverage", result.stdout)
        self.assertNotIn("PyYAML is required", result.stdout)

    def test_checker_failure_with_pyyaml_keeps_generic_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            python = Path(directory) / "python3"
            python.write_text(
                f"#!/bin/sh\n"
                f'if [ "$1" = "-c" ]; then exec "{sys.executable}" "$@"; fi\n'
                'printf "checker failed\\n" >&2\n'
                'exit 7\n'
            )
            python.chmod(0o755)
            result = self.run_checker_block(directory)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("checker failed", result.stderr)
        self.assertIn("ERROR: go-ftw positive coverage failed", result.stdout)
        self.assertNotIn("PyYAML is required", result.stdout)


if __name__ == "__main__":
    unittest.main()
