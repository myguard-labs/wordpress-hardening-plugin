"""Exercise local CI startup and YAML diagnostics in isolated directories."""

import os
import select
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/ci-local.sh"


def yaml_block():
    script = SCRIPT.read_text()
    return (
        'FAIL=0\nnote() { :; }\nok() { printf "OK: %s\\n" "$1"; }\n'
        'err() { printf "ERROR: %s\\n" "$1"; FAIL=1; }\n'
        + script[script.index('note "regression YAML parses"'):]
    )


class CiLocalRootTests(unittest.TestCase):
    @staticmethod
    def run_startup(directory, env=None):
        startup = SCRIPT.read_text().split("\nFAIL=0\n", 1)[0]
        # Git hooks export repository context that would override the fixture cwd.
        inherited = os.environ if env is None else env
        env = {name: value for name, value in inherited.items() if not name.startswith("GIT_")}
        return subprocess.run(
            ["bash", "-c", startup + '\nprintf "CHECKS_STARTED:%s\\n" "$PWD"\n'],
            cwd=directory, env=env, capture_output=True, text=True, check=False,
        )

    def test_normal_subdirectory_resolves_repository_root(self):
        result = self.run_startup(ROOT / "plugins")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(f"CHECKS_STARTED:{ROOT}\n", result.stdout)

    def test_non_repository_stops_before_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_startup(directory)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("CI-local: cannot resolve repository root", result.stderr)
        self.assertNotIn("CHECKS_STARTED", result.stdout)

    def test_failed_cd_stops_before_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            git = Path(directory) / "git"
            git.write_text('#!/bin/sh\nprintf "%s\\n" "$CI_ROOT_TEST_TARGET"\n')
            git.chmod(0o755)
            env = {**os.environ, "PATH": directory + os.pathsep + os.environ["PATH"],
                   "CI_ROOT_TEST_TARGET": str(Path(directory) / "missing")}
            result = self.run_startup(directory, env)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("CI-local: cannot enter repository root", result.stderr)
        self.assertNotIn("CHECKS_STARTED", result.stdout)

    def test_hook_environment_does_not_override_fixture_directory(self):
        hook_env = {
            **os.environ, "GIT_DIR": str(ROOT / ".git"),
            "GIT_WORK_TREE": ".", "GIT_PREFIX": "",
        }
        with tempfile.TemporaryDirectory() as outside:
            for explicit_env in (False, True):
                with self.subTest(explicit_env=explicit_env), mock.patch.dict(
                    os.environ, hook_env, clear=True
                ):
                    env = hook_env if explicit_env else None
                    normal = self.run_startup(ROOT / "plugins", env)
                    self.assertEqual(0, normal.returncode, normal.stderr)
                    self.assertEqual(f"CHECKS_STARTED:{ROOT}\n", normal.stdout)
                    invalid = self.run_startup(outside, env)
                    self.assertNotEqual(0, invalid.returncode)
                    self.assertIn("cannot resolve repository root", invalid.stderr)
                    self.assertNotIn("CHECKS_STARTED", invalid.stdout)


class CiLocalYamlTempTests(unittest.TestCase):
    def test_real_yaml_diagnostics_and_cleanup(self):
        for content, expected in (("valid: true\n", 0), ("broken: [\n", 1)):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                corpus = root / "tests/regression/wordpress-hardening-plugin"
                corpus.mkdir(parents=True)
                (corpus / "fixture.yaml").write_text(content)
                scratch = root / "scratch"
                scratch.mkdir()
                result = subprocess.run(
                    ["bash", "-c", yaml_block()], cwd=root,
                    env={**os.environ, "TMPDIR": str(scratch)},
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(expected, result.returncode, result.stdout + result.stderr)
                if expected:
                    self.assertIn("invalid regression YAML:", result.stdout)
                    self.assertIn("yaml.parser.ParserError", result.stdout)
                else:
                    self.assertIn("all regression YAML valid", result.stdout)
                self.assertEqual([], list(scratch.iterdir()))

    def test_mktemp_failure_stops_with_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                ["bash", "-c", yaml_block()], cwd=directory,
                env={**os.environ, "TMPDIR": str(Path(directory) / "missing")},
                capture_output=True, text=True, check=False,
            )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("cannot create temporary file for regression YAML errors", result.stdout)
        self.assertNotIn("all regression YAML valid", result.stdout)

    def test_parallel_runs_have_distinct_files_and_clean_up(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            python = root / "python3"
            # Keep the fixture independent of procfs, including on Linux test hosts.
            python.write_text(
                f"#!{sys.executable}\nimport os, sys\n"
                'from pathlib import Path\n'
                'from unittest.mock import patch\n'
                'with patch("os.readlink", side_effect=FileNotFoundError("procfs unavailable")):\n'
                '    stderr = os.fstat(2)\n'
                '    paths = [path for path in Path(os.environ["TMPDIR"]).iterdir()\n'
                '             if os.path.samestat(path.stat(), stderr)]\n'
                '    if len(paths) != 1:\n'
                '        raise RuntimeError("cannot identify temporary diagnostics file")\n'
                '    print(paths[0], flush=True)\n'
                'sys.stdin.readline()\n'
                'sys.stderr.write("isolated YAML error\\n")\n'
                'sys.exit(int(os.environ["CI_YAML_TEST_STATUS"]))\n'
            )
            python.chmod(0o755)
            processes = []
            try:
                for status in (0, 1):
                    processes.append(subprocess.Popen(
                        ["bash", "-c", yaml_block()], cwd=root,
                        env={**os.environ, "PATH": directory + os.pathsep + os.environ["PATH"],
                             "TMPDIR": directory, "CI_YAML_TEST_STATUS": str(status)},
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, text=True,
                    ))
                paths = []
                for process in processes:
                    ready, _, _ = select.select([process.stdout], [], [], 10)
                    self.assertTrue(ready, "YAML diagnostic writer did not start")
                    path = Path(process.stdout.readline().strip())
                    self.assertTrue(path.is_file(), str(path))
                    self.assertEqual(root, path.parent)
                    paths.append(path)
                self.assertNotEqual(paths[0], paths[1])
                for status, process in enumerate(processes):
                    stdout, stderr = process.communicate("\n", timeout=10)
                    self.assertEqual(status, process.returncode, stdout + stderr)
                    if status:
                        self.assertIn("invalid regression YAML: isolated YAML error", stdout)
                for path in paths:
                    self.assertFalse(path.exists(), f"temporary diagnostics leaked: {path}")
            finally:
                for process in processes:
                    if process.poll() is None:
                        process.kill()
                    process.communicate()


if __name__ == "__main__":
    unittest.main()
