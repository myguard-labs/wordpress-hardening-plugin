"""Guard strict YAML validation and its position before go-ftw."""

import contextlib
import io
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from check_security_corpus import check_corpus

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests/security"
FALSE_POSITIVES = CORPUS / "wordpress-hardening-plugin/false-positives.yaml"
WORKFLOW = ROOT / ".github/workflows/security-corpus.yml"
CHECKER = ROOT / "ci/check_security_corpus.py"


class SecurityCorpusTest(unittest.TestCase):
    def test_committed_corpus_is_valid(self):
        self.assertGreater(check_corpus(CORPUS), 0)

    def test_duplicate_key_in_false_positives_fails_before_ftw(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "false-positives.yaml"
            fixture = FALSE_POSITIVES.read_text()
            self.assertIn("  enabled: true\n", fixture)
            path.write_text(
                fixture.replace(
                    "  enabled: true\n", "  enabled: true\n  enabled: false\n", 1
                )
            )
            result = subprocess.run(
                [sys.executable, str(CHECKER), directory],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("duplicate mapping key 'enabled'", result.stderr)
            self.assertIn("false-positives.yaml", result.stderr)

    def test_nested_duplicate_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "nested.yml").write_text(
                "tests:\n  - output:\n      status: 200\n      status: 403\n"
            )
            with self.assertRaisesRegex(ValueError, "duplicate mapping key 'status'"):
                check_corpus(Path(directory))

    def test_malformed_yaml_and_empty_corpus_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory)
            with self.assertRaisesRegex(ValueError, "no YAML corpus files"):
                check_corpus(corpus)
            (corpus / "invalid.yaml").write_text("tests: [\n")
            with self.assertRaisesRegex(ValueError, "invalid.yaml"):
                check_corpus(corpus)

    def test_unhashable_mapping_key_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "invalid.yaml").write_text("? [one, two]\n: value\n")
            with self.assertRaisesRegex(ValueError, "unhashable mapping key"):
                check_corpus(Path(directory))

    def test_merge_override_is_valid_but_duplicate_explicit_key_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "merge.yaml"
            path.write_text(
                "defaults: &defaults\n  enabled: false\n"
                "case:\n  <<: *defaults\n  enabled: true\n"
            )
            self.assertEqual(1, check_corpus(Path(directory)))

            path.write_text(path.read_text() + "  enabled: false\n")
            with self.assertRaisesRegex(ValueError, "duplicate mapping key 'enabled'"):
                check_corpus(Path(directory))

    def test_cli_reports_success_and_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory)
            (corpus / "valid.yaml").write_text("meta:\n  enabled: true\n")
            output = io.StringIO()
            with contextlib.redirect_stdout(output), mock.patch.object(
                sys, "argv", [str(CHECKER), str(corpus)]
            ):
                runpy.run_path(str(CHECKER), run_name="__main__")
            self.assertIn("Validated 1 security corpus YAML files", output.getvalue())

            (corpus / "valid.yaml").write_text("meta: [\n")
            errors = io.StringIO()
            with (
                contextlib.redirect_stderr(errors),
                mock.patch.object(sys, "argv", [str(CHECKER), str(corpus)]),
                self.assertRaises(SystemExit) as exit_status,
            ):
                runpy.run_path(str(CHECKER), run_name="__main__")
            self.assertEqual(1, exit_status.exception.code)
            self.assertIn("valid.yaml", errors.getvalue())

    def test_workflow_validates_before_ftw(self):
        workflow = WORKFLOW.read_text()
        self.assertIn("python3 ci/check_security_corpus.py tests/security", workflow)
        self.assertIn("./ftw check -d tests/security", workflow)
        self.assertLess(
            workflow.index("python3 ci/check_security_corpus.py tests/security"),
            workflow.index("./ftw check -d tests/security"),
        )


if __name__ == "__main__":
    unittest.main()
