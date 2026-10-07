"""Build the Coraza probe and exercise harmless body success/error fixtures."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CorazaBodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        for name in ("main.go", "go.mod", "go.sum"):
            shutil.copyfile(ROOT / "tests/coraza" / name, cls.directory / name)
        shutil.copyfile(ROOT / "ci/coraza_body_test.go", cls.directory / "main_test.go")
        cls.probe = cls.directory / "coraza-probe"
        result = subprocess.run(
            ["go", "build", "-mod=readonly", "-o", str(cls.probe), "."],
            cwd=cls.directory, capture_output=True, text=True, check=False,
        )
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)

    def run_probe(self, data, extra_config="", expected_interruption=False, limit_files=False):
        config = self.directory / "body.conf"
        config.write_text(
            'SecAction "id:9900001,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"\n'
            + extra_config
        )
        fixture = self.directory / "body.json"
        fixture.write_text(json.dumps([{
            "name": "isolated-body", "method": "POST", "uri": "/body-check",
            "headers": {"Content-Type": "application/json"}, "data": data,
            "expect_interruption": expected_interruption,
        }]))
        command = [str(self.probe), "-tx", str(fixture), str(config)]
        if limit_files:
            command = ["bash", "-c", 'ulimit -f 0; exec "$@"', "bash", *command]
        return subprocess.run(
            command, cwd=self.directory,
            env={**os.environ, "TMPDIR": str(self.directory)},
            capture_output=True, text=True, check=False,
        )

    def test_go_returned_error_and_interruption_controls(self):
        result = subprocess.run(
            ["go", "test", "-mod=readonly", "-count=1", "-v", "."],
            cwd=self.directory, capture_output=True, text=True, check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("--- PASS: TestProcessRequestBody", result.stdout)

    def test_valid_and_empty_bodies_pass(self):
        for body in ('{"message":"safe"}', ""):
            with self.subTest(body=body):
                result = self.run_probe(body)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertIn("1/1 passed", result.stdout)

    def test_malformed_body_fails_with_processor_diagnostic(self):
        result = self.run_probe('{"message":')
        self.assertNotEqual(0, result.returncode)
        self.assertIn("request body processor: JSON:", result.stdout)
        self.assertIn("0/1 passed", result.stdout)

    def test_write_error_fails_with_diagnostic(self):
        result = self.run_probe(
            '{"message":"safe"}',
            'SecRequestBodyInMemoryLimit 1\n',
            limit_files=True,
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("write request body:", result.stdout)
        self.assertIn("file too large", result.stdout)
        self.assertIn("0/1 passed", result.stdout)

    def test_body_limit_interruption_is_preserved(self):
        result = self.run_probe(
            '{"message":"safe"}', 'SecRequestBodyLimit 1\n',
            expected_interruption=True,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("1/1 passed", result.stdout)

    def test_header_interruption_skips_malformed_body(self):
        result = self.run_probe(
            '{"message":',
            'SecAction "id:9900002,phase:1,deny,status:403,log"\n',
            expected_interruption=True,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("1/1 passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
