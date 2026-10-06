"""Guard the policy-compatible lint workflow call and its checks."""

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CALLER = ROOT / ".github/workflows/lint.yml"
CALLEE = ROOT / ".github/workflows/plugin-lint.yml"


def run_blocks(workflow):
    """Return shell lines from unconditional steps, grouped by run block."""
    blocks = []
    for job in yaml.safe_load(workflow)["jobs"].values():
        if "if" in job:
            continue
        for step in job.get("steps", []):
            if "if" in step or "run" not in step:
                continue
            blocks.append([
                line.strip() for line in step["run"].splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ])
    return blocks


class RunBlocksTests(unittest.TestCase):
    def test_unconditional_run_blocks(self):
        workflow = """jobs:
  lint:
    steps:
      - uses: actions/checkout
      - run: |
          # A comment is not executable.

          lint .
      - run: check .
  reusable:
    uses: ./.github/workflows/plugin-lint.yml
"""
        self.assertEqual([["lint ."], ["check ."]], run_blocks(workflow))

    def test_conditional_steps_do_not_satisfy_required_checks(self):
        for condition in ("false", "'false'", "${{ false }}", "success()"):
            with self.subTest(condition=condition):
                workflow = f"""jobs:
  lint:
    steps:
      - run: lint .
        if: {condition}
"""
                self.assertEqual([], run_blocks(workflow))

    def test_disabled_job_does_not_satisfy_required_checks(self):
        workflow = """jobs:
  lint:
    if: false
    steps:
      - run: lint .
"""
        self.assertEqual([], run_blocks(workflow))


class LintWorkflowTests(unittest.TestCase):
    def test_plugin_lint_uses_local_reusable_workflow(self):
        caller = CALLER.read_text()
        job = re.search(r"(?ms)^  plugin-lint:\n(?P<body>(?:^    .*\n|^$)*)", caller)
        self.assertIsNotNone(job)
        self.assertIn("    needs: validate-files\n", job.group("body"))
        self.assertIn("    timeout-minutes: 20\n", caller)
        self.assertIn(
            "    uses: ./.github/workflows/plugin-lint.yml\n", job.group("body")
        )

    def test_reusable_workflow_keeps_all_plugin_checks(self):
        callee = CALLEE.read_text()
        self.assertRegex(callee, r"(?m)^  workflow_call:$")
        self.assertRegex(callee, r"(?m)^  check-syntax:$")
        self.assertIn("permissions:\n  contents: read\n", callee)
        self.assertIn("    timeout-minutes: 20\n", callee)
        external_uses = re.findall(r"(?m)^\s+uses: (?!actions/)(\S+)", callee)
        self.assertEqual([], external_uses)

    def test_yaml_lint_is_executable(self):
        blocks = run_blocks(CALLEE.read_text())
        yaml_blocks = [
            block for block in blocks if "python -m pip install yamllint==1.38.0" in block
        ]
        self.assertEqual(1, len(yaml_blocks))
        self.assertIn("yamllint -f github -d 'extends: default", yaml_blocks[0])
        self.assertIn("min-spaces-from-content: 1' tests/regression", yaml_blocks[0])

    def test_line_lint_is_executable(self):
        blocks = run_blocks(CALLEE.read_text())
        line_blocks = [block for block in blocks if any("linelint_sha=" in line for line in block)]
        self.assertEqual(1, len(line_blocks))
        commands = line_blocks[0]
        self.assertIn("linelint_sha=7907a5dca0c28ea7dd05c6d8d8cacded713aca11", commands)
        self.assertIn('GOBIN="${RUNNER_TEMP}/linelint-bin" go install \\', commands)
        self.assertIn('"github.com/fernandrone/linelint@${linelint_sha}"', commands)
        self.assertIn('"${RUNNER_TEMP}/linelint-bin/linelint" .', commands)

    def test_secrules_lint_is_executable(self):
        blocks = run_blocks(CALLEE.read_text())
        parser_blocks = [
            block for block in blocks if "python -m pip install secrules-parsing==0.3.0" in block
        ]
        self.assertEqual(1, len(parser_blocks))
        commands = parser_blocks[0]
        self.assertIn("python -m pip install --upgrade setuptools==80.10.2", commands)
        self.assertIn("secrules-parser -c -v --output-type github -f plugins/*.conf", commands)


class LintPipelineTests(unittest.TestCase):
    def run_check(self, step_name, configs, data_files=()):
        steps = yaml.safe_load(CALLER.read_text())["jobs"]["validate-files"]["steps"]
        script = next(step["run"] for step in steps if step.get("name") == step_name)
        with tempfile.TemporaryDirectory() as directory:
            plugins = Path(directory) / "plugins"
            plugins.mkdir()
            for name, contents in configs.items():
                (plugins / name).write_text(contents)
            for name in data_files:
                (plugins / name).write_text("fixture\n")
            return subprocess.run(
                ["bash", "--noprofile", "--norc", "-c",
                 "set +e\nset +o pipefail\n" + script],
                cwd=directory, capture_output=True, text=True, check=False,
            )

    def test_existing_pmfromfile_references_pass_without_errexit(self):
        result = self.run_check(
            "Check @pmFromFile references",
            {"first.conf": '@pmFromFile "first.data"\n',
             "second.conf": "@pmFromFile second.data\n"},
            data_files=("first.data", "second.data"),
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("✓ All @pmFromFile references valid", result.stdout)
        self.assertEqual("", result.stderr)

    def test_missing_pmfromfile_reference_fails_without_errexit(self):
        result = self.run_check(
            "Check @pmFromFile references",
            {"fixture.conf": '@pmFromFile "missing.data"\n'},
        )
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("ERROR: Referenced file not found: missing.data", result.stdout)
        self.assertNotIn("✓ All @pmFromFile references valid", result.stdout)
        self.assertEqual("", result.stderr)

    def test_boundary_rule_ids_in_multiple_files_pass_without_errexit(self):
        result = self.run_check(
            "Check Rule ID ranges",
            {"first.conf": "id:9522000\n", "second.conf": "id:9522999\n"},
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("✓ All Rule IDs in valid range", result.stdout)
        self.assertEqual("", result.stderr)

    def test_outside_rule_ids_fail_without_errexit(self):
        for rule_id in (9521999, 9523000):
            with self.subTest(rule_id=rule_id):
                result = self.run_check(
                    "Check Rule ID ranges",
                    {"first.conf": f"id:{rule_id}\n", "second.conf": "id:9522000\n"},
                )
                self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertIn(
                    f"ERROR: Rule ID {rule_id} outside allocated range", result.stdout
                )
                self.assertNotIn("✓ All Rule IDs in valid range", result.stdout)
                self.assertEqual("", result.stderr)


if __name__ == "__main__":
    unittest.main()
