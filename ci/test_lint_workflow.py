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
    def run_check(self, configs, data_files=(), test_ids=(9522000,)):
        step = next(
            step for step in yaml.safe_load(CALLER.read_text())["jobs"]["validate-files"]["steps"]
            if step.get("name") == "Validate plugin file references and IDs"
        )
        self.assertEqual("bash scripts/ci-local.sh --validate-files", step["run"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "plugins").mkdir()
            (root / "scripts").mkdir()
            (root / "tests/regression/wordpress-hardening-plugin").mkdir(parents=True)
            (root / "scripts/ci-local.sh").write_text((ROOT / "scripts/ci-local.sh").read_text())
            subprocess.run(["git", "init", "-q", directory], check=True)
            for name, contents in configs.items():
                (root / "plugins" / name).write_text(contents)
            for name in data_files:
                (root / "plugins" / name).write_text("fixture\n")
            for rule_id in test_ids:
                (root / "tests/regression/wordpress-hardening-plugin" / f"{rule_id}.yaml").write_text("test: true\n")
            return subprocess.run(
                ["bash", "--noprofile", "--norc", "-c", step["run"]],
                cwd=root, capture_output=True, text=True, check=False,
            )

    def test_valid_file_checks_pass(self):
        result = self.run_check(
            {"first.conf": 'id:9522000\n@pmFromFile "first.data"\n',
             "second.conf": "id:9522999\n@pmFromFile second.data\n"},
            data_files=("first.data", "second.data"), test_ids=(9522000, 9522999),
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        for marker in (
            "all @pmFromFile targets exist",
            "all rule IDs in range",
            "no duplicate rule IDs",
            "all test files map to a rule",
            "CI-local: all checks passed",
        ):
            self.assertIn(marker, result.stdout)

    def test_missing_quoted_reference_fails(self):
        result = self.run_check({"fixture.conf": 'id:9522000\n@pmFromFile "missing.data"\n'})
        self.assertNotEqual(0, result.returncode)
        self.assertIn("referenced file not found: missing.data", result.stdout)

    def test_rule_id_boundaries_and_duplicates_fail(self):
        for config, error in (
            ({"first.conf": "id:9521999\n", "second.conf": "id:9522000\n"}, "outside allocated range"),
            ({"first.conf": "id:9523000\n", "second.conf": "id:9522000\n"}, "outside allocated range"),
            ({"first.conf": "id:9522000\n", "second.conf": "id:9522000\n"}, "duplicate rule IDs"),
        ):
            with self.subTest(error=error, config=config):
                result = self.run_check(config)
                self.assertNotEqual(0, result.returncode)
                self.assertIn(error, result.stdout)

    def test_missing_test_rule_fails(self):
        result = self.run_check({"fixture.conf": "id:9522000\n"}, test_ids=(9522001,))
        self.assertNotEqual(0, result.returncode)
        self.assertIn("references missing rule 9522001", result.stdout)


if __name__ == "__main__":
    unittest.main()
