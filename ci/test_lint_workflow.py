"""Guard the policy-compatible lint workflow call and its checks."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CALLER = ROOT / ".github/workflows/lint.yml"
CALLEE = ROOT / ".github/workflows/plugin-lint.yml"


def run_blocks(workflow):
    """Return executable shell lines grouped by workflow run block."""
    blocks = []
    commands = None
    for line in workflow.splitlines():
        if re.fullmatch(r" {8}run: \|", line):
            commands = []
            blocks.append(commands)
            continue
        if commands is not None and line.startswith(" " * 10):
            command = line.strip()
            if command and not command.startswith("#"):
                commands.append(command)
        elif line.strip():
            commands = None
    return blocks


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
        self.assertIn("    timeout-minutes: 20\n", callee)
        external_uses = re.findall(r"(?m)^\s+uses: (?!actions/)(\S+)", callee)
        self.assertEqual([], external_uses)

    def test_yaml_lint_is_executable(self):
        blocks = run_blocks(CALLEE.read_text())
        yaml_blocks = [block for block in blocks if "python -m pip install yamllint" in block]
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
            block for block in blocks if "python -m pip install secrules-parsing" in block
        ]
        self.assertEqual(1, len(parser_blocks))
        commands = parser_blocks[0]
        self.assertIn("secrules-parser -c -v --output-type github -f plugins/*.conf", commands)


if __name__ == "__main__":
    unittest.main()
