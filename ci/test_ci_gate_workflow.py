"""Exercise the shared gate checker through local and workflow entry points."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/integration.yml"
SCRIPT = ROOT / "scripts/ci-local.sh"
SOURCE = ROOT / "plugins/wordpress-hardening-before.conf"


class GateWorkflowTests(unittest.TestCase):
    def workflow_command(self):
        steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["validate-gates"]["steps"]
        gate = next(step for step in steps if step.get("name") == "Validate gate structure and placement")
        self.assertEqual("bash scripts/ci-local.sh --validate-gates", gate["run"])
        self.assertTrue(any(step.get("name") == "Verify rule parameters" for step in steps))
        return gate["run"]

    def fixture(self, root):
        (root / "plugins").mkdir()
        (root / "ci").mkdir()
        (root / "scripts").mkdir()
        shutil.copy2(SCRIPT, root / "scripts/ci-local.sh")
        for source in (ROOT / "plugins").glob("*.conf"):
            shutil.copy2(source, root / "plugins" / source.name)
        for name in ("check_gate_coverage.awk", "check_chained_skipafter.awk"):
            shutil.copy2(ROOT / "ci" / name, root / "ci" / name)
        subprocess.run(["git", "init", "-q", str(root)], check=True)

    def run_lane(self, root, command):
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "-c", command],
            cwd=root, capture_output=True, text=True, check=False,
        )

    def test_placement_mutation_rejected_by_local_and_workflow(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            commands = ("bash scripts/ci-local.sh --validate-gates", self.workflow_command())
            for command in commands:
                with self.subTest(lane=command, state="green"):
                    result = self.run_lane(root, command)
                    self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                    for marker in (
                        "no chained rule carries skipAfter",
                        "all skipAfter targets resolve",
                        "extension regexes properly anchored",
                        "all markers well-formed and reachable",
                        "all required rules enclosed by gate markers",
                    ):
                        self.assertIn(marker, result.stdout)
            target = root / "plugins" / SOURCE.name
            original = target.read_text()
            begin = 'SecMarker "BEGIN_WPHARD_BLOCK_EDITOR_ACCESS"'
            end = 'SecMarker "END_WPHARD_BLOCK_EDITOR_ACCESS"'
            self.assertEqual(1, original.count(begin))
            self.assertEqual(1, original.count(end))
            target.write_text(original.replace(begin, "", 1).replace(end, end + "\n" + begin, 1))
            for command in commands:
                with self.subTest(lane=command, state="red"):
                    result = self.run_lane(root, command)
                    self.assertNotEqual(0, result.returncode)
                    self.assertIn(
                        "ERROR: rule 9522301 must occur exactly once between",
                        result.stderr,
                    )
                    self.assertIn("CI-local: FAILED", result.stdout)
            target.write_text(original)
            for command in commands:
                with self.subTest(lane=command, state="restored"):
                    result = self.run_lane(root, command)
                    self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_unknown_mode_fails_before_checks(self):
        result = self.run_lane(ROOT, "bash scripts/ci-local.sh --missing-mode")
        self.assertEqual(2, result.returncode)
        self.assertIn("unknown mode", result.stderr)
        self.assertNotIn("gate marker coverage", result.stdout)


if __name__ == "__main__":
    unittest.main()
