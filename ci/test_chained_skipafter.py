"""Exercise the shared chain guard and its local/CI entry points."""

import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "ci/check_chained_skipafter.awk"
STARTER = """SecRule REQUEST_URI "@contains /probe" \\
  "id:9522990,phase:2,pass,skipAfter:END_PROBE,chain"
"""
INNER = """SecRule REQUEST_METHOD "@streq GET" \\
  "t:none,chain"
SecRule REQUEST_HEADERS:Host "@rx ." \\
  "t:none"
"""


class ChainedSkipAfterTests(unittest.TestCase):
    def run_guard(self, rules):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "rules.conf"
            fixture.write_text(rules)
            return subprocess.run(
                ["awk", "-f", str(GUARD), str(fixture)],
                capture_output=True,
                text=True,
                check=False,
            )

    def test_valid_chains_and_starter_skipafter_pass(self):
        result = self.run_guard(STARTER + INNER + "SecMarker END_PROBE\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_nonchained_skipafter_passes(self):
        result = self.run_guard(
            'SecRule REQUEST_URI "@contains /ok" "id:9522991,skipAfter:END_PROBE"\n'
            "SecMarker END_PROBE\n"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_selector_containing_chain_does_not_start_chain(self):
        result = self.run_guard(
            'SecRule ARGS:name "@streq chain" "id:9522992,phase:2,pass"\n'
            'SecRule REQUEST_URI "@contains /ok" "id:9522993,skipAfter:END_PROBE"\n'
            "SecMarker END_PROBE\n"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_continued_selector_containing_chain_does_not_start_chain(self):
        result = self.run_guard(
            'SecRule ARGS:name "@streq chain" \\\n  "id:9522994,phase:2,pass"\n'
            'SecRule REQUEST_URI "@contains /ok" \\\n  "id:9522995,skipAfter:END_PROBE"\n'
            "SecMarker END_PROBE\n"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_unquoted_operator_with_chain_action_still_rejects_inner_skipafter(self):
        result = self.run_guard(
            'SecRule REQUEST_URI @detectXSS "id:9522996,phase:2,pass,chain"\n'
            'SecRule ARGS:name "@streq value" "skipAfter:END_PROBE"\n'
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("chained skipAfter", result.stdout)

    def test_quoted_chain_first_action_rejects_inner_skipafter(self):
        result = self.run_guard(
            'SecRule REQUEST_URI "@contains /probe" "chain,id:9522997,phase:2,pass"\n'
            'SecRule REQUEST_METHOD "@streq GET" "skipAfter:END_PROBE"\n'
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("chained skipAfter", result.stdout)

    def test_flush_left_multiline_inner_skipafter_fails(self):
        rules = STARTER + INNER.replace(
            '"t:none,chain"', '"t:none,skipAfter:END_PROBE,chain"'
        )
        result = self.run_guard(rules)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("chained skipAfter", result.stdout)

    def test_single_line_inner_skipafter_fails(self):
        result = self.run_guard(
            STARTER + 'SecRule REQUEST_METHOD "@streq GET" "skipAfter:END_PROBE"\n'
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("chained skipAfter", result.stdout)

    def test_local_and_workflow_use_same_guard(self):
        invocation = "awk -f ci/check_chained_skipafter.awk plugins/*.conf"
        local_source = (ROOT / "scripts/ci-local.sh").read_text()
        self.assertIn(invocation, local_source)
        local_block = (
            local_source.split(
                "# ── integration.yml: skipAfter only on chain-starter rules", 1
            )[1]
            .split("\n", 1)[1]
            .split("# ── skipAfter targets resolve to a SecMarker", 1)[0]
        )
        local_script = (
            "FAIL=0; note() { :; }; ok() { :; }; "
            'err() { echo "$1"; FAIL=1; };\n' + local_block + '\ntest "$FAIL" -eq 0\n'
        )
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/integration.yml").read_text()
        )
        steps = workflow["jobs"]["validate-gates"]["steps"]
        script = next(
            step["run"]
            for step in steps
            if step.get("name") == "Verify skipAfter only on chain-starter rules"
        )
        self.assertIn(invocation, script)
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / "ci").mkdir()
            (work / "plugins").mkdir()
            (work / "ci/check_chained_skipafter.awk").write_text(GUARD.read_text())
            fixture = work / "plugins/rules.conf"
            fixture.write_text(STARTER + INNER)
            for entry in (local_script, script):
                valid = subprocess.run(
                    [
                        "bash",
                        "--noprofile",
                        "--norc",
                        "-e",
                        "-o",
                        "pipefail",
                        "-c",
                        entry,
                    ],
                    cwd=work,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)
            fixture.write_text(
                STARTER
                + INNER.replace('"t:none,chain"', '"t:none,skipAfter:END_PROBE,chain"')
            )
            for entry, message in (
                (local_script, "skipAfter on a chained rule"),
                (script, "skipAfter found on a chained (inner) SecRule"),
            ):
                invalid = subprocess.run(
                    [
                        "bash",
                        "--noprofile",
                        "--norc",
                        "-e",
                        "-o",
                        "pipefail",
                        "-c",
                        entry,
                    ],
                    cwd=work,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(invalid.returncode, 0)
                self.assertIn(message, invalid.stdout)


if __name__ == "__main__":
    unittest.main()
