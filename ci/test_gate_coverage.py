"""Regression tests for the shared CI feature-gate coverage check."""

import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "ci/check_gate_coverage.awk"
GATES = {
    9522207: "WPHARD_BLOCK_REST_API_ROOT",
    9522301: "WPHARD_BLOCK_EDITOR_ACCESS",
    9522303: "WPHARD_BLOCK_BACKUP_FILES",
    9522305: "WPHARD_BLOCK_DB_FILES",
    9522307: "WPHARD_BLOCK_UPLOAD_TRAVERSAL",
    9522309: "WPHARD_BLOCK_NULL_BYTES",
    9522311: "WPHARD_BLOCK_SCANNERS",
    9522313: "WPHARD_BLOCK_DEBUG_PROBES",
    9522315: "WPHARD_BLOCK_LOGIN_INJECTION",
    9522317: "WPHARD_BLOCK_DANGEROUS_ADMIN",
    9522411: "WPHARD_RATELIMIT_LOGIN",
    9522510: "WPHARD_GEOIP_LOGIN",
    9522603: "WPHARD_IP_REPUTATION",
}


def fixture():
    lines = []
    for rule_id, gate in GATES.items():
        lines += [
            f'SecMarker "BEGIN_{gate}"',
            f'SecRule ARGS "@rx x" "id:{rule_id},phase:2"',
            f'SecMarker "END_{gate}"',
        ]
    return lines


def check(*contents):
    with tempfile.TemporaryDirectory() as directory:
        paths = []
        for index, content in enumerate(contents):
            path = Path(directory) / f"rules-{index}.conf"
            path.write_text("\n".join(content) + "\n", encoding="utf-8")
            paths.append(str(path))
        return subprocess.run(
            ["awk", "-f", str(CHECKER), *paths],
            capture_output=True,
            text=True,
            check=False,
        )


class GateCoverageTests(unittest.TestCase):
    def test_real_plugins_pass(self):
        result = subprocess.run(
            [
                "awk",
                "-f",
                str(CHECKER),
                *map(str, sorted((ROOT / "plugins").glob("*.conf"))),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_all_required_gates_pass(self):
        result = check(fixture())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_multiline_rule_actions_pass(self):
        lines = fixture()
        lines[4:5] = [
            'SecRule ARGS "@rx x" \\',
            '  "id:9522301,\\',
            '  phase:2"',
        ]
        result = check(lines)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_deleted_rule_with_id_comment_fails(self):
        lines = fixture()
        lines[4] = '# Removed SecRule; id:9522301 was here'
        result = check(lines)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rule 9522301 must occur exactly once between", result.stderr)

    def test_id_outside_rule_action_fails(self):
        for replacement in (
            'SecRule ARGS "@rx id:9522301" "phase:2"',
            'SecRule ARGS "@rx x" "phase:2" # id:9522301',
        ):
            with self.subTest(replacement=replacement):
                lines = fixture()
                lines[4] = replacement
                result = check(lines)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("rule 9522301 must occur exactly once between", result.stderr)

    def test_end_before_rule_fails(self):
        lines = fixture()
        lines[4], lines[5] = lines[5], lines[4]
        result = check(lines)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rule 9522301 must occur exactly once between", result.stderr)

    def test_rule_on_marker_boundary_fails(self):
        lines = fixture()
        lines[3], lines[4] = lines[4], lines[3]
        self.assertNotEqual(check(lines).returncode, 0)

    def test_missing_rule_or_marker_fails(self):
        for missing in (3, 4, 5):
            with self.subTest(missing=missing):
                lines = fixture()
                del lines[missing]
                self.assertNotEqual(check(lines).returncode, 0)

    def test_duplicate_and_cross_file_fails(self):
        lines = fixture()
        self.assertNotEqual(check(lines + [lines[4]]).returncode, 0)
        first = lines[:4] + lines[5:]
        self.assertNotEqual(check(first, [lines[4]]).returncode, 0)


if __name__ == "__main__":
    unittest.main()
