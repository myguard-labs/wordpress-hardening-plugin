"""Exercise the CI-local rule and marker loops against isolated plugin fixtures."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CiLocalReadLoopTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        (self.root / "scripts").mkdir()
        (self.root / "ci").mkdir()
        shutil.copy2(ROOT / "scripts/ci-local.sh", self.root / "scripts/ci-local.sh")
        for name in ("check_chained_skipafter.awk", "check_gate_coverage.awk"):
            shutil.copy2(ROOT / "ci" / name, self.root / "ci" / name)
        shutil.copytree(ROOT / "plugins", self.root / "plugins")
        shutil.copytree(
            ROOT / "tests/regression/wordpress-hardening-plugin",
            self.root / "tests/regression/wordpress-hardening-plugin",
        )
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        self.plugin = self.root / "plugins/wordpress-hardening-before.conf"

    def run_gate(self, mode):
        return subprocess.run(
            ["bash", "scripts/ci-local.sh", mode], cwd=self.root,
            capture_output=True, text=True, check=False,
        )

    def run_gate_with_portable_sed(self):
        """Reject GNU sed's BRE optional-quote extension at the command boundary."""
        shim_dir = self.root / "bin"
        shim_dir.mkdir(exist_ok=True)
        sed = shutil.which("sed")
        self.assertIsNotNone(sed)
        shim = shim_dir / "sed"
        shim.write_text(
            '#!/bin/sh\n'
            'for arg do\n'
            '  case "$arg" in *"\\\\?"*)\n'
            '    printf "nonportable sed BRE: %s\\n" "$arg" >&2; exit 99;;\n'
            '  esac\n'
            'done\n'
            f'exec "{sed}" "$@"\n',
            encoding="utf-8",
        )
        shim.chmod(0o755)
        env = os.environ.copy()
        env["PATH"] = f"{shim_dir}{os.pathsep}{env['PATH']}"
        return subprocess.run(
            ["bash", "scripts/ci-local.sh", "--validate-files"], cwd=self.root,
            env=env, capture_output=True, text=True, check=False,
        )

    def test_pmfromfile_paths_use_portable_sed(self):
        for quoted in (False, True):
            with self.subTest(quoted=quoted):
                path = 'wordpress-hardening-files.data'
                if quoted:
                    path = f'"{path}"'
                self.append(f'SecRule REQUEST_FILENAME "@pmFromFile {path}"')
                result = self.run_gate_with_portable_sed()
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertIn("all @pmFromFile targets exist", result.stdout)
                self.assertNotIn("nonportable sed BRE", result.stderr)

    def test_pmfromfile_missing_path_is_reported_with_portable_sed(self):
        self.append('SecRule REQUEST_FILENAME "@pmFromFile missing-unquoted.data"')
        self.append('SecRule REQUEST_FILENAME "@pmFromFile "missing-quoted.data""')
        result = self.run_gate_with_portable_sed()
        self.assertNotEqual(0, result.returncode)
        self.assertIn("referenced file not found: missing-unquoted.data", result.stdout)
        self.assertIn("referenced file not found: missing-quoted.data", result.stdout)
        self.assertNotIn("nonportable sed BRE", result.stderr)

    def append(self, line):
        with self.plugin.open("a") as plugin:
            plugin.write("\n" + line + "\n")

    def test_existing_rules_and_markers_pass_both_modes(self):
        for mode in ("--validate-files", "--validate-gates"):
            with self.subTest(mode=mode):
                result = self.run_gate(mode)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertIn("CI-local: all checks passed", result.stdout)

    def test_rule_id_range_accepts_both_boundaries(self):
        self.append('SecRule ARGS "@rx boundary" "id:9522000,pass"')
        self.append('SecRule ARGS "@rx boundary" "id:9522999,pass"')
        result = self.run_gate("--validate-files")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("all rule IDs in range", result.stdout)

    def test_out_of_range_rule_id_fails(self):
        self.append('SecRule ARGS "@rx invalid" "id:9523000,pass"')
        result = self.run_gate("--validate-files")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("rule ID 9523000 outside allocated range", result.stdout)

    def test_missing_skipafter_target_fails(self):
        self.append('SecRule ARGS "@rx invalid" "id:9522999,pass,skipAfter:MISSING_TARGET"')
        result = self.run_gate("--validate-gates")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("skipAfter:MISSING_TARGET has no matching SecMarker", result.stdout)

    def test_malformed_begin_marker_fails(self):
        self.append('SecMarker "BEGIN_BROKEN_GATE"')
        result = self.run_gate("--validate-gates")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("BEGIN_BROKEN_GATE has no matching END_BROKEN_GATE", result.stdout)

    def test_untargeted_end_marker_fails(self):
        self.append('SecMarker "END_DEAD_GATE"')
        result = self.run_gate("--validate-gates")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("END_DEAD_GATE never targeted by a skipAfter", result.stdout)


if __name__ == "__main__":
    unittest.main()
