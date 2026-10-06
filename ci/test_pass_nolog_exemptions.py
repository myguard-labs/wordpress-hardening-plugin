"""Keep diagnostic pass rules logged while exempting one CRS lint warning each."""

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "plugins/wordpress-hardening-before.conf"
IDS = (9522121, 9522701, 9522702, 9522703)
EXEMPTION = "#crs-linter:ignore:pass_nolog"


def rule_block(source, rule_id):
    match = re.search(
        rf'(?m)^SecRule [^\n]+ \\\n  "id:{rule_id},\\\n'
        rf'(?P<actions>(?:[^\n]*\n)*?[^\n]*msg:[^\n]*"?\n)',
        source,
    )
    if match is None:
        raise AssertionError(f"rule {rule_id} is missing")
    return match


class PassNologExemptionsTests(unittest.TestCase):
    def test_only_intentional_detections_are_exempt_and_logged(self):
        source = RULES.read_text()
        self.assertEqual(len(IDS), source.count(EXEMPTION))
        for rule_id in IDS:
            with self.subTest(rule_id=rule_id):
                match = rule_block(source, rule_id)
                prefix = source[:match.start()].splitlines()
                self.assertEqual(EXEMPTION, prefix[-1])
                self.assertIn("# Keep pass,log,auditlog:", prefix[-2])
                actions = match.group("actions")
                for action in ("pass", "log", "auditlog"):
                    self.assertRegex(actions, rf"(?m)^  {action},\\?$")
                self.assertNotRegex(actions, r"(?m)^  nolog,\\?$")

    @unittest.skipUnless(shutil.which("crs-linter"), "crs-linter is not installed")
    def test_installed_linter_exemption_and_removal_control(self):
        source = RULES.read_text()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tags = root / "tags"
            tags.write_text("")
            rules = root / RULES.name

            def warnings(candidate):
                rules.write_text(candidate)
                result = subprocess.run(
                    ["crs-linter", "-d", str(ROOT), "-r", str(rules),
                     "-t", str(tags)],
                    capture_output=True, text=True, check=False,
                )
                self.assertIn("rule id:", result.stdout + result.stderr)
                return result.stdout + result.stderr

            clean = warnings(source)
            for rule_id in IDS:
                with self.subTest(rule_id=rule_id):
                    warning = f"rule uses 'pass' without 'nolog'; rule id: {rule_id}"
                    self.assertNotIn(warning, clean)
                    match = rule_block(source, rule_id)
                    marker = source.rfind(EXEMPTION, 0, match.start())
                    self.assertGreaterEqual(marker, 0)
                    mutated = source[:marker] + source[marker + len(EXEMPTION):]
                    self.assertIn(warning, warnings(mutated))


if __name__ == "__main__":
    unittest.main()
