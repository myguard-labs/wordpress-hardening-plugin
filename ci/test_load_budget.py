"""Evaluate load budgets with inert values in the pinned Coraza engine."""

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
RULE_ID = 9522112


def budget_cases():
    """Expected outcomes are explicit; fixtures never contact WordPress."""
    cases = [
        ("ordinary-admin-chunks", [("load[chunk_0]", "jquery,common"),
                                   ("load[chunk_1]", "utils,wp-dom-ready")], False),
        ("missing-load", [], False),
        ("empty-load", [("load", "")], False),
        ("empty-chunk", [("load[chunk_0]", "")], False),
        ("unrelated-long-value", [("other", "x" * 200)], False),
        ("chunk-with-unrelated-value", [("load[chunk_0]", "x" * 100),
                                        ("other", "x" * 200)], False),
        ("chunk-and-empty-scalar", [("load[chunk_0]", "x" * 80),
                                   ("load", "")], True),
        ("mixed-keys", [("load[chunk_0]", "x" * 40),
                        ("load[a]", "y" * 40)], True),
        ("scalar-and-array", [("load", "x" * 40),
                              ("load[]", "y" * 40)], True),
        ("duplicate-scalar", [("load", "x" * 40), ("load", "y" * 40)], True),
        ("encoded-bytes-count-once", [("load", "," * 79)], False),
        ("encoded-bytes-at-cutoff", [("load", "," * 80)], True),
        ("multibyte-below-cutoff", [("load", "é" * 39)], False),
        ("multibyte-at-cutoff", [("load", "é" * 40)], True),
        ("multibyte-chunk-128", [("load[chunk_0]", "é" * 64)], False),
        ("multibyte-chunk-130", [("load[chunk_0]", "é" * 65)], True),
        ("mixed-case-key-strict-cutoff", [("Load", "x" * 80)], True),
        ("incomplete-bracket", [("load[", "x" * 80)], False),
        ("similar-name", [("preload", "x" * 80)], False),
        ("tab-prefix-is-not-a-space", [("\tload", "x" * 80)], False),
    ]
    strict_keys = ("load", "load[]", "load[a]", "load[a]x", " load",
                   "  load[a]x", " load[chunk_0]", "load[chunk_0]x",
                   "load[chunk_0][a]", "load[chunk_-1]", "load[chunk_]",
                   "load[chunk_a]", "load[chunk_0]\n")
    for key in strict_keys:
        for size, blocked in ((79, False), (80, True), (81, True)):
            cases.append((f"strict-{key!r}-{size}", [(key, "x" * size)], blocked))
    for size, blocked in ((127, False), (128, False), (129, True)):
        cases.append((f"chunk-size-{size}", [("load[chunk_0]", "x" * size)], blocked))
    for size, blocked in ((79, False), (80, True), (81, True)):
        cases.append((f"array-aggregate-{size}",
                      [("load[a]", "x" * 40), ("load[b]", "y" * (size - 40))],
                      blocked))
    for size, blocked in ((1023, False), (1024, True), (1025, True)):
        values = [(f"load[chunk_{i}]", "x" * 128) for i in range(7)]
        values += [("load[chunk_7]", "y" * min(size - 896, 128))]
        if size > 1024:
            values += [("load[chunk_8]", "z")]
        cases.append((f"chunk-aggregate-{size}", values, blocked))
    cases.append(("duplicate-chunk-aggregate",
                  [("load[chunk_0]", "x" * 128)] * 8, True))
    return cases


class LoadBudgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        for name in ("main.go", "go.mod", "go.sum"):
            shutil.copyfile(ROOT / "tests/coraza" / name, cls.directory / name)
        cls.probe = cls.directory / "coraza-probe"
        result = subprocess.run(
            ["go", "build", "-mod=readonly", "-o", str(cls.probe), "."],
            cwd=cls.directory, capture_output=True, text=True, check=False,
        )
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        cls.setup = cls.directory / "setup.conf"
        cls.scores = cls.directory / "scores.conf"
        cls.scores.write_text(
            'SecRule TX:inbound_anomaly_score_pl1 "@eq 5" '
            '"id:9900002,phase:1,pass,log,t:none,msg:\'score-five\'"\n'
            'SecRule TX:inbound_anomaly_score_pl1 "@eq 0" '
            '"id:9900003,phase:1,pass,log,t:none,msg:\'score-zero\'"\n'
        )

    def check_cases(self, cases, *, path="/wp-admin/load-scripts.php",
                    feature=None, plugin=None):
        settings = ["tx.critical_anomaly_score=5", "tx.inbound_anomaly_score_pl1=0"]
        if feature is not None:
            settings.append(f"tx.wphard.block_load_scripts_dos={feature}")
        if plugin is not None:
            settings.append(f"tx.wordpress-hardening-plugin_enabled={plugin}")
        self.setup.write_text(
            'SecDefaultAction "phase:1,pass,log"\n'
            'SecAction "id:9900001,phase:1,pass,nolog,t:none,'
            + ",".join("setvar:" + value for value in settings) + '"\n'
        )
        transactions = []
        for name, values, blocked in cases:
            transactions.append({
                "name": name, "uri": path + "?" + urlencode(values),
                "headers": {"Host": "localhost", "User-Agent": "budget-test",
                            "Accept": "*/*"},
                "expect_ids": [RULE_ID, 9900002] if blocked else [9900003],
                "no_expect_ids": [9900003] if blocked else [RULE_ID, 9900002],
                "expect_interruption": False,
            })
        fixture = self.directory / "cases.json"
        fixture.write_text(json.dumps(transactions))
        result = subprocess.run(
            [str(self.probe), "-tx", str(fixture), str(self.setup),
             str(ROOT / "plugins/wordpress-hardening-before.conf"),
             str(ROOT / "plugins/wordpress-hardening-after.conf"), str(self.scores)],
            cwd=ROOT / "plugins", capture_output=True, text=True, check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn(f"{len(cases)}/{len(cases)} passed", result.stdout)

    def test_load_budget_matrix(self):
        for path in ("/wp-admin/load-scripts.php", "/wp-admin/load-styles.php"):
            with self.subTest(path=path):
                self.check_cases(budget_cases(), path=path)

    def test_aggregate_regression(self):
        self.check_cases([("aggregate-strict-cutoff",
                           [("load[a]", "x" * 40), ("load[b]", "y" * 40)], True)])

    def test_normalized_paths(self):
        for path in ("/wp-admin/load-scr%69pts.php", "/wp-admin/./load-scripts.php",
                     "http://localhost/wp-admin/load-scripts.php"):
            with self.subTest(path=path):
                self.check_cases([("normalized-path", [("load", "x" * 80)], True)],
                                 path=path)

    def test_non_target_paths(self):
        for path in ("/", "/wp-admin/load-scr%2569pts.php",
                     "/wp-admin/load-scripts.php/extra", "/other.php"):
            with self.subTest(path=path):
                self.check_cases([("non-target", [("load", "x" * 80)], False)],
                                 path=path)

    def test_feature_disabled(self):
        self.check_cases([(name, values, False) for name, values, _ in budget_cases()],
                         feature=0)

    def test_plugin_disabled(self):
        self.check_cases([(name, values, False) for name, values, _ in budget_cases()],
                         plugin=0)


if __name__ == "__main__":
    unittest.main()
