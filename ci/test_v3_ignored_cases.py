"""Replay the stateless historical nginx/v3 ignores on pinned Coraza.

Each test reads its go-ftw assertion and observes that a targeted rule
mutation turns that same named case red. The stateful 9522412-1 rate-limit
fixture needs the separate persistent-collection engine and is not replayed.
"""

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
BUILD_TIMEOUT = 300
PROBE_TIMEOUT = 30
TITLES = (
    "9522119-1",
    "9522311-1",
    "9522112-2",
    "9522104-12",
    "9522309-3",
    "9522114-5",
    "9522200-5",
    "9522200-11",
    "9522603-4",
    "9522202-5",
)
NEGATIVE_MUTATIONS = {
    "9522104-12": (
        "wordpress-hardening-before.conf",
        r"(?:/wp/v2/users/[0-9]+)",
        r"(?:/wp/v2/users/(?:[0-9]+|me))",
    ),
    "9522114-5": (
        "wordpress-hardening-after.conf",
        r"(?:\.php)?(?:\.(?:bak|backup",
        r"(?:\.php)?(?:\.php|\.(?:bak|backup",
    ),
    "9522200-5": ("wordpress-hardening-before.conf", "wp-cron|wp-login", "wp-login"),
}


def run_bounded(command, *, cwd, timeout, label):
    try:
        return subprocess.run(
            command, cwd=cwd, capture_output=True, text=True, check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{label} timed out after {timeout}s") from exc


def fixture(title):
    source = (
        ROOT
        / "tests/regression/wordpress-hardening-plugin"
        / (title.split("-")[0] + ".yaml")
    )
    document = yaml.safe_load(source.read_text(encoding="utf-8"))
    matches = [test for test in document["tests"] if test["test_title"] == title]
    if len(matches) != 1 or len(matches[0]["stages"]) != 1:
        raise ValueError(f"{title}: expected exactly one single-stage fixture")
    stage = matches[0]["stages"][0]
    rule_id = int(title.split("-")[0])
    output = stage["output"]
    expected = {"log_contains": f'id "{rule_id}"'}
    excluded = {"no_log_contains": f'id "{rule_id}"'}
    if output not in (expected, excluded):
        raise ValueError(f"{title}: unsupported go-ftw assertion {output}")
    request = stage["input"]
    return {
        "name": title,
        "method": request["method"],
        "uri": request["uri"],
        "headers": request["headers"],
        "data": request.get("data", ""),
        # The original HTTP fixture connects to the local engine. The staged
        # CI config enables the legacy XFF mode used by that fixture.
        "client_ip": "127.0.0.1",
        "expect_ids": [rule_id] if output == expected else [],
        "no_expect_ids": [rule_id] if output == excluded else [],
    }


def mutate_rule(plugins, title):
    rule_id = int(title.split("-")[0])
    if title in NEGATIVE_MUTATIONS:
        name, old, new = NEGATIVE_MUTATIONS[title]
        path = plugins / name
        source = path.read_text(encoding="utf-8")
        if source.count(old) != 1:
            raise ValueError(
                f"{title}: mutation target occurs {source.count(old)} times"
            )
        path.write_text(source.replace(old, new), encoding="utf-8")
    else:
        # Remove the complete rule, including its chains, after it is loaded.
        with (plugins / "wordpress-hardening-after.conf").open("a") as stream:
            stream.write(f"\nSecRuleRemoveById {rule_id}\n")


class V3IgnoredCaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = Path(
            cls.enterClassContext(
                tempfile.TemporaryDirectory(prefix="v3-ignored-", dir=ROOT)
            )
        )
        probe_source = cls.directory / "coraza"
        probe_source.mkdir()
        for name in ("main.go", "go.mod", "go.sum"):
            shutil.copyfile(ROOT / "tests/coraza" / name, probe_source / name)
        cls.probe = probe_source / "coraza-probe"
        result = run_bounded(
            ["go", "build", "-mod=readonly", "-o", str(cls.probe), "."],
            cwd=probe_source, timeout=BUILD_TIMEOUT, label="Coraza probe build",
        )
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)

    def run_case(self, title, *, mutated=False):
        case = fixture(title)
        with tempfile.TemporaryDirectory(prefix="v3-case-", dir=self.directory) as lane:
            lane = Path(lane)
            plugins = lane / "plugins"
            shutil.copytree(ROOT / "plugins", plugins)
            shutil.copyfile(
                ROOT / "tests/integration/ci-plugin/zzz-ci-config.conf",
                plugins / "zzz-ci-config.conf",
            )
            if mutated:
                mutate_rule(plugins, title)
            setup = lane / "setup.conf"
            setup.write_text(
                'SecDefaultAction "phase:1,pass,log"\n'
                'SecDefaultAction "phase:2,pass,log"\n'
                'SecAction "id:9900001,phase:1,pass,nolog,t:none,'
                "setvar:tx.critical_anomaly_score=5,"
                "setvar:tx.detection_paranoia_level=2,"
                "setvar:tx.wphard.block_scanners=1,"
                'setvar:tx.wphard.ip_reputation_enabled=1"\n',
                encoding="utf-8",
            )
            transactions = lane / "transactions.json"
            transactions.write_text(json.dumps([case]), encoding="utf-8")
            return run_bounded(
                [
                    str(self.probe),
                    "-tx",
                    str(transactions),
                    "wordpress-hardening-config.conf",
                    "zzz-ci-config.conf",
                    str(setup),
                    "wordpress-hardening-ip.conf",
                    "wordpress-hardening-before.conf",
                    "wordpress-hardening-after.conf",
                ],
                cwd=plugins, timeout=PROBE_TIMEOUT, label=f"Coraza probe {title}",
            )

    def assert_case(self, title):
        green = self.run_case(title)
        self.assertEqual(green.returncode, 0, green.stdout + green.stderr)
        self.assertIn(f"PASS {title}", green.stdout)
        red = self.run_case(title, mutated=True)
        self.assertEqual(red.returncode, 1, red.stdout + red.stderr)
        self.assertIn(f"FAIL {title}", red.stdout)
        rule_id = int(title.split("-")[0])
        expected_error = (
            f"expected id {rule_id} did not fire"
            if fixture(title)["expect_ids"]
            else f"forbidden id {rule_id} fired"
        )
        self.assertIn(expected_error, red.stdout)

    def test_stateful_fixture_is_not_silently_flattened(self):
        with self.assertRaisesRegex(ValueError, "exactly one single-stage fixture"):
            fixture("9522412-1")

    def test_missing_mutation_target_is_rejected(self):
        with tempfile.TemporaryDirectory(
            prefix="v3-mutation-", dir=self.directory
        ) as lane:
            (Path(lane) / "wordpress-hardening-before.conf").write_text(
                "", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "mutation target occurs 0 times"):
                mutate_rule(Path(lane), "9522104-12")

    def test_probe_timeout_reports_named_case(self):
        timeout = subprocess.TimeoutExpired("probe", PROBE_TIMEOUT)
        with (patch.object(subprocess, "run", side_effect=timeout),
              self.assertRaisesRegex(
                  RuntimeError, "Coraza probe 9522119-1 timed out after 30s")):
            self.run_case("9522119-1")


class BoundedProcessTests(unittest.TestCase):
    def test_probe_receives_timeout(self):
        completed = subprocess.CompletedProcess(["probe"], 0)
        with patch.object(subprocess, "run", return_value=completed) as runner:
            self.assertIs(
                completed,
                run_bounded(
                    ["probe"], cwd=ROOT, timeout=PROBE_TIMEOUT,
                    label="Coraza probe 9522119-1",
                ),
            )
        runner.assert_called_once_with(
            ["probe"], cwd=ROOT, capture_output=True, text=True,
            check=False, timeout=PROBE_TIMEOUT,
        )

    def test_build_timeout_reports_setup_failure(self):
        timeout = subprocess.TimeoutExpired("go build", BUILD_TIMEOUT)
        with (patch.object(subprocess, "run", side_effect=timeout),
              self.assertRaisesRegex(
                  RuntimeError, "Coraza probe build timed out after 300s")):
            run_bounded(
                ["go", "build"], cwd=ROOT, timeout=BUILD_TIMEOUT,
                label="Coraza probe build",
            )


def make_case_test(title):
    def test(self):
        self.assert_case(title)

    return test


for _title in TITLES:
    setattr(
        V3IgnoredCaseTests, "test_" + re.sub(r"\W", "_", _title), make_case_test(_title)
    )


if __name__ == "__main__":
    unittest.main()
