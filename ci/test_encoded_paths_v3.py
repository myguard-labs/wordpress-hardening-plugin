"""Check rule-specific oracles for the live encoded-path v3 probe."""

import json
import unittest
from pathlib import Path

from ci.check_encoded_paths_v3 import CASES, assert_result


def record(*ids):
    return {
        "transaction": {
            "messages": [{"details": {"ruleId": str(rule_id)}} for rule_id in ids]
        }
    }


class EncodedPathsV3Tests(unittest.TestCase):
    def test_each_positive_requires_its_own_rule_and_block(self):
        for rule_id, _method, _positive, _benign, _double in CASES:
            with self.subTest(rule_id=rule_id):
                expected = 200 if rule_id == 9522121 else 403
                self.assertTrue(
                    assert_result(
                        rule_id, "positive", expected, record(rule_id, 949110)
                    )
                )
                with self.assertRaisesRegex(AssertionError, "rule did not fire"):
                    assert_result(rule_id, "positive", expected, record(949110))
                with self.assertRaisesRegex(
                    AssertionError, f"expected HTTP {expected}"
                ):
                    assert_result(
                        rule_id,
                        "positive",
                        403 if expected == 200 else 200,
                        record(rule_id),
                    )

    def test_new_cases_match_coraza_fixture_boundaries(self):
        fixture = json.loads(
            (Path(__file__).with_name("urldecode_coraza.json")).read_text()
        )
        by_name = {item["name"]: item for item in fixture}
        for rule_id, method, positive, benign, double in CASES:
            if rule_id not in (9522117, 9522118, 9522121):
                continue
            for suffix, path, oracle in (
                (91, positive, "expect_ids"),
                (92, benign, "no_expect_ids"),
                (93, double, "no_expect_ids"),
            ):
                with self.subTest(rule_id=rule_id, suffix=suffix):
                    case = by_name[f"{rule_id}-{suffix}"]
                    self.assertEqual(method, case["method"])
                    self.assertEqual(path, case["uri"])
                    self.assertIn(rule_id, case[oracle])

    def test_benign_and_double_encoded_paths_do_not_match(self):
        for rule_id, _method, _positive, _benign, _double in CASES:
            for kind in ("benign", "double"):
                with self.subTest(rule_id=rule_id, kind=kind):
                    self.assertFalse(assert_result(rule_id, kind, 200, record(920350)))
                    with self.assertRaisesRegex(AssertionError, "fired unexpectedly"):
                        assert_result(rule_id, kind, 200, record(rule_id))


if __name__ == "__main__":
    unittest.main()
