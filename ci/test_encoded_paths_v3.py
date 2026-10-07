"""Check rule-specific oracles for the live encoded-path v3 probe."""

import unittest

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
                self.assertTrue(
                    assert_result(rule_id, "positive", 403, record(rule_id, 949110))
                )
                with self.assertRaisesRegex(AssertionError, "rule did not fire"):
                    assert_result(rule_id, "positive", 403, record(949110))
                with self.assertRaisesRegex(AssertionError, "expected HTTP 403"):
                    assert_result(rule_id, "positive", 200, record(rule_id))

    def test_benign_and_double_encoded_paths_do_not_match(self):
        for rule_id, _method, _positive, _benign, _double in CASES:
            for kind in ("benign", "double"):
                with self.subTest(rule_id=rule_id, kind=kind):
                    self.assertFalse(assert_result(rule_id, kind, 200, record(920350)))
                    with self.assertRaisesRegex(AssertionError, "fired unexpectedly"):
                        assert_result(rule_id, kind, 200, record(rule_id))


if __name__ == "__main__":
    unittest.main()
