"""Check the rule-specific oracle used by the live nginx/v3 probe."""

import unittest

from ci.check_load_budget_v3 import LONG_PATH, SHORT_PATH, assert_result


def record(*ids):
    return {"transaction": {"messages": [
        {"details": {"ruleId": str(rule_id)}} for rule_id in ids
    ]}}


class LoadBudgetV3Tests(unittest.TestCase):
    def test_long_encoded_array_requires_rule_and_block(self):
        self.assertTrue(assert_result("base", LONG_PATH, 403, record(9522112, 949110)))
        with self.assertRaisesRegex(AssertionError, "rule 9522112 did not fire"):
            assert_result("base", LONG_PATH, 403, record(949110))
        with self.assertRaisesRegex(AssertionError, "expected HTTP 403"):
            assert_result("base", LONG_PATH, 200, record(9522112))

    def test_short_value_and_disabled_feature_remain_clean(self):
        for mode, path in (("base", SHORT_PATH), ("disabled", LONG_PATH),
                           ("disabled", SHORT_PATH)):
            with self.subTest(mode=mode, path=path):
                self.assertFalse(assert_result(mode, path, 200, record(920350)))
                with self.assertRaisesRegex(AssertionError, "fired unexpectedly"):
                    assert_result(mode, path, 200, record(9522112))
                with self.assertRaisesRegex(AssertionError, "expected HTTP 200"):
                    assert_result(mode, path, 403, record(920350))


if __name__ == "__main__":
    unittest.main()
