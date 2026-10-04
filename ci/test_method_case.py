"""Method checks preserve mixed-case requests across supported engines."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "plugins"
AFTER = (ROOT / "wordpress-hardening-after.conf").read_text()
RATELIMIT = (ROOT / "wordpress-hardening-ratelimit.conf").read_text()


def method_rule(source, rule_id):
    """Return the method operator and actions for one named SecRule."""
    if rule_id == 9522119:
        chain = source.split("id:9522119,", 1)[1].split("\n\n", 1)[0]
        match = re.search(r'SecRule REQUEST_METHOD "([^"]+)"\s*\\\s*"([^"]+)"', chain)
    else:
        rules = re.finditer(
            r'SecRule REQUEST_METHOD "([^"]+)"\s*\\\s*"([^"]+)"', source
        )
        match = next((rule for rule in rules if rule.group(2).startswith(
            f"id:{rule_id},")), None)
    if match is None:
        raise AssertionError(f"REQUEST_METHOD rule {rule_id} is missing")
    return match.groups()


def matches_method(source, rule_id, method):
    operator, actions = method_rule(source, rule_id)
    # Match the declared pipeline, so a missing transform makes this test red.
    transforms = re.findall(r't:([A-Za-z]+)', actions)
    if not transforms or transforms[0] != "none":
        raise AssertionError(f"{rule_id} must reset inherited transforms")
    for transform in transforms[1:]:
        if transform != "lowercase":
            raise AssertionError(f"{rule_id} uses unexpected transform {transform}")
        method = method.lower()
    if operator.startswith("!@rx "):
        return re.fullmatch(operator[5:], method) is None
    if operator.startswith("@streq "):
        return method == operator[7:]
    raise AssertionError(f"{rule_id} uses unexpected operator {operator}")


class TestMethodCase(unittest.TestCase):
    def test_uncommon_method_negative_control_mixed_case_allowed(self):
        for method in ("GET", "get", "Post", "hEaD", "options"):
            with self.subTest(method=method):
                self.assertFalse(matches_method(AFTER, 9522119, method))

    def test_uncommon_methods_still_match(self):
        for method in ("TRACE", "trace", "pRoPfInD", "POSTX", ""):
            with self.subTest(method=method):
                self.assertTrue(matches_method(AFTER, 9522119, method))

    def test_login_init_and_tick_count_case_variants(self):
        for rule_id in (9522414, 9522411):
            for method in ("POST", "post", "Post", "pOsT"):
                with self.subTest(rule_id=rule_id, method=method):
                    self.assertTrue(matches_method(RATELIMIT, rule_id, method))

    def test_login_get_and_non_post_do_not_count(self):
        for rule_id in (9522414, 9522411):
            for method in ("GET", "get", "POSTX", "", "OPTIONS"):
                with self.subTest(rule_id=rule_id, method=method):
                    self.assertFalse(matches_method(RATELIMIT, rule_id, method))


if __name__ == "__main__":
    unittest.main()
