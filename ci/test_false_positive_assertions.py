"""Check go-ftw false-positive assertions against synthetic log excerpts."""

import re
import unittest
from pathlib import Path

import yaml

CORPUS = (
    Path(__file__).resolve().parents[1]
    / "tests/security/wordpress-hardening-plugin/false-positives.yaml"
)
SCORE_CASES = (
    "fp-admin-ajax",
    "fp-wpcron-internal",
    "fp-wp-login-plain",
    "fp-wp-login-normal-post",
)
MARKER_CASES = (
    "fp-admin-ajax",
    "fp-wp-login-plain",
    "fp-wp-login-normal-post",
    "fp-wpjson-subpath-read",
    "fp-legit-login-whitelisted-ip",
    "fp-order-array-reorder",
)
ALL_CASES = {
    "fp-homepage",
    "fp-normal-post",
    "fp-admin-ajax",
    "fp-wpcron-internal",
    "fp-wp-login-plain",
    "fp-wp-login-normal-post",
    "fp-wpjson-subpath-read",
    "fp-upload-image",
    "fp-theme-asset",
    "fp-legit-login-whitelisted-ip",
    "fp-tutorial-permalink-php-keywords",
    "fp-orderby-legit",
    "fp-orderby-multicolumn",
    "fp-order-array-reorder",
    "fp-numeric-queryvars",
    "fp-cat-list-negative",
    "fp-strict-integer-params-legit",
}


def extract_assertions(text):
    """Read go-ftw assertions with the same YAML scalar semantics as the fixture."""
    cases = yaml.safe_load(text)["tests"]
    titles = [case["test_title"] for case in cases]
    outputs = {case["test_title"]: case["stages"][0]["output"] for case in cases}
    for title, output in outputs.items():
        for key in ("log_contains", "no_log_contains"):
            if key in output and (
                not isinstance(output[key], str) or not output[key].strip()
            ):
                raise ValueError(f"{title} has empty {key}")
    return titles, outputs


def replace_homepage_assertion(text, replacement):
    """Replace fp-homepage's output scalar, regardless of its YAML quoting."""
    title = re.search(
        r"""(?m)^  - test_title: (?:fp-homepage|'fp-homepage'|"fp-homepage")\s*$""",
        text,
    )
    if title is None:
        raise ValueError("fp-homepage is missing")
    next_title = re.search(r"(?m)^  - test_title:", text[title.end() :])
    end = title.end() + next_title.start() if next_title else len(text)
    block = text[title.end() : end]
    assertion = re.search(
        r"(?m)^          no_log_contains:[^\n]*(?:\n {12,}[^\n]*)*", block
    )
    if assertion is None:
        raise ValueError("fp-homepage no_log_contains is missing")
    start = title.end() + assertion.start()
    stop = title.end() + assertion.end()
    return text[:start] + replacement + text[stop:]


class FalsePositiveAssertionsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.titles, cls.outputs = extract_assertions(CORPUS.read_text())

    def test_expected_false_positive_cases_are_present(self):
        self.assertEqual(17, len(self.titles))
        self.assertEqual(ALL_CASES, set(self.titles))
        for case in sorted(ALL_CASES):
            self.assertIn("no_log_contains", self.outputs[case])

    def test_empty_output_assertion_is_rejected(self):
        fixture = CORPUS.read_text()
        for replacement in (
            "          no_log_contains:",
            "          no_log_contains: ''",
            "          no_log_contains: '   '",
            '          no_log_contains: ""',
            "          no_log_contains: >-",
        ):
            with self.subTest(replacement=replacement):
                mutated = replace_homepage_assertion(fixture, replacement)
                with self.assertRaisesRegex(
                    ValueError, "fp-homepage has empty no_log_contains"
                ):
                    extract_assertions(mutated)

    def test_multiline_folded_assertion_is_loaded_completely(self):
        fixture = CORPUS.read_text()
        replacement = (
            "          no_log_contains: >-\n"
            '            id "9522\n'
            "            |per_pl=[1-9]"
        )
        _, outputs = extract_assertions(
            replace_homepage_assertion(fixture, replacement)
        )
        self.assertEqual(
            'id "9522 |per_pl=[1-9]', outputs["fp-homepage"]["no_log_contains"]
        )

    def test_quoted_homepage_assertion_preserves_all_cases(self):
        fixture = CORPUS.read_text()
        quoted = "          no_log_contains: 'id \"9522'"
        titles, outputs = extract_assertions(
            replace_homepage_assertion(fixture, quoted)
        )
        self.assertEqual(self.titles, titles)
        self.assertEqual(self.outputs, outputs)

    def test_quoted_homepage_titles_select_the_homepage_assertion(self):
        fixture = CORPUS.read_text()
        replacement = '          no_log_contains: "replacement marker"'
        for title in ("'fp-homepage'", '"fp-homepage"'):
            with self.subTest(title=title):
                quoted_fixture = fixture.replace(
                    "  - test_title: fp-homepage", f"  - test_title: {title}", 1
                )
                mutated = replace_homepage_assertion(quoted_fixture, replacement)
                titles, outputs = extract_assertions(mutated)
                self.assertIn("fp-homepage", titles)
                self.assertEqual(
                    "replacement marker", outputs["fp-homepage"]["no_log_contains"]
                )

    def test_nonzero_score_in_every_pl_slot_is_forbidden(self):
        for case in SCORE_CASES:
            pattern = re.compile(self.outputs[case]["no_log_contains"])
            with self.subTest(case=case):
                self.assertIsNone(pattern.search("per_pl=0-0-0-0, threshold=5"))
                for slot in range(4):
                    scores = ["0"] * 4
                    scores[slot] = "5"
                    self.assertIsNotNone(
                        pattern.search("per_pl=" + "-".join(scores)),
                        f"{case} missed PL{slot + 1}",
                    )
                self.assertIsNotNone(pattern.search("per_pl=0-10-0-0"))

    def test_only_intentional_breach_marker_is_allowed(self):
        for case in MARKER_CASES:
            output = self.outputs[case]
            pattern = re.compile(output["no_log_contains"])
            with self.subTest(case=case):
                self.assertEqual('id "9522121"', output["log_contains"])
                for suffix in range(1000):
                    rule_id = 9522000 + suffix
                    matched = pattern.search(f'id "{rule_id}"') is not None
                    self.assertEqual(rule_id != 9522121, matched, rule_id)

    def test_tutorial_forbids_all_three_crs_response_rules(self):
        output = self.outputs["fp-tutorial-permalink-php-keywords"]
        pattern = re.compile(output["no_log_contains"])
        for rule_id in (953100, 953110, 953120):
            with self.subTest(rule_id=rule_id):
                self.assertIsNotNone(pattern.search(f'id "{rule_id}"'))
        self.assertIsNotNone(pattern.search('id "9522000"'))
        self.assertIsNone(pattern.search('id "953130"'))


if __name__ == "__main__":
    unittest.main()
