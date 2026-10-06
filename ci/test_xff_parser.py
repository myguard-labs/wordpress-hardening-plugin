"""Compare the shipped XFF grammar to the standard library address parser."""

import re
import unittest
from pathlib import Path

from ci.check_xff_trust import address_corpus, expected_address

SOURCE = Path(__file__).resolve().parents[1] / "plugins/wordpress-hardening-ip.conf"
RULE = re.compile(
    r'(?m)^[ \t]*SecRule\s+\S+\s+"(?P<operator>[^"]*)"\s+"(?P<actions>[^"]*)"'
)


def rule_parts(source, rule_id, *, chained=False):
    rules = list(RULE.finditer(re.sub(r"\\\r?\n[ \t]*", " ", source)))
    identifier = re.compile(rf"(?:^|,)\s*id\s*:\s*{rule_id}\s*(?:,|$)")
    for index, rule in enumerate(rules):
        if identifier.search(rule["actions"]):
            if chained:
                assert index + 1 < len(rules), f"SecRule id:{rule_id} has no chain link"
                link = rules[index + 1]
                assert not re.search(r"(?:^|,)\s*id\s*:", link["actions"]), (
                    f"SecRule id:{rule_id} has no chain link"
                )
                return link["operator"], link["actions"]
            return rule["operator"], rule["actions"]
    raise AssertionError(f"SecRule id:{rule_id} not found")


def parser_pattern(source, rule_id, *, chained=True):
    operator, _ = rule_parts(source, rule_id, chained=chained)
    match = re.fullmatch(r"@rx\s+(.+)", operator, re.DOTALL)
    assert match is not None, f"SecRule id:{rule_id} has no @rx operator"
    return re.compile(match[1])


class XffParserTests(unittest.TestCase):
    def test_rule_body_ignores_spacing_and_continuations(self):
        source = SOURCE.read_text()
        changed = re.sub(r"\\\r?\n[ \t]*", "\n  ", source)
        changed = changed.replace("SecRule ", "SecRule\t  ")
        changed = changed.replace('"id:9522061,', '" id : 9522061 ,')
        changed = changed.replace('"@rx ', '"@rx   ')
        for rule_id in (9522061, 9522062, 9522068):
            with self.subTest(rule_id=rule_id):
                self.assertEqual(
                    parser_pattern(source, rule_id).pattern,
                    parser_pattern(changed, rule_id).pattern,
                )
                self.assertEqual(
                    re.sub(r"\s+", "", rule_parts(source, rule_id, chained=True)[1]),
                    re.sub(r"\s+", "", rule_parts(changed, rule_id, chained=True)[1]),
                )
        self.assertEqual(
            parser_pattern(source, 9522063, chained=False).pattern,
            parser_pattern(changed, 9522063, chained=False).pattern,
        )

    def test_missing_rule_names_id(self):
        source = SOURCE.read_text().replace('"id:9522061,', '"id:9522999,', 1)
        with self.assertRaisesRegex(AssertionError, "SecRule id:9522061 not found"):
            parser_pattern(source, 9522061)

    def test_missing_chain_link_names_id(self):
        source = 'SecRule TX:test "@eq 1" "id:9522061,chain"'
        with self.assertRaisesRegex(
            AssertionError, "SecRule id:9522061 has no chain link"
        ):
            parser_pattern(source, 9522061)

    def test_chain_link_with_own_id_rejected(self):
        source = (
            'SecRule TX:test "@eq 1" "id:9522061,chain"\n'
            'SecRule TX:other "@rx .*" "id:9522062,pass"'
        )
        with self.assertRaisesRegex(
            AssertionError, "SecRule id:9522061 has no chain link"
        ):
            parser_pattern(source, 9522061)

    def test_non_rx_chain_link_names_id(self):
        source = (
            'SecRule TX:test "@eq 1" "id:9522061,chain"\n'
            'SecRule REQUEST_HEADERS:X-Forwarded-For "@eq 1" "t:none"'
        )
        with self.assertRaisesRegex(AssertionError, "id:9522061 has no @rx"):
            parser_pattern(source, 9522061)

    def test_parser_differential_corpus(self):
        source = SOURCE.read_text()
        patterns = [
            parser_pattern(source, number) for number in (9522061, 9522062, 9522068)
        ]
        for address in address_corpus():
            for header in (
                address,
                "[" + address + "]",
                address + " , 8.8.8.8",
                "[" + address + "]:443",
            ):
                with self.subTest(header=header):
                    expected = expected_address(header)
                    matches = [pattern.search(header) for pattern in patterns]
                    captured = next((m[1].strip("[]") for m in matches if m), None)
                    self.assertEqual(expected, captured, header)

    def test_ported_first_hop_and_malformed_fallback(self):
        source = SOURCE.read_text()
        patterns = [
            parser_pattern(source, number) for number in (9522061, 9522062, 9522068)
        ]
        cases = {
            "127.0.0.1:1": "127.0.0.1",
            "10.1.2.3:8080, 8.8.8.8": "10.1.2.3",
            "255.255.255.255:65535": "255.255.255.255",
            "[::1]:443": "::1",
            "[::1]:1": "::1",
            "[2001:db8::1]:65535, 8.8.8.8": "2001:db8::1",
            " [::ffff:10.0.0.1]:8080 , 8.8.8.8": "::ffff:10.0.0.1",
            "::1:80": "::1:80",
            "127.0.0.1:": None,
            "127.0.0.1:-1": None,
            "127.0.0.1:+80": None,
            "127.0.0.1:0": None,
            "127.0.0.1:65536": None,
            "127.0.0.1:080": None,
            "127.0.0.1:80junk": None,
            "127.0.0.1:80:90": None,
            "127.0.0.1: 80": None,
            "127.0.0.1 :80": None,
            "[::1]:": None,
            "[::1]:-1": None,
            "[::1]:+80": None,
            "[::1]:0": None,
            "[::1]:65536": None,
            "[::1]:080": None,
            "[::1]:80junk": None,
            "[::1]:80:90": None,
            "[::1]: 80": None,
            "[::1] :80": None,
            "[::1:80": None,
            "::1]:80": None,
            "[127.0.0.1]:80": None,
            "::1:12345": None,
        }
        for header, expected in cases.items():
            with self.subTest(header=header):
                self.assertEqual(expected, expected_address(header))
                matches = [pattern.search(header) for pattern in patterns]
                captured = next((m[1] for m in matches if m), None)
                self.assertEqual(expected, captured, header)

    def test_parser_transforms_reset_on_each_chain_link(self):
        source = SOURCE.read_text()
        for rule_id in (9522061, 9522062, 9522068):
            _, actions = rule_parts(source, rule_id, chained=True)
            action_list = actions.split(",")
            self.assertEqual(
                ["t:none"],
                [action for action in action_list if action.startswith("t:")],
            )
            self.assertIn("capture", action_list)

    def test_mapped_private_compression_positions(self):
        source = SOURCE.read_text()
        pattern = parser_pattern(source, 9522063, chained=False)
        for address in address_corpus():
            if "ffff:10.0.0.1" in address and expected_address(address):
                with self.subTest(address=address):
                    self.assertIsNotNone(pattern.fullmatch(address.lower()))
        for address in ("0:0:0:0:0:ffff:192.0.2.1", "::ffff:172.32.0.1"):
            self.assertIsNone(pattern.fullmatch(address))


if __name__ == "__main__":
    unittest.main()
