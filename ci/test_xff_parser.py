"""Compare the shipped XFF grammar to the standard library address parser."""

import re
import unittest
from pathlib import Path

from ci.check_xff_trust import address_corpus, expected_address

SOURCE = Path(__file__).resolve().parents[1] / "plugins/wordpress-hardening-ip.conf"


def parser_pattern(source, rule_id):
    link = source.split(f'"id:{rule_id},', 1)[1].split("SecRule", 1)[1]
    return re.compile(link.split('"@rx ', 1)[1].split('"', 1)[0])


class XffParserTests(unittest.TestCase):
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
            link = source.split(f'"id:{rule_id},', 1)[1].split("SecRule", 1)[1]
            actions = link.split('" \\\n', 1)[1].split('"', 2)[1]
            action_list = actions.split(",")
            self.assertEqual(
                ["t:none"],
                [action for action in action_list if action.startswith("t:")],
            )
            self.assertIn("capture", action_list)

    def test_mapped_private_compression_positions(self):
        source = SOURCE.read_text()
        prefix = source.split('"id:9522063,', 1)[0].rsplit('"@rx ', 1)[1]
        pattern = re.compile(prefix.split('"', 1)[0])
        for address in address_corpus():
            if "ffff:10.0.0.1" in address and expected_address(address):
                with self.subTest(address=address):
                    self.assertIsNotNone(pattern.fullmatch(address.lower()))
        for address in ("0:0:0:0:0:ffff:192.0.2.1", "::ffff:172.32.0.1"):
            self.assertIsNone(pattern.fullmatch(address))


if __name__ == "__main__":
    unittest.main()
