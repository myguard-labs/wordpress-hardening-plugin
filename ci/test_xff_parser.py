"""Compare the shipped XFF grammar to the standard library address parser."""

import re
import unittest
from pathlib import Path

from ci.check_xff_trust import address_corpus, expected_address

SOURCE = Path(__file__).resolve().parents[1] / "plugins/wordpress-hardening-before.conf"


def parser_pattern(source, rule_id):
    link = source.split(f'"id:{rule_id},', 1)[1].split("SecRule", 1)[1]
    return re.compile(link.split('"@rx ', 1)[1].split('"', 1)[0])


class XffParserTests(unittest.TestCase):
    def test_parser_differential_corpus(self):
        source = SOURCE.read_text()
        patterns = [parser_pattern(source, number) for number in (9522061, 9522062)]
        for address in address_corpus():
            for header in (address, "[" + address + "]", address + " , 8.8.8.8"):
                with self.subTest(header=header):
                    expected = expected_address(header)
                    matches = [pattern.search(header) for pattern in patterns]
                    captured = next((m[1].strip("[]") for m in matches if m), None)
                    self.assertEqual(expected, captured, header)

    def test_parser_transforms_reset_on_each_chain_link(self):
        source = SOURCE.read_text()
        for rule_id in (9522061, 9522062):
            link = source.split(f'"id:{rule_id},', 1)[1].split("SecRule", 1)[1]
            actions = link.split('" \\\n', 1)[1].split('"', 2)[1]
            self.assertTrue(actions.startswith("t:none,capture,"), actions)

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
