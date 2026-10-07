"""Keep CIDR fixtures and engine outcomes independent of shipped data files."""

import ipaddress
import tempfile
import unittest
from pathlib import Path

from ci import check_cidr_files as cidr


class CIDRFilesTests(unittest.TestCase):
    def test_default_proxy_file_keeps_no_live_entries(self):
        source = cidr.xff.ROOT / "plugins/wordpress-hardening-trusted-proxies.data"
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "default"
            cidr.xff.stage(target, "default", "198.18.0.1")
            staged = target / source.name
            self.assertEqual(source.read_bytes(), staged.read_bytes())
            self.assertFalse(
                [
                    line
                    for line in staged.read_text().splitlines()
                    if line.strip() and not line.lstrip().startswith("#")
                ]
            )

    def test_stage_uses_cidrs_and_places_peer_on_opposite_sides(self):
        with tempfile.TemporaryDirectory() as temporary:
            for mode in cidr.MODES:
                target = Path(temporary) / mode
                cidr.stage(target, mode, "198.18.0.1")
                proxy = (
                    target / "wordpress-hardening-trusted-proxies.data"
                ).read_text()
                reputation = (
                    target / "wordpress-hardening-ip-reputation.data"
                ).read_text()
                if mode == "malformed-proxy":
                    self.assertEqual("bad-cidr/99\n", proxy)
                    self.assertEqual(cidr.REPUTATION + "\n", reputation)
                elif mode == "malformed-reputation":
                    self.assertEqual("bad-cidr/99\n", reputation)
                    self.assertEqual("198.18.0.0/28\n", proxy)
                else:
                    self.assertEqual("/28", proxy.strip()[-3:])
                    self.assertEqual(
                        mode == "inside",
                        ipaddress.ip_address("198.18.0.1")
                        in ipaddress.ip_network(proxy.strip()),
                    )
                    self.assertEqual(cidr.REPUTATION + "\n", reputation)

    def test_mutations_remove_the_distinct_matching_rules(self):
        for mutation, rule in (
            ("remove-proxy", 9522065),
            ("remove-reputation", 9522603),
        ):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as temporary,
            ):
                target = Path(temporary) / "inside"
                cidr.stage(target, "inside", "198.18.0.1", mutation)
                self.assertIn(
                    f"SecRuleRemoveById {rule}",
                    (target / "wordpress-hardening-ip.conf").read_text(),
                )


if __name__ == "__main__":
    unittest.main()
