"""Check optional IP layout and the selection regression's failure controls."""

import re
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from ci import check_optional_ip as selection


class OptionalIPTests(unittest.TestCase):
    def test_moved_rules_are_not_in_standard_autoload_files(self):
        plugins = selection.xff.ROOT / "plugins"
        optional = plugins / "wordpress-hardening-ip.conf"
        ids = re.findall(r"\bid:(\d+)", optional.read_text())
        self.assertCountEqual(
            ids, [str(i) for i in (*selection.MOVED_IDS, 9522069, 9522070)]
        )
        for pattern in ("*-config.conf", "*-before.conf", "*-after.conf"):
            for path in plugins.glob(pattern):
                self.assertNotEqual(optional, path, "IP file is automatically loaded")
                loaded = set(re.findall(r"\bid:(\d+)", path.read_text()))
                self.assertFalse(loaded & set(ids), f"IP rules in {path.name}")

    def test_base_fixture_keeps_optional_file_without_an_include(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "base"
            selection.stage(target, "base", "198.18.0.1")
            self.assertTrue((target / "wordpress-hardening-ip.conf").exists())
            source = "\n".join(p.read_text() for p in target.glob("*-before.conf"))
            self.assertNotIn("Include ", source)
            for key in selection.STATE:
                self.assertIn("&TX:wphard." + key, source)

    def test_disable_and_enable_overrides_precede_optional_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            for mode, value in (("disabled", "0"), ("enabled", "1"), ("unset", None)):
                target = Path(temporary) / mode
                selection.stage(target, mode, "198.18.0.1")
                source = (target / "zzz-ci-selection-config.conf").read_text()
                if value is None:
                    self.assertNotIn("wordpress-hardening-plugin_enabled", source)
                else:
                    self.assertIn("wordpress-hardening-plugin_enabled=" + value, source)

    def test_mutations_target_real_rules_and_loader(self):
        with tempfile.TemporaryDirectory() as temporary:
            private = Path(temporary) / "private"
            selection.stage(private, "unset", "198.18.0.1", "remove-private")
            self.assertIn(
                "SecRuleRemoveById 9522063",
                (private / "wordpress-hardening-ip.conf").read_text(),
            )
            base = Path(temporary) / "base"
            selection.stage(base, "base", "198.18.0.1", "autoload-ip")
            self.assertEqual(
                (base / "wordpress-hardening-ip.conf").read_bytes(),
                (base / "aaa-ci-accidental-before.conf").read_bytes(),
            )

    def test_private_client_failure_names_the_missing_exemption(self):
        response = mock.MagicMock()
        response.__enter__.return_value.status = 200
        blocked = urllib.error.HTTPError(
            "http://fixture/xmlrpc.php", 403, "blocked", {}, None
        )
        with (
            mock.patch.object(selection.xff, "run", return_value="true"),
            mock.patch.object(selection.urllib.request, "build_opener") as opener,
            mock.patch.object(
                selection,
                "cases",
                return_value=[
                    ("private-client-exemption", "/xmlrpc.php", "10.0.0.5", 200)
                ],
            ),
        ):
            opener.return_value.open.side_effect = [response, blocked]
            with self.assertRaisesRegex(
                AssertionError,
                "apache:unset:private-client-exemption: expected 200, got 403",
            ):
                selection.check_http(
                    "apache", "unset", "http://fixture", "fixture", False
                )


if __name__ == "__main__":
    unittest.main()
