"""Check XFF engine fixtures and CRS image selection without Docker."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ci import check_xff_trust


class XffTrustTests(unittest.TestCase):
    def test_private_proxy_cases_include_malformed_headers_when_trusted(self):
        cases = check_xff_trust.peer_cases(True)
        self.assertIn(("private-peer-empty-XFF", "", False), cases)
        self.assertIn(("private-peer-malformed-XFF", "127.0.0.1junk", False), cases)
        self.assertIn(
            ("private-peer-malformed-whitespace-v4-XFF", "127.0.0.1 junk", False),
            cases,
        )
        self.assertIn(
            ("private-peer-malformed-whitespace-v6-XFF", "::1 junk", False), cases
        )
        self.assertIn(
            ("private-peer-private-comma-XFF", "10.0.0.5 , 8.8.8.8", True), cases
        )
        self.assertIn(
            ("private-peer-private-whitespace-XFF", "10.0.0.5   ", True), cases
        )
        self.assertIn(("private-peer-private-XFF", "10.0.0.5", True), cases)
        self.assertIn(("private-peer-no-header", None, False), cases)
        for name, header in (
            ("private-peer-missing-v6-bracket", "[::1"),
            ("private-peer-extra-v6-bracket", "::1]"),
            ("private-peer-mapped-invalid-999", "::ffff:10.999.999.999"),
            ("private-peer-mapped-invalid-256", "::ffff:127.0.0.256"),
            ("private-peer-mapped-leading-zero-3", "::ffff:127.000.0.1"),
            ("private-peer-mapped-leading-zero-2", "::ffff:127.0.0.01"),
        ):
            self.assertIn((name, header, False), cases)
        self.assertIn(("private-peer-bracketed-v6", "[::1]", True), cases)
        self.assertIn(("spoof-v6-full", "0:0:0:0:0:0:0:1", True), check_xff_trust.CASES)
        self.assertIn(
            ("private-peer-mapped-comma", "::ffff:10.0.0.1, 8.8.8.8", True), cases
        )
        self.assertIn(("private-peer-v6-whitespace", "::1   ", True), cases)

    def test_trust_modes_stage_explicit_values_and_proxy_boundary(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(check_xff_trust, "ROOT", Path(temporary)),
        ):
            (Path(temporary) / "plugins").mkdir()
            for mode, value in (
                ("default", None),
                ("trusted", 1),
                ("untrusted", 1),
                ("legacy", 0),
                ("unsupported", 2),
                ("textual", "false"),
            ):
                target = Path(temporary) / mode
                check_xff_trust.stage(target, mode, "198.18.0.1")
                config = target / "ci-xff-probe-config.conf"
                if value is None:
                    self.assertFalse(config.exists())
                else:
                    self.assertIn(
                        f"trusted_proxies_enabled={value}", config.read_text()
                    )
                if mode != "default":
                    proxy = (
                        target / "wordpress-hardening-trusted-proxies.data"
                    ).read_text()
                    self.assertIn(
                        "198.18.0.1" if mode == "trusted" else "198.18.0.2", proxy
                    )

    def test_workflow_tags_are_used_for_images_and_detect_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            workflows = Path(temporary) / ".github/workflows"
            workflows.mkdir(parents=True)
            for name in check_xff_trust.TAG_WORKFLOWS:
                (workflows / name).write_text(
                    'env:\n  CRS_TAG: "apache-test"\n  CRS_TAG_NGINX: "nginx-test"\n'
                )
            with mock.patch.object(check_xff_trust, "ROOT", Path(temporary)):
                with mock.patch.dict(os.environ, {}, clear=True):
                    tags = check_xff_trust.workflow_tags()
                    self.assertEqual(
                        "owasp/modsecurity-crs:apache-test",
                        check_xff_trust.selected_image("apache", tags),
                    )
                    self.assertEqual(
                        "owasp/modsecurity-crs:nginx-test",
                        check_xff_trust.selected_image("nginx", tags),
                    )
                    self.assertEqual(
                        "custom:local",
                        check_xff_trust.selected_image("nginx", tags, "custom:local"),
                    )
                    changed = workflows / check_xff_trust.TAG_WORKFLOWS[1]
                    changed.write_text(
                        changed.read_text().replace("nginx-test", "stale-tag")
                    )
                    with self.assertRaisesRegex(ValueError, "CRS_TAG_NGINX differs"):
                        check_xff_trust.workflow_tags()
                    changed.write_text(
                        changed.read_text().replace("stale-tag", "nginx-test")
                    )
                with (
                    mock.patch.dict(os.environ, {"CRS_TAG": "stale-env"}),
                    self.assertRaisesRegex(ValueError, "CRS_TAG environment differs"),
                ):
                    check_xff_trust.workflow_tags()


if __name__ == "__main__":
    unittest.main()
