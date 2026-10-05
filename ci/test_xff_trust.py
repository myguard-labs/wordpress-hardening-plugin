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
        self.assertIn(("private-peer-private-XFF", "10.0.0.5", True), cases)
        self.assertIn(("private-peer-no-header", None, False), cases)

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
