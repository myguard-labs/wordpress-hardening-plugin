"""Unit controls for the isolated On-mode threshold probe."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from ci import check_block_mode


class Response:
    def __init__(self, status):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class BlockModeTests(unittest.TestCase):
    def test_stage_uses_shipped_rule_and_isolated_score_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "plugins").mkdir()
            (root / "plugins/wordpress-hardening-after.conf").write_text("shipped rule")
            with mock.patch.object(check_block_mode.check_xff_trust, "ROOT", root):
                target = root / "staged"
                check_block_mode.stage(target, "score", "198.18.0.1")
            self.assertEqual(
                (target / "wordpress-hardening-after.conf").read_text(), "shipped rule"
            )
            self.assertIn(
                "block_plugin_readme=1",
                (target / "aaa-ci-block-config.conf").read_text(),
            )
            self.assertIn(
                "TX:inbound_anomaly_score_pl2",
                (target / "zzz-ci-block-after.conf").read_text(),
            )

    def test_check_requires_plugin_score_threshold_and_http_block(self):
        uri = check_block_mode.ATTACK_PATH
        def run_probe():
            check_block_mode.check("apache", "score", "http://example", "server", False)

        def response_for(expected):
            def open_response(request, **_kwargs):
                return Response(expected if request.full_url.endswith(uri) else 200)

            return open_response

        log = "\n".join(
            f'event [id "{rule}"] [uri "{uri}"]'
            for rule in ("9522115", "9902116", "949110")
        )
        for status, event_log, error in (
            (403, log, None),
            (403, log.replace('[id "9902116"]', '[id "0"]'), "PL2 inbound score"),
            (403, log.replace('[id "949110"]', '[id "0"]'), "threshold rule"),
            (200, log, "expected HTTP 403"),
        ):
            with self.subTest(status=status, error=error):
                opener = mock.Mock()
                opener.open.side_effect = response_for(status)
                with (
                    mock.patch.object(
                        check_block_mode.urllib.request, "build_opener", return_value=opener
                    ),
                    mock.patch.object(check_block_mode.check_xff_trust, "run", return_value="true"),
                    mock.patch.object(
                        check_block_mode.subprocess,
                        "run",
                        return_value=SimpleNamespace(stderr=event_log),
                    ),
                ):
                    if error:
                        with self.assertRaisesRegex(AssertionError, error):
                            run_probe()
                    else:
                        run_probe()


if __name__ == "__main__":
    unittest.main()
