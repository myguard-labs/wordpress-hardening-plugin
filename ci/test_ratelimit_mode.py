"""Unit controls for the On-mode login limiter probe."""

import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from ci import check_ratelimit_mode as limiter


class Response:
    def __init__(self, status):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class RateLimitModeTests(unittest.TestCase):
    def test_stage_loads_shipped_rules_and_mutates_only_staged_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            original = (
                limiter.xff.ROOT / "plugins/wordpress-hardening-ratelimit.conf"
            ).read_text()
            normal = Path(temporary) / "normal"
            mutated = Path(temporary) / "mutated"
            limiter.stage(normal, "ratelimit", "198.18.0.1")
            limiter.stage(mutated, "ratelimit", "198.18.0.1", "remove-deny")
            self.assertIn(
                "deny,status:429",
                (normal / "wordpress-hardening-ratelimit.conf").read_text(),
            )
            self.assertNotIn(
                "deny,status:429",
                (mutated / "wordpress-hardening-ratelimit.conf").read_text(),
            )
            self.assertEqual(
                original,
                (
                    limiter.xff.ROOT / "plugins/wordpress-hardening-ratelimit.conf"
                ).read_text(),
            )
            self.assertIn(
                "ratelimit_login_attempts=3",
                (normal / "zzz-ci-ratelimit-config.conf").read_text(),
            )
            self.assertIn(
                "wordpress-hardening-ratelimit.conf",
                (normal / "zzz-ci-ratelimit-before.conf").read_text(),
            )

    def test_http_asserts_limit_boundary_and_separate_client(self):
        def run(statuses):
            opener = mock.Mock()
            opener.open.side_effect = [
                urllib.error.HTTPError(
                    "http://fixture/wp-login.php", 429, "Too Many Requests", None, None
                )
                if status == 429
                else Response(status)
                for status in [200, *statuses]
            ]
            with (
                mock.patch.object(
                    limiter.urllib.request, "build_opener", return_value=opener
                ),
                mock.patch.object(limiter.xff, "run", return_value="true"),
            ):
                limiter.check("apache", "ratelimit", "http://fixture", "server", False)
            clients = [
                call.args[0].headers["X-forwarded-for"]
                for call in opener.open.call_args_list[1:]
            ]
            self.assertEqual(
                [
                    "198.51.100.100",
                    "198.51.100.100",
                    "198.51.100.101",
                    "198.51.100.100",
                    "198.51.100.101",
                ],
                clients,
            )

        run([200, 200, 200, 429, 200])
        for statuses, message in (
            ([200, 429, 200, 429, 200], "client-a-below-limit"),
            ([200, 200, 429, 429, 200], "client-b-first"),
            ([200, 200, 200, 200, 200], "client-a-at-limit: expected HTTP 429"),
        ):
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(AssertionError, message),
            ):
                run(statuses)


if __name__ == "__main__":
    unittest.main()
