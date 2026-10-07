"""Unit controls for the Apache login limiter expiry probe."""

import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from ci import check_ratelimit_expiry as expiry


class Response:
    def __init__(self, status):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class RateLimitExpiryTests(unittest.TestCase):
    def test_stage_removes_only_staged_expiry(self):
        with tempfile.TemporaryDirectory() as temporary:
            normal = Path(temporary) / "normal"
            mutated = Path(temporary) / "mutated"
            expiry.stage(normal, "ratelimit", "198.18.0.1")
            expiry.stage(mutated, "ratelimit", "198.18.0.1", "remove-expiry")
            rules = "wordpress-hardening-ratelimit.conf"
            self.assertIn(
                "expirevar:ip.login_attempts=60", (normal / rules).read_text()
            )
            self.assertNotIn(
                "expirevar:ip.login_attempts=60", (mutated / rules).read_text()
            )
            self.assertIn(
                "expirevar:ip.login_attempts=60",
                (expiry.limiter.xff.ROOT / "plugins" / rules).read_text(),
            )

    def test_stopped_server_reports_logs(self):
        with (
            mock.patch.object(expiry.urllib.request, "build_opener"),
            mock.patch.object(
                expiry.limiter.xff, "run", side_effect=["false", "server failed"]
            ),
            self.assertRaisesRegex(AssertionError, "server failed"),
        ):
            expiry.check("apache", "ratelimit", "http://fixture", "server", False)

    def test_recovery_assertion_rejects_persistent_counter(self):
        statuses = [200, 200, 429, 429, 200]

        def run(expected_statuses):
            opener = mock.Mock()
            opener.open.side_effect = [
                urllib.error.HTTPError("http://fixture", status, "blocked", None, None)
                if status == 429
                else Response(status)
                for status in [200, *expected_statuses]
            ]
            with (
                mock.patch.object(
                    expiry.urllib.request, "build_opener", return_value=opener
                ),
                mock.patch.object(expiry.limiter.xff, "run", return_value="true"),
                mock.patch.object(expiry.time, "sleep") as sleep,
            ):
                expiry.check("apache", "ratelimit", "http://fixture", "server", False)
            sleep.assert_called_once_with(expiry.WAIT_SECONDS)
            requests = [call.args[0] for call in opener.open.call_args_list]
            self.assertEqual("GET", requests[0].get_method())
            self.assertEqual(5, len(requests[1:]))
            self.assertTrue(
                all(request.get_method() == "POST" for request in requests[1:])
            )
            self.assertTrue(
                all(
                    request.headers["X-forwarded-for"] == expiry.CLIENT
                    for request in requests
                )
            )

        run(statuses)
        for index, wrong, assertion in (
            (2, 200, "at-threshold: expected HTTP 429, got 200"),
            (3, 200, "before-expiry: expected HTTP 429, got 200"),
            (4, 429, "after-expiry: expected HTTP 200, got 429"),
        ):
            changed = statuses.copy()
            changed[index] = wrong
            with (
                self.subTest(assertion=assertion),
                self.assertRaisesRegex(AssertionError, assertion),
            ):
                run(changed)


if __name__ == "__main__":
    unittest.main()
