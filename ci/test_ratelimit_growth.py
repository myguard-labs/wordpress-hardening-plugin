"""Unit controls for the disposable Apache SDBM growth probe."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ci import check_ratelimit_growth as growth


class RateLimitGrowthTests(unittest.TestCase):
    def test_main_checks_host_perl_before_docker_setup(self):
        with (
            mock.patch.object(sys, "argv", ["check_ratelimit_growth"]),
            mock.patch.object(growth.subprocess, "run") as run,
            mock.patch.object(growth.limiter.xff, "workflow_tags") as tags,
            mock.patch.object(
                growth.limiter.xff, "selected_image", return_value="image"
            ),
            mock.patch.object(growth.limiter.xff, "docker") as docker,
        ):
            tags.side_effect = lambda: self.assertEqual(1, run.call_count)
            growth.main()

        run.assert_called_once_with(
            ["perl", "-MSDBM_File", "-e", "1"],
            check=True,
            capture_output=True,
        )
        docker.assert_called_once()

    def test_main_reports_missing_host_perl_before_docker_setup(self):
        failures = (
            FileNotFoundError("perl"),
            subprocess.CalledProcessError(2, ["perl", "-MSDBM_File", "-e", "1"]),
        )
        for failure in failures:
            with (
                self.subTest(failure=type(failure).__name__),
                mock.patch.object(sys, "argv", ["check_ratelimit_growth"]),
                mock.patch.object(growth.subprocess, "run", side_effect=failure),
                mock.patch.object(growth.limiter.xff, "workflow_tags") as tags,
                mock.patch.object(growth.limiter.xff, "docker") as docker,
                self.assertRaisesRegex(SystemExit, "host Perl SDBM_File is required"),
            ):
                growth.main()
            tags.assert_not_called()
            docker.assert_not_called()

    def test_stage_pins_short_collection_timeout_and_preserves_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            normal = Path(temporary) / "normal"
            disabled = Path(temporary) / "disabled"
            source = (
                growth.limiter.xff.ROOT / "plugins/wordpress-hardening-ratelimit.conf"
            )
            original = source.read_text()
            growth.stage(normal, "ratelimit", "198.18.0.1")
            growth.stage(disabled, "ratelimit", "198.18.0.1", "disable-limiter")
            self.assertEqual(
                "SecCollectionTimeout 3\n", (normal / "zzz-ci-timeout.conf").read_text()
            )
            self.assertIn(
                "ratelimit_login_enabled=0",
                (disabled / "zzz-ci-ratelimit-config.conf").read_text(),
            )
            self.assertNotIn(
                "ratelimit_login_enabled=0",
                (normal / "zzz-ci-ratelimit-config.conf").read_text(),
            )
            self.assertEqual(original, source.read_text())

    def test_key_count_uses_both_sdbm_files_and_rejects_reader_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            completed = subprocess.CompletedProcess([], 0, "20", "")
            with mock.patch.object(
                growth.subprocess, "run", return_value=completed
            ) as run:
                self.assertEqual(
                    20,
                    growth.key_count("apache", directory, "initial", "/data/httpd-ip"),
                )
            self.assertEqual(3, run.call_count)
            commands = [call.args[0] for call in run.call_args_list]
            self.assertEqual("docker", commands[0][0])
            self.assertTrue(commands[0][2].endswith(".pag"))
            self.assertTrue(commands[1][2].endswith(".dir"))
            self.assertEqual("perl", commands[2][0])
            with (
                mock.patch.object(
                    growth.subprocess,
                    "run",
                    side_effect=subprocess.CalledProcessError(1, ["docker", "cp"]),
                ),
                self.assertRaises(subprocess.CalledProcessError),
            ):
                growth.key_count("apache", directory, "missing", "/data/httpd-ip")


if __name__ == "__main__":
    unittest.main()
