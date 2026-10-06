"""Check info-leak path boundaries and shipped defaults with inert transactions."""

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXECUTABLES = ("/wp-admin/install.php", "/wp-admin/setup-config.php")
NON_EXECUTABLES = (
    "/readme.html", "/license.txt", "/.user.ini",
    "/wp-includes/wlwmanifest.xml", "/wp-content/debug.log",
)


class InfoLeakPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # unittest owns cleanup even if compilation or a later assertion fails.
        cls.directory = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        for name in ("main.go", "go.mod", "go.sum"):
            shutil.copyfile(ROOT / "tests/coraza" / name, cls.directory / name)
        cls.probe = cls.directory / "coraza-probe"
        subprocess.run(
            ["go", "build", "-mod=readonly", "-o", str(cls.probe), "."],
            cwd=cls.directory, capture_output=True, text=True, check=True,
        )
        cls.marker = cls.directory / "default-marker.conf"
        cls.marker.write_text(
            'SecRule TX:wphard.block_plugin_readme "@streq 0" '
            '"id:9900002,phase:1,pass,log,t:none,msg:\'readme-default-zero\'"\n'
        )

    def check_paths(self, paths, *, rule=9522100, matches=True, settings=(),
                    default_marker=False):
        setup = self.directory / "setup.conf"
        setup.write_text(
            'SecDefaultAction "phase:1,pass,log"\n'
            'SecAction "id:9900001,phase:1,pass,nolog,t:none,'
            'setvar:tx.critical_anomaly_score=5'
            + ''.join(',setvar:tx.' + setting for setting in settings) + '"\n'
        )
        fixture = self.directory / "paths.json"
        fixture.write_text(json.dumps([
            {"name": path, "uri": path,
             "headers": {"Host": "localhost", "User-Agent": "path-boundary-test",
                         "Accept": "*/*"},
             "expect_ids": ([rule] if matches else [])
                           + ([9900002] if default_marker else []),
             "no_expect_ids": [] if matches else [rule],
             "expect_interruption": False}
            for path in paths
        ]))
        result = subprocess.run(
            [str(self.probe), "-tx", str(fixture),
             str(ROOT / "plugins/wordpress-hardening-config.conf"), str(setup),
             str(ROOT / "plugins/wordpress-hardening-before.conf"),
             str(ROOT / "plugins/wordpress-hardening-after.conf"), str(self.marker)],
            cwd=ROOT / "plugins", capture_output=True, text=True, check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn(f"{len(paths)}/{len(paths)} passed", result.stdout)

    def test_executable_path_info(self):
        self.check_paths([
            path + suffix for path in EXECUTABLES
            for suffix in ("/", "/extra", "/extra/nested.css", "/extra?mode=check")
        ])

    def test_encoded_and_normalized_path_info(self):
        self.check_paths([
            "/wp-admin/install%2ephp/extra",
            "/wp-admin/setup-config.php%2fextra",
            "/WP-ADMIN/INSTALL.PHP/extra",
            "/wp-admin/./setup-config.php/extra",
            "http://localhost/wp-admin/install.php/extra?mode=check",
        ])

    def test_exact_targets(self):
        self.check_paths([
            path + suffix for path in (*EXECUTABLES, *NON_EXECUTABLES)
            for suffix in ("", "?mode=check")
        ])

    def test_static_file_path_info(self):
        self.check_paths([
            path + suffix for path in NON_EXECUTABLES
            for suffix in ("/", "/extra", "/extra/nested.css", "/extra?mode=check",
                           "%2fextra", "%2Fextra%2fnested.css?mode=check")
        ])

    def test_static_file_normalized_paths(self):
        self.check_paths([
            "/r%65adme.html/extra", "/LICENSE.TXT/extra",
            "/./.user.ini/extra", "/wp-includes/./wlwmanifest.xml/extra",
            "http://localhost/wp-content/debug.log/extra?mode=check",
        ])

    def test_static_filename_near_misses(self):
        self.check_paths([
            path + suffix for path in NON_EXECUTABLES
            for suffix in (".bak", ".bak/extra", "x/extra", "%2ebak/extra")
        ], matches=False)

    def test_static_single_decode_and_query_boundaries(self):
        self.check_paths([
            path + suffix for path in NON_EXECUTABLES
            for suffix in ("%252fextra", "%2/extra", "%GG/extra", "%00/extra",
                           "%3fextra", "%23extra")
        ] + ["/search?path=" + path + "/extra" for path in NON_EXECUTABLES]
          + ["/r%2565adme.html/extra",
             "http://localhost/search?path=/readme.html/extra"], matches=False)

    def test_php_filename_near_misses(self):
        self.check_paths([
            path + suffix for path in EXECUTABLES
            for suffix in (".bak", ".bak/extra", "x/extra", "%2ebak/extra")
        ], matches=False)

    def test_single_decode_and_malformed_boundaries(self):
        self.check_paths([
            "/wp-admin/install%252ephp/extra",
            "/wp-admin/setup-config.php%252fextra",
            "/wp-admin/install.php%2/extra",
            "/wp-admin/setup-config.php%GG/extra",
            "/wp-admin/install.php%00/extra",
            "/search?path=/wp-admin/install.php/extra",
            "http://localhost/search?path=/wp-admin/setup-config.php/extra",
            "/r%2565adme.html", "/", "/wp-admin/",
        ], matches=False)

    def test_info_leak_feature_disabled(self):
        self.check_paths([
            path + suffix for path in (*EXECUTABLES, *NON_EXECUTABLES)
            for suffix in ("", "/", "/extra/nested", "/extra?mode=check", "%2fextra")
        ], matches=False, settings=("wphard.block_info_leak_files=0",))

    def test_plugin_readme_ships_disabled(self):
        # No CI opt-in fixture: assert the initialized value and actual behavior.
        self.check_paths([
            "/wp-content/plugins/akismet/readme.txt",
            "/wp-content/plugins/akismet/readm%65.txt",
            "/wp-content/themes/example/readme.md",
        ], rule=9522115, matches=False, default_marker=True)

    def test_plugin_readme_explicit_opt_in(self):
        self.check_paths(["/wp-content/plugins/akismet/readme.txt"], rule=9522115,
                         settings=("wphard.block_plugin_readme=1",))


if __name__ == "__main__":
    unittest.main()
