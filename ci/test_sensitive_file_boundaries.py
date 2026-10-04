"""Rule 9522202 must preserve the data-file block except for exact paths."""

import re
import unittest
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
RULES = (ROOT / 'plugins/wordpress-hardening-before.conf').read_text()
DATA = (ROOT / 'plugins/wordpress-hardening-files.data').read_text()
EXCEPTIONS = (
    '/blog/wp-config-guide/',
    '/nginx.conf-tutorial/',
    '/wp-content/mu-plugins-info/',
    '/wp-config-staging.php',
)


class TestSensitiveFileBoundaries(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rule = RULES.split('id:9522202,', 1)[1].split('id:9522208,', 1)[0]
        if 'chain"' not in rule:
            raise AssertionError('9522202 must chain from the broad data-file match')
        if '@pmFromFile wordpress-hardening-files.data' not in RULES:
            raise AssertionError('9522202 data-file match is missing')
        match = re.search(r'SecRule REQUEST_FILENAME "!@rx ([^"]+)"', rule)
        if match is None:
            raise AssertionError('9522202 negative exception is missing')
        cls.pattern = re.compile(match.group(1))
        cls.tokens = tuple(line for line in DATA.splitlines()
                           if line and not line.startswith('#'))

    def matches(self, path):
        # Model the decoded, lowercased REQUEST_FILENAME used by the chained
        # SecRules. The engine regression suite checks actual transformations.
        path = unquote(path).lower()
        return any(token in path for token in self.tokens) and not bool(
            self.pattern.search(path))

    def test_every_data_token_remains_protected(self):
        for token in self.tokens:
            with self.subTest(token=token):
                self.assertTrue(self.matches(token), token)

    def test_only_explicit_complete_paths_are_exempt(self):
        for path in EXCEPTIONS:
            with self.subTest(path=path):
                self.assertFalse(self.matches(path), path)
                self.assertTrue(self.matches(path + 'extra'), path)
                self.assertTrue(self.matches(path + '.bak'), path)
                self.assertTrue(self.matches('/wp-config.php' + path), path)
                self.assertTrue(self.matches('/wp-admin/install.php' + path), path)

    def test_reviewed_cross_product_and_repeated_stacks(self):
        for path in (
            '/wp-admin/wp-config2.bak.phps',
            '/wp-admin/wp-config-staging.bak.phps',
            '/wp-admin/wp-config.php.bak.php.bak.phps',
            '/wp-admin/install.php.bak.php.bak.phps',
        ):
            with self.subTest(path=path):
                self.assertTrue(self.matches(path), path)

    def test_php_alias_backup_and_path_info_variants(self):
        for path in (
            '/wp-config.php', '/wp-config.php.save',
            '/wp-config-staging.php.bak', '/wp-config-staging.phps',
            '/wp-config-staging.php5', '/wp-admin/install.php',
            '/wp-admin/install.php.bak.php', '/nginx.conf.txt',
            '/wp-content/mu-plugins.bak/secret.php',
            '/wp-config.php/blog/wp-config-guide/',
            '/wp-admin/install.php/nginx.conf-tutorial/',
            '/wp-config%2ephp.bak',
        ):
            with self.subTest(path=path):
                self.assertTrue(self.matches(path), path)

    def test_malformed_and_unrelated_paths(self):
        for path in ('/unrelated/', '/index.php', '/blog/%00unrelated'):
            with self.subTest(path=path):
                self.assertFalse(self.matches(path), path)
        for path in (
            '/blog/wp-config-guide/%00',
            '/wp-config-staging.php%2ebak',
            '/nginx.conf-tutorial%2fbak',
        ):
            with self.subTest(path=path):
                self.assertTrue(self.matches(path), path)


if __name__ == '__main__':
    unittest.main()
