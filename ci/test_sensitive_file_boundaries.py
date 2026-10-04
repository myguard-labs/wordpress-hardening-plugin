"""Direct checks for rule 9522202's data-file and path-boundary contract."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = (ROOT / "plugins/wordpress-hardening-before.conf").read_text()
DATA = (ROOT / "plugins/wordpress-hardening-files.data").read_text()
DIRECTORY_TOKENS = {
    '/wp-content/backups-dup-pro', '/wp-content/mu-plugins',
    '/wp-content/upgrade', '/wp-content/wp-rocket-config',
    '/wp-content/uploads/sucuri', '/wp-content/uploads/updraft',
    '/wp-admin/install', '/wp-admin/includes',
}


class TestSensitiveFileBoundaries(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rule = RULES.split('id:9522202,', 1)[1].split('id:9522208,', 1)[0]
        cls.assertIn(cls, 'chain"', rule)
        cls.assertIn(cls, '@pmFromFile wordpress-hardening-files.data', RULES)
        match = re.search(r'SecRule REQUEST_FILENAME "@rx ([^"]+)"', rule)
        cls.pattern = re.compile(match.group(1))
        cls.tokens = [
            line for line in DATA.splitlines()
            if line and not line.startswith('#')
        ]

    def matches(self, path):
        path = path.lower()
        return any(token in path for token in self.tokens) and bool(self.pattern.search(path))

    def test_each_token_exact_backup_and_path_suffix(self):
        for token in self.tokens:
            if token.endswith('/'):
                paths = (token, token + 'secret.php')
            elif token == '/readme.':
                paths = ('/readme.txt', '/readme.txt.bak',
                         '/readme.txt/extra')
            elif token == '/wp-config':
                paths = ('/wp-config', '/wp-config.php',
                         '/wp-config.php.bak', '/wp-config.php/extra')
            elif token in DIRECTORY_TOKENS:
                paths = (token, token + '/secret.php',
                         token + '.bak/secret.php')
            else:
                paths = (token, token + '.bak', token + '/extra')
            for path in paths:
                with self.subTest(token=token, path=path):
                    self.assertIn(token, path)  # Original @pmFromFile.
                    self.assertTrue(self.matches(path), path)

    def test_each_token_nearby_slug_stays_accessible(self):
        for token in self.tokens:
            if token.endswith('/'):
                path = token[:-1] + '-guide/'
            elif token == '/readme.':
                path = '/readme.txt-guide/'
            elif token == '/wp-config':
                path = '/wp-config-staging.php'
            else:
                path = token + '-guide/'
            with self.subTest(token=token, path=path):
                self.assertFalse(self.matches(path), path)

    def test_sensitive_variants(self):
        for path in ('/wp-config-sample.php', '/wp-config.php.save',
                     '/wp-config-backup.php', '/blog/wp-config.php',
                     '/blog/nginx.conf', '/nginx.conf.bak',
                     '/wp-admin/install.php.bak', '/wp-admin/install.php5',
                     '/wp-content/mu-plugins/test.php'):
            with self.subTest(path=path):
                self.assertTrue(self.matches(path))

    def test_permalinks_and_lookalikes(self):
        for path in ('/blog/wp-config-guide/', '/nginx.conf-tutorial/',
                     '/wp-content/mu-plugins-info/', '/wp-config-staging.php',
                     '/wp-content/upgrade-guide/', '/blog/license.txt-guide/'):
            with self.subTest(path=path):
                self.assertFalse(self.matches(path))


if __name__ == '__main__':
    unittest.main()
