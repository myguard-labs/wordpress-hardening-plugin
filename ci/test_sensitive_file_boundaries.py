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
# Mirrors the 9522114 backup vocabulary; .1 represents its numeric branch.
BACKUP_SUFFIXES = (
    '.bak', '.backup', '.save', '.old', '.new', '.orig', '.tmp',
    '.swp', '.swo', '.txt', '.inc', '.dist', '.sample', '.copy',
    '.1', '~',
)
README_EXTENSIONS = ('txt', 'htm', 'html', 'md', 'rst')
PHP_EXTENSIONS = ('php', 'php4', 'php5', 'php74', 'phps', 'phtml', 'pht', 'phar')


class TestSensitiveFileBoundaries(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rule = RULES.split('id:9522202,', 1)[1].split('id:9522208,', 1)[0]
        if 'chain"' not in rule:
            raise AssertionError('9522202 must chain to the path boundary')
        if '@pmFromFile wordpress-hardening-files.data' not in RULES:
            raise AssertionError('9522202 data-file prefilter is missing')
        match = re.search(r'SecRule REQUEST_FILENAME "@rx ([^"]+)"', rule)
        if match is None:
            raise AssertionError('9522202 path-boundary regex is missing')
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
                paths = tuple(
                    f'/readme.{ext}{suffix}'
                    for ext in README_EXTENSIONS
                    for suffix in ('', *BACKUP_SUFFIXES)
                ) + ('/readme.txt/extra',)
            elif token == '/wp-config':
                paths = tuple(
                    base + suffix
                    for base in ('/wp-config', '/wp-config.php')
                    for suffix in ('', *BACKUP_SUFFIXES)
                ) + ('/wp-config.php/extra', '/wp-config.old.php')
            elif token in DIRECTORY_TOKENS:
                paths = (token, token + '/secret.php') + tuple(
                    token + suffix + '/secret.php'
                    for suffix in BACKUP_SUFFIXES
                )
            else:
                paths = (token, token + '/extra') + tuple(
                    token + suffix for suffix in BACKUP_SUFFIXES
                )
            for path in paths:
                with self.subTest(token=token, path=path):
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

            if not token.endswith('/'):
                dotted = (
                    '/readme.tutorial/' if token == '/readme.'
                    else '/wp-config.php.tutorial/' if token == '/wp-config'
                    else token + '.tutorial/'
                )
                with self.subTest(token=token, path=dotted):
                    self.assertFalse(self.matches(dotted), dotted)

    def test_hyphenated_config_and_installer_backups(self):
        self.assertFalse(self.matches('/wp-config-staging.php'))
        for suffix in BACKUP_SUFFIXES:
            for base in ('/wp-config-staging.php', '/wp-admin/install.php'):
                path = base + suffix
                with self.subTest(path=path):
                    self.assertTrue(self.matches(path), path)

    def test_config_and_installer_php_aliases(self):
        for extension in PHP_EXTENSIONS:
            for base in ('/wp-config', '/wp-config-old',
                         '/wp-config-staging', '/wp-admin/install'):
                path = f'{base}.{extension}'
                with self.subTest(path=path):
                    if path == '/wp-config-staging.php':
                        self.assertFalse(self.matches(path), path)
                    else:
                        self.assertTrue(self.matches(path), path)

                    for suffix in ('.save', '~'):
                        backup = path + suffix
                        with self.subTest(path=backup):
                            self.assertTrue(self.matches(backup), backup)

                    tutorial = path + '.tutorial/'
                    with self.subTest(path=tutorial):
                        self.assertFalse(self.matches(tutorial), tutorial)

    def test_stacked_backup_suffixes_keep_component_boundaries(self):
        for base in ('/wp-config.php', '/wp-config-old.php',
                     '/wp-config-staging.php', '/wp-admin/install.php',
                     '/nginx.conf', '/readme.html'):
            for suffix in ('.bak', '.bak.txt', '.bak.txt.old'):
                path = base + suffix
                with self.subTest(path=path):
                    self.assertTrue(self.matches(path), path)

            lookalike = base + '.bak.tutorial.txt/'
            with self.subTest(path=lookalike):
                self.assertFalse(self.matches(lookalike), lookalike)

        self.assertTrue(self.matches('/wp-config.bak.php.save'))
        self.assertTrue(self.matches('/wp-content/mu-plugins.bak.txt/secret.php'))
        self.assertFalse(self.matches(
            '/wp-content/mu-plugins.bak.tutorial.txt/secret.php'
        ))

    def test_numeric_config_copies(self):
        for base in ('/wp-config2', '/wp-config12',
                     '/wp-config-backup2', '/wp-config-old12'):
            for extension in ('', '.php', '.php5', '.phtml'):
                path = base + extension
                with self.subTest(path=path):
                    self.assertTrue(self.matches(path), path)
                    self.assertTrue(self.matches(path + '.bak.txt'))

                tutorial = path + '.tutorial/'
                with self.subTest(path=tutorial):
                    self.assertFalse(self.matches(tutorial), tutorial)

        self.assertFalse(self.matches('/wp-config2-guide/'))

    def test_sensitive_variants(self):
        for path in ('/wp-config-sample.php', '/wp-config.php.save',
                     '/wp-config-backup.php', '/blog/wp-config.php',
                     '/wp-config-old.php.save',
                     '/wp-config-staging.php.save',
                     '/wp-config-staging.php.txt',
                     '/wp-config-staging.php~',
                     '/blog/nginx.conf', '/nginx.conf.bak',
                     '/wp-admin/install.php.bak', '/wp-admin/install.php~',
                     '/wp-admin/install.php5',
                     '/wp-content/mu-plugins/test.php'):
            with self.subTest(path=path):
                self.assertTrue(self.matches(path))

    def test_permalinks_and_lookalikes(self):
        for path in ('/blog/wp-config-guide/', '/nginx.conf-tutorial/',
                     '/nginx.conf.tutorial/',
                     '/wp-config.php.tutorial/',
                     '/wp-config-old.php.tutorial/',
                     '/readme.tutorial/',
                     '/wp-content/mu-plugins-info/', '/wp-config-staging.php',
                     '/wp-content/mu-plugins.bak-guide/',
                     '/wp-content/upgrade-guide/', '/blog/license.txt-guide/'):
            with self.subTest(path=path):
                self.assertFalse(self.matches(path))


if __name__ == '__main__':
    unittest.main()
