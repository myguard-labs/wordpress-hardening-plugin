"""Boundary checks for the backup-file rule; FTW exercises the real engines."""

import re
import unittest
from pathlib import Path

RULES = (Path(__file__).resolve().parents[1] /
         'plugins/wordpress-hardening-before.conf').read_text()


class TestBackupFiles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        match = re.search(
            r'SecRule REQUEST_FILENAME "@rx ([^"]+)"\s*\\\s*"id:9522303,',
            RULES,
        )
        if match is None:
            raise AssertionError('9522303 REQUEST_FILENAME regex is missing')
        cls.pattern = re.compile(match.group(1))

    def test_bare_backup_archives(self):
        for path in (
            '/backup.zip', '/backup.tar', '/db-backup.zip',
            '/site-backup.zip', '/wordpress-backup.zip', '/backup.tar.xz',
        ):
            with self.subTest(path=path):
                self.assertRegex(path, self.pattern)

    def test_existing_backup_paths(self):
        for path in (
            '/backups/db-2024-01-01.sql', '/wp-content/backups/site.zip',
            '/my-backup-1.zip', '/x_backup_y.tar.gz',
        ):
            with self.subTest(path=path):
                self.assertRegex(path, self.pattern)

    def test_benign_paths(self):
        for path in (
            '/wp-content/plugins/some-backup-plugin/style.css',
            '/wp-content/plugins/backup-manager/style.css',
            '/backup.zip.css', '/backup.css', '/backup', '/site-backup',
            '/site-backup-guide/',
            '/my-backup-1.css',
        ):
            with self.subTest(path=path):
                self.assertNotRegex(path, self.pattern)


if __name__ == '__main__':
    unittest.main()
