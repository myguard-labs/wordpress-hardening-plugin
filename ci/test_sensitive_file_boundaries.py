"""Rule 9522202 must preserve the data-file block except for exact paths."""

import re
import unittest
from pathlib import Path
from urllib.parse import unquote

import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES = (ROOT / 'plugins/wordpress-hardening-before.conf').read_text()
DATA = (ROOT / 'plugins/wordpress-hardening-files.data').read_text()
EXCEPTIONS = (
    '/blog/wp-config-guide',
    '/blog/wp-config-guide/',
    '/nginx.conf-tutorial',
    '/nginx.conf-tutorial/',
    '/wp-content/mu-plugins-info',
    '/wp-content/mu-plugins-info/',
    '/wp-config-staging.php',
)


def request_filename_rules(rules=RULES):
    return tuple(
        match for match in re.finditer(
            r'^SecRule REQUEST_FILENAME "(?P<selector>[^\"]+)" \\\n'
            r'\s+"(?P<actions>(?:[^"\\]|\\\\|\\\n)*)"',
            rules,
            re.MULTILINE,
        )
    )


def action_tokens(actions):
    """Split SecRule actions at commas outside single-quoted values."""
    actions = actions.replace('\\\n', '')
    tokens = []
    start = 0
    quoted = False
    escaped = False
    for index, char in enumerate(actions):
        if escaped:
            escaped = False
        elif char == '\\':
            escaped = True
        elif char == "'":
            quoted = not quoted
        elif char == ',' and not quoted:
            tokens.append(actions[start:index].strip())
            start = index + 1
    if quoted:
        raise ValueError('unterminated quoted SecRule action')
    tokens.append(actions[start:].strip())
    return tuple(tokens)


def sensitive_rule_match(rules):
    return next(
        (match for match in request_filename_rules(rules)
         if 'id:9522202' in action_tokens(match.group('actions'))),
        None,
    )


def sensitive_rule_chain(rules, match):
    directives = tuple(re.finditer(r'^[ \t]*Sec(?:Rule|Action|Marker)\b',
                                   rules[match.end():], re.MULTILINE))
    actions = match.group('actions')
    for index, directive in enumerate(directives):
        end = match.end() + directive.start()
        if ('chain' not in action_tokens(actions)
                or not directive.group().lstrip().startswith('SecRule')):
            return rules[match.start():end]
        next_start = (match.end() + directives[index + 1].start()
                      if index + 1 < len(directives) else len(rules))
        quoted = re.findall(r'"((?:[^"\\]|\\[\s\S])*)"',
                            rules[end:next_start])
        if not quoted:
            return rules[match.start():end]
        actions = quoted[-1]
    return rules[match.start():]


class TestSensitiveFileBoundaries(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sensitive_rule = sensitive_rule_match(RULES)
        if cls.sensitive_rule is None:
            raise AssertionError('9522202 action list is missing')
        if 'chain' not in action_tokens(cls.sensitive_rule.group('actions')):
            raise AssertionError('9522202 must chain from the broad data-file match')
        rule = sensitive_rule_chain(RULES, cls.sensitive_rule)
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
        self.assertTrue(self.tokens, 'sensitive-file data contains no tokens')
        for token in self.tokens:
            with self.subTest(token=token):
                self.assertTrue(self.matches(token), token)

    def test_sensitive_file_selector_and_id_share_rule_action_list(self):
        rule = self.sensitive_rule
        self.assertEqual(
            '@pmFromFile wordpress-hardening-files.data',
            rule.group('selector'),
        )

    def test_rule_action_id_ignores_quoted_text_and_action_order(self):
        rules = (
            'SecRule REQUEST_FILENAME "@rx decoy" \\\n'
            '  "msg:\'quoted,id:9522202,decoy\',id:9522200,chain"\n'
            'SecRule REQUEST_FILENAME "@pmFromFile wordpress-hardening-files.data" \\\n'
            '  "msg:\'quoted,id:9522202,decoy\',chain,id:9522202,phase:2"\n'
        )
        match = sensitive_rule_match(rules)
        self.assertIsNotNone(match)
        self.assertEqual('@pmFromFile wordpress-hardening-files.data',
                         match.group('selector'))

    def test_sensitive_chain_stops_at_next_top_level_rule(self):
        rules = (
            'SecRule REQUEST_FILENAME "@pmFromFile wordpress-hardening-files.data" \\\n'
            '  "id:9522202,chain"\n'
            '  SecRule REQUEST_FILENAME "!@rx ^/allowed$" \\\n'
            '    "t:none"\n'
            'SecRule TX:other "@eq 1" \\\n'
            '  "id:9522299,msg:\'SecRule REQUEST_FILENAME !@rx ^/wrong$\'"\n'
        )
        match = sensitive_rule_match(rules)
        chain = sensitive_rule_chain(rules, match)
        self.assertIn('!@rx ^/allowed$', chain)
        self.assertNotIn('!@rx ^/wrong$', chain)

    def test_unindented_continuation_belongs_to_chain(self):
        rules = (
            'SecRule REQUEST_FILENAME "@pmFromFile wordpress-hardening-files.data" \\\n'
            '  "id:9522202,chain"\n'
            'SecRule REQUEST_FILENAME "!@rx ^/allowed$" \\\n'
            '  "t:none"\n'
            'SecRule TX:other "@eq 1" \\\n'
            '  "id:9522299,msg:\'SecRule REQUEST_FILENAME !@rx ^/wrong$\'"\n'
        )
        chain = sensitive_rule_chain(rules, sensitive_rule_match(rules))
        self.assertIn('!@rx ^/allowed$', chain)
        self.assertNotIn('!@rx ^/wrong$', chain)

    def test_quoted_chain_text_does_not_extend_chain(self):
        rules = (
            'SecRule REQUEST_FILENAME "@pmFromFile wordpress-hardening-files.data" \\\n'
            '  "id:9522202,chain"\n'
            'SecRule REQUEST_FILENAME "!@rx ^/allowed$" \\\n'
            '  "msg:\'quoted,chain,decoy\',t:none"\n'
            'SecRule REQUEST_FILENAME "!@rx ^/wrong$" \\\n'
            '  "t:none"\n'
        )
        chain = sensitive_rule_chain(rules, sensitive_rule_match(rules))
        self.assertIn('!@rx ^/allowed$', chain)
        self.assertNotIn('!@rx ^/wrong$', chain)

    def test_malformed_quoted_action_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'unterminated quoted'):
            action_tokens("msg:'unterminated,id:9522202,chain")

    def test_only_explicit_complete_paths_are_exempt(self):
        for path in EXCEPTIONS:
            with self.subTest(path=path):
                self.assertFalse(self.matches(path), path)
                self.assertTrue(self.matches(path + 'extra'), path)
                self.assertTrue(self.matches(path + '.bak'), path)
                self.assertTrue(self.matches('/wp-config.php' + path), path)
                self.assertTrue(self.matches('/wp-admin/install.php' + path), path)

    def test_article_aliases_do_not_exempt_nested_or_nearby_names(self):
        for path in EXCEPTIONS:
            with self.subTest(path=path):
                self.assertTrue(self.matches('/extra' + path), path)
                self.assertTrue(self.matches(path + '/extra'), path)
                self.assertTrue(self.matches(path + '%00'), path)
                self.assertTrue(self.matches(path + '%GG'), path)
        self.assertTrue(self.matches('/wp-config-staging.php/'))

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

    def test_info_leak_duplicates_do_not_expand_data_match(self):
        for path in ('/.user.ini', '/wp-content/debug.log'):
            with self.subTest(path=path):
                self.assertNotIn(path, self.tokens)
        for path in ('/article/.user.ini-guide',
                     '/article/wp-content/debug.log-guide'):
            with self.subTest(path=path):
                self.assertFalse(self.matches(path), path)
        fixture = yaml.safe_load(
            (ROOT / 'tests/regression/wordpress-hardening-plugin/9522202.yaml').read_text()
        )
        cases = {test['test_title']: test['stages'][0] for test in fixture['tests']}
        for title, path in (('9522202-11', '/.user.ini'),
                            ('9522202-28', '/wp-content/debug.log/extra')):
            with self.subTest(title=title):
                self.assertEqual(path, cases[title]['input']['uri'])
                self.assertEqual('id "9522100"', cases[title]['output']['log_contains'])

    def test_static_fast_path_preserves_sensitive_path_info(self):
        sensitive = RULES.index('id:9522202,')
        fast_path = RULES.index('id:9522199,')
        benign_fast_path = RULES.index('id:9522198,')
        end_marker = RULES.index('SecMarker "END_WPHARD_STATIC_FILE_RULES"')
        self.assertLess(benign_fast_path, fast_path)
        self.assertLess(fast_path, sensitive)
        self.assertLess(sensitive, end_marker)
        fast_path_rule = RULES[fast_path:sensitive]
        self.assertIn('skipAfter:END_WPHARD_STATIC_FILE_RULES', fast_path_rule)
        self.assertIn('!@pmFromFile wordpress-hardening-files.data',
                      fast_path_rule)
        guard = re.search(r'SecRule REQUEST_FILENAME "!@rx ([^"]+)"',
                          fast_path_rule)
        self.assertIsNotNone(guard)
        extension_guard = re.compile(guard.group(1))
        benign_rule = RULES[RULES.rfind('SecRule REQUEST_FILENAME',
                                        0, benign_fast_path):fast_path]
        self.assertIn('@rx ^(?:/wp-content/plugins/wp-config-tools/style\\.css'
                      '|/blog/wp-config-guide/style\\.css)$', benign_rule)
        self.assertIn('skipAfter:END_WPHARD_STATIC_FILE_RULES', benign_rule)
        match = re.search(
            r'SecRule REQUEST_FILENAME "@rx ([^"]+)"\s*\\\s*"(id:9522199,[^"]*)"',
            RULES)
        self.assertIsNotNone(match)
        fast_path_pattern = re.compile(match.group(1))
        self.assertRegex(match.group(2), r',\\\s*chain\s*$')

        # These PHP origins can execute the script despite the inert suffix.
        for path in ('/wp-config.php/extra.css',
                     '/wp-admin/install.php/extra.js'):
            with self.subTest(path=path):
                self.assertIsNotNone(fast_path_pattern.search(path), path)
                self.assertTrue(self.matches(path), path)
        for path in ('/wp-content/mu-plugins/extra.css',
                     '/blog/wp-config.php/extra.css',
                     '/wp-config-staging.php/extra.css',
                     '/wp-content/mu-plugins.bak/extra.css',
                     '/wp-config-backup/extra.css'):
            with self.subTest(path=path):
                self.assertTrue(any(token in path for token in self.tokens), path)
                self.assertTrue(self.matches(path), path)
        self.assertIsNotNone(extension_guard.search(
            '/wp-content/plugins/test.bak/extra.css'))
        for path in ('/wp-content/themes/site/style.css',
                     '/wp-includes/js/jquery.js'):
            with self.subTest(path=path):
                self.assertIsNotNone(fast_path_pattern.search(path), path)
                self.assertFalse(any(token in path for token in self.tokens))
                self.assertIsNone(extension_guard.search(path), path)
        for path in ('/wp-config.php', '/style.css.bak'):
            with self.subTest(path=path):
                self.assertIsNone(fast_path_pattern.search(path), path)


if __name__ == '__main__':
    unittest.main()
