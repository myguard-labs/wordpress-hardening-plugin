"""Keep each scoring rule's severity paired with its CRS score variable."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def scoring_rules(source):
    """Read ID-delimited rule blocks, including their ID-less chain children.

    This checks the repository's action-per-line SecLang layout. Engine load
    and syntax gates validate the grammar independently.
    """
    source = '\n'.join(line for line in source.splitlines()
                       if not line.lstrip().startswith('#'))
    blocks = re.split(r'\bid:(\d+)\s*,', source)
    for index in range(1, len(blocks), 2):
        rule_id, actions = blocks[index:index + 2]
        scores = re.findall(r'%\{tx\.([a-z]+)_anomaly_score\}', actions)
        if scores:
            severity = re.findall(r"\bseverity:'([A-Z]+)'", actions)
            yield rule_id, severity, scores


class TestSeverityScores(unittest.TestCase):
    def test_shipped_scoring_rules_match_severity(self):
        count = 0
        for path in sorted((ROOT / 'plugins').glob('*.conf')):
            for rule_id, severities, scores in scoring_rules(path.read_text()):
                count += 1
                with self.subTest(file=path.name, rule=rule_id):
                    self.assertEqual(len(severities), 1,
                                     f'{rule_id}: scoring rule needs one severity')
                    self.assertEqual(scores, [severities[0].lower()] * len(scores),
                                     f'{rule_id}: severity and CRS score differ')
                    # These blocking rules deliberately retain the default
                    # five-point weight; lowering both fields is a regression.
                    self.assertEqual(severities, ['CRITICAL'])
        self.assertGreater(count, 0, 'no scoring rules checked')

    def test_chain_score_belongs_to_starter(self):
        source = '''SecRule ARGS "@rx x" "id:1, severity:'WARNING',chain"
        SecRule ARGS "@rx y" \\
          "setvar:'tx.inbound_anomaly_score_pl2=+%{tx.warning_anomaly_score}'"
        SecRule ARGS "@rx z" "id:2, severity:'NOTICE', \\
          setvar:'tx.inbound_anomaly_score_pl1=+%{tx.notice_anomaly_score}'"
        '''
        self.assertEqual(list(scoring_rules(source)), [
            ('1', ['WARNING'], ['warning']),
            ('2', ['NOTICE'], ['notice']),
        ])

    def test_comments_and_non_scoring_rules_are_ignored(self):
        source = '''# id:1, severity:'NOTICE', %{tx.critical_anomaly_score}
        SecAction "id:2,pass,nolog,setvar:tx.enabled=1"
        '''
        self.assertEqual(list(scoring_rules(source)), [])

    def test_missing_severity_does_not_inherit_previous_rule(self):
        source = '''SecAction "id:1,severity:'CRITICAL'"
        SecAction "id:2,setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}"
        '''
        self.assertEqual(list(scoring_rules(source)), [('2', [], ['critical'])])


if __name__ == '__main__':
    unittest.main()
