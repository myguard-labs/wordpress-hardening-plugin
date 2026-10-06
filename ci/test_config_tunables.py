"""Keep documented config tunables connected to live rules."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "plugins/wordpress-hardening-config.conf"
CONSUMER_FILES = tuple(
    path for path in (ROOT / "plugins").glob("*.conf") if path != CONFIG
)
TUNABLE = re.compile(
    r"^#SecAction .*?setvar:[\'\"]?tx\.wphard\.([A-Za-z0-9_]+)=",
    re.MULTILINE,
)
CONSOLIDATION = re.compile(
    r"^# Consolidated tunables: ([A-Za-z0-9_, ]+) -> ([A-Za-z0-9_]+)$",
    re.MULTILINE,
)


def uncommented_rules(sources):
    """Return rule text with full-line comments removed."""
    return "\n".join(
        line
        for source in sources
        for line in source.splitlines()
        if not line.lstrip().startswith("#")
    )


def undocumented_consumers(config, rules):
    """Find config tunables with neither a live consumer nor consolidation."""
    tunables = set(TUNABLE.findall(config))
    consolidations = {}
    for names, replacement in CONSOLIDATION.findall(config):
        for name in re.findall(r"[A-Za-z0-9_]+", names):
            consolidations[name] = replacement
    return sorted(
        name
        for name in tunables
        if not re.search(
            rf"\b(?:TX:)?wphard\.{re.escape(name)}\b", rules, re.IGNORECASE
        )
        and not (
            name in consolidations
            and re.search(
                rf"\b(?:TX:)?wphard\.{re.escape(consolidations[name])}\b",
                rules,
                re.IGNORECASE,
            )
        )
    )


class ConfigTunablesTests(unittest.TestCase):
    def test_each_documented_tunable_has_a_rule_or_consolidation(self):
        rules = uncommented_rules(path.read_text() for path in CONSUMER_FILES)
        self.assertEqual([], undocumented_consumers(CONFIG.read_text(), rules))

    def test_new_tunable_without_consumer_or_note_is_rejected(self):
        config = '#SecAction "id:9522998,setvar:tx.wphard.new_toggle=1"\n'
        self.assertEqual(["new_toggle"], undocumented_consumers(config, "SecRule ARGS"))

    def test_explicit_consolidation_requires_a_live_replacement(self):
        config = (
            '#SecAction "id:9522998,setvar:tx.wphard.old_toggle=1"\n'
            "# Consolidated tunables: old_toggle -> client_is_private\n"
        )
        self.assertEqual(
            [], undocumented_consumers(config, "SecRule TX:wphard.client_is_private")
        )
        self.assertEqual(["old_toggle"], undocumented_consumers(config, "SecRule ARGS"))


if __name__ == "__main__":
    unittest.main()
