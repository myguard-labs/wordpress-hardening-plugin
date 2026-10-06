"""Keep Apache go-ftw exclusions explained and frozen."""

import copy
import unittest
from pathlib import Path

import yaml
from check_ftw_positives import check_ignores

CONFIG = Path(__file__).resolve().parents[1] / "tests/integration/.ftw.yml"


class FtwIgnoreTests(unittest.TestCase):
    def setUp(self):
        self.settings = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))

    def test_committed_apache_exclusions_have_tracked_reasons(self):
        check_ignores(self.settings)

    def test_new_ignore_is_rejected(self):
        changed = copy.deepcopy(self.settings)
        changed["testoverride"]["ignore"]["9522999-1"] = (
            "R6-NIT-IGNORE: simulated new exclusion with a full explanation"
        )
        with self.assertRaisesRegex(ValueError, "ignore IDs changed"):
            check_ignores(changed)

    def test_replacement_ignore_is_rejected(self):
        changed = copy.deepcopy(self.settings)
        ignored = changed["testoverride"]["ignore"]
        ignored["9522999-1"] = ignored.pop("9522801-2")
        with self.assertRaisesRegex(ValueError, "ignore IDs changed"):
            check_ignores(changed)

    def test_restoring_revslider_ignore_is_rejected(self):
        changed = copy.deepcopy(self.settings)
        changed["testoverride"]["ignore"]["9522120-1"] = (
            "R6-APACHE-9522120: stale revslider exclusion from before Apache validation"
        )
        with self.assertRaisesRegex(ValueError, "ignore IDs changed"):
            check_ignores(changed)

    def test_restoring_long_php_upload_ignore_is_rejected(self):
        changed = copy.deepcopy(self.settings)
        changed["testoverride"]["ignore"]["9522205-2"] = (
            "R6-APACHE-9522205: stale exclusion after matching path validation"
        )
        with self.assertRaisesRegex(ValueError, "ignore IDs changed"):
            check_ignores(changed)

    def test_missing_or_vague_reason_is_rejected(self):
        for reason in (None, "", "investigate", "R6-NIT-IGNORE: too short"):
            with self.subTest(reason=reason):
                changed = copy.deepcopy(self.settings)
                changed["testoverride"]["ignore"]["9522801-2"] = reason
                with self.assertRaisesRegex(ValueError, "tracked reason required"):
                    check_ignores(changed)

    def test_malformed_ignore_mapping_is_rejected(self):
        for ignored in (None, ["9522120-1"], {9522120: "reason"}):
            with self.subTest(ignored=ignored):
                changed = copy.deepcopy(self.settings)
                changed["testoverride"]["ignore"] = ignored
                with self.assertRaisesRegex(TypeError, "ignore .* (mapping|strings)"):
                    check_ignores(changed)


if __name__ == "__main__":
    unittest.main()
