"""Oracle checks for the two-origin framing probe."""

import copy
import unittest

from ci.check_smuggle_diff import assert_observations


class SmuggleDiffOracleTest(unittest.TestCase):
    def setUp(self):
        self.rows = [
            {"engine": "apache", "case": "valid", "status": "HTTP/1.1 200 OK",
             "origin_seen": True, "origin_headers": "Content-Length: 4",
             "origin_body_hex": "74657374", "audit_has_transaction": True},
            {"engine": "apache", "case": "ambiguous", "status": "HTTP/1.1 200 OK",
             "origin_seen": True, "origin_headers": (
                 "POST /framing-probe HTTP/1.1\r\nContent-Length: 0"),
             "origin_body_hex": "", "audit_has_transaction": True},
            {"engine": "nginx", "case": "valid", "status": "HTTP/1.1 200 OK",
             "origin_seen": True, "origin_headers": "Content-Length: 4",
             "origin_body_hex": "74657374", "audit_has_transaction": False},
            {"engine": "nginx", "case": "ambiguous", "status": "HTTP/1.1 400 Bad Request",
             "origin_seen": False, "origin_headers": "", "origin_body_hex": "",
             "audit_has_transaction": False},
        ]

    def test_observed_valid_and_ambiguous_framing(self):
        assert_observations(self.rows)

    def test_origin_framing_negative_control(self):
        broken = copy.deepcopy(self.rows)
        broken[1]["origin_headers"] = "Content-Length: 5"
        with self.assertRaises(AssertionError):
            assert_observations(broken)

    def test_duplicate_origin_content_length_is_rejected(self):
        broken = copy.deepcopy(self.rows)
        broken[1]["origin_headers"] = (
            "POST /framing-probe HTTP/1.1\r\n"
            "Content-Length: 0\r\nContent-Length: 5")
        with self.assertRaises(AssertionError):
            assert_observations(broken)

    def test_missing_engine_is_rejected(self):
        with self.assertRaises(AssertionError):
            assert_observations(self.rows[:2])


if __name__ == "__main__":
    unittest.main()
