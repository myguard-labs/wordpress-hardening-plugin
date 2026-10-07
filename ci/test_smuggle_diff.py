"""Oracle checks for the two-origin framing probe."""

import copy
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from ci.check_smuggle_diff import assert_observations, probe


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


class SmuggleDiffProbeTest(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.origin = mock.Mock()
        self.origin.getsockname.return_value = ("127.0.0.1", 12345)
        self.thread = mock.Mock()
        self.connection = mock.MagicMock()
        self.connection.__enter__.return_value = self.connection
        self.connection.recv.side_effect = [b"HTTP/1.1 200 OK\r\n\r\n", b""]

    def run_probe(self, docker_run, refused_connections=0):
        def run(*args):
            if args[:2] == ("docker", "run"):
                self.events.append("docker-start")
                docker_run()
                self.events.append("docker-ready")
                return "container-id"
            self.events.append("inspect")
            return "127.0.0.1"

        def connect(*_args, **_kwargs):
            self.events.append("connect")
            if self.events.count("connect") <= refused_connections:
                raise ConnectionRefusedError("proxy starting")
            return self.connection

        self.thread.start.side_effect = lambda: self.events.append("listener-start")
        self.connection.sendall.side_effect = lambda _request: self.events.append("send")
        with tempfile.TemporaryDirectory() as temp:
            audit = Path(temp) / "audit.log"
            with (mock.patch("ci.check_smuggle_diff.socket.socket", return_value=self.origin),
                  mock.patch("ci.check_smuggle_diff.threading.Thread", return_value=self.thread),
                  mock.patch("ci.check_smuggle_diff.socket.create_connection", side_effect=connect),
                  mock.patch("ci.check_smuggle_diff.run", side_effect=run),
                  mock.patch("ci.check_smuggle_diff.time.sleep"),
                  mock.patch("ci.check_smuggle_diff.subprocess.run")):
                return probe("apache", "valid", b"request", "image", "network",
                             "127.0.0.1", Path(temp), audit)

    def test_delayed_engine_start_keeps_origin_listener_ready_for_request(self):
        row = self.run_probe(lambda: threading.Event().wait(0.02), refused_connections=1)
        self.assertEqual(self.events,
                         ["docker-start", "docker-ready", "inspect", "connect",
                          "connect", "listener-start", "send"])
        self.assertEqual(row["status"], "HTTP/1.1 200 OK")
        self.origin.close.assert_called_once()

    def test_engine_start_failure_closes_unstarted_origin(self):
        def fail_start():
            raise RuntimeError("docker startup failed")

        with self.assertRaisesRegex(RuntimeError, "docker startup failed"):
            self.run_probe(fail_start)
        self.assertNotIn("listener-start", self.events)
        self.origin.close.assert_called_once()
        self.thread.join.assert_not_called()


if __name__ == "__main__":
    unittest.main()
