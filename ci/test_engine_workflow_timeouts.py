"""Require bounded timeouts on every mandatory engine job."""

import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
JOBS = {
    "apache-modsecurity2.yml": "apache-modsecurity2",
    "nginx-libmodsecurity3.yml": "nginx-libmodsecurity3",
    "security-corpus.yml": "security-corpus",
}


def job_timeout(workflow, job_name):
    """Read a job timeout from workflow YAML, without accepting missing jobs."""
    return yaml.safe_load(workflow)["jobs"][job_name].get("timeout-minutes")


class EngineWorkflowTimeoutTests(unittest.TestCase):
    def test_engine_jobs_have_bounded_timeouts(self):
        for filename, job_name in JOBS.items():
            with self.subTest(workflow=filename):
                workflow = (ROOT / ".github/workflows" / filename).read_text()
                timeout = job_timeout(workflow, job_name)
                self.assertIs(type(timeout), int)
                self.assertGreaterEqual(timeout, 1)
                self.assertLessEqual(timeout, 360)

    def test_missing_timeout_is_rejected(self):
        workflow = "jobs:\n  engine:\n    runs-on: ubuntu-latest\n"
        self.assertIsNone(job_timeout(workflow, "engine"))

    def test_missing_job_is_rejected(self):
        with self.assertRaises(KeyError):
            job_timeout("jobs: {}\n", "engine")


if __name__ == "__main__":
    unittest.main()
